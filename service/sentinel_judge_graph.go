package service

import (
	"context"

	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/compose"
	"github.com/cloudwego/eino/schema"
)

// 判定图（v0.3 §7.4）用 eino compose.Graph 表达：
//
//	START → prep → model → parse → branch ─┬─ 合法/用尽重试 → finalize → END
//	                                        └─ 不合法且还有余量 → model
//
// 重试计数、对话历史、token 累计都放在图局部状态里（WithGenLocalState），
// 节点之间只传 []*schema.Message，类型沿边自动校验。

// judgeMaxAttempts 是「1 次原始 + 2 次重试」。
const judgeMaxAttempts = 3

// JudgePrompt 是判定图的输入。
type JudgePrompt struct {
	System string
	User   string
}

// JudgeVerdict 是模型输出的强类型结果（由 decode 回调产出）。
//
// AttackPath/Impact/FixEvidence/Snippets 只在 IsSecurityFix=true 时有意义：
// 命中时展开「攻击路径 → 影响 → 修复依据」三段式说明，未命中时为空。
type JudgeVerdict struct {
	IsSecurityFix bool
	VulnClass     string
	Severity      string
	Confidence    float64
	Title         string
	Reasoning     string
	Evidence      []string
	AttackPath    string
	Impact        string
	FixEvidence   string
	Snippets      []string
}

// JudgeRunOutput 是判定图的产物。
type JudgeRunOutput struct {
	Verdict          *JudgeVerdict
	Raw              string
	Attempts         int
	PromptTokens     int
	CompletionTokens int
	// Partial 为 true 表示三次输出都没通过校验，只有兜底结论。
	Partial   bool
	LastError string
}

// judgeRunState 是单次运行的图局部状态。
type judgeRunState struct {
	messages         []*schema.Message
	attempts         int
	verdict          *JudgeVerdict
	raw              string
	promptTokens     int
	completionTokens int
	lastErr          string
}

// BuildJudgeGraph 编译判定图。decode 负责「解析 + 枚举校验」，
// 校验失败会把错误回灌给模型再试一次（最多 judgeMaxAttempts 次）。
func BuildJudgeGraph(ctx context.Context, cm model.BaseChatModel, decode func(raw string) (*JudgeVerdict, error)) (compose.Runnable[JudgePrompt, *JudgeRunOutput], error) {
	g := compose.NewGraph[JudgePrompt, *JudgeRunOutput](
		compose.WithGenLocalState(func(context.Context) *judgeRunState { return &judgeRunState{} }),
	)

	stateOf := func(ctx context.Context) *judgeRunState {
		var st *judgeRunState
		_ = compose.ProcessState[*judgeRunState](ctx, func(_ context.Context, s *judgeRunState) error {
			st = s
			return nil
		})
		if st == nil {
			st = &judgeRunState{}
		}
		return st
	}

	prep := compose.InvokableLambda(func(ctx context.Context, in JudgePrompt) ([]*schema.Message, error) {
		st := stateOf(ctx)
		st.messages = []*schema.Message{
			schema.SystemMessage(in.System),
			schema.UserMessage(in.User),
		}
		return st.messages, nil
	})

	parse := compose.InvokableLambda(func(ctx context.Context, msg *schema.Message) ([]*schema.Message, error) {
		st := stateOf(ctx)
		st.attempts++

		if msg == nil || msg.Content == "" {
			st.lastErr = "模型返回空响应"
			return st.messages, nil
		}
		st.raw = msg.Content
		if msg.ResponseMeta != nil && msg.ResponseMeta.Usage != nil {
			st.promptTokens += msg.ResponseMeta.Usage.PromptTokens
			st.completionTokens += msg.ResponseMeta.Usage.CompletionTokens
		}

		verdict, err := decode(msg.Content)
		if err == nil {
			st.verdict = verdict
			st.lastErr = ""
			return st.messages, nil
		}

		st.lastErr = err.Error()
		st.messages = append(st.messages,
			schema.AssistantMessage(msg.Content, nil),
			schema.UserMessage("上一次输出不合法："+err.Error()+
				"。请只输出严格合法的 JSON：vuln_class 必须在枚举内，evidence 必须是 diff 里真实存在的 hunk 头。"),
		)
		return st.messages, nil
	})

	finalize := compose.InvokableLambda(func(ctx context.Context, _ []*schema.Message) (*JudgeRunOutput, error) {
		st := stateOf(ctx)
		out := &JudgeRunOutput{
			Raw:              st.raw,
			Attempts:         st.attempts,
			PromptTokens:     st.promptTokens,
			CompletionTokens: st.completionTokens,
			Verdict:          st.verdict,
		}
		if st.verdict == nil {
			out.Partial = true
			out.LastError = st.lastErr
		}
		return out, nil
	})

	branch := compose.NewGraphBranch(func(ctx context.Context, _ []*schema.Message) (string, error) {
		st := stateOf(ctx)
		if st.verdict != nil || st.attempts >= judgeMaxAttempts {
			return "finalize", nil
		}
		return "model", nil
	}, map[string]bool{"model": true, "finalize": true})

	if err := g.AddLambdaNode("prep", prep); err != nil {
		return nil, err
	}
	if err := g.AddChatModelNode("model", cm, compose.WithNodeName("judge_model")); err != nil {
		return nil, err
	}
	if err := g.AddLambdaNode("parse", parse); err != nil {
		return nil, err
	}
	if err := g.AddLambdaNode("finalize", finalize); err != nil {
		return nil, err
	}
	if err := g.AddBranch("parse", branch); err != nil {
		return nil, err
	}
	if err := g.AddEdge(compose.START, "prep"); err != nil {
		return nil, err
	}
	if err := g.AddEdge("prep", "model"); err != nil {
		return nil, err
	}
	if err := g.AddEdge("model", "parse"); err != nil {
		return nil, err
	}
	if err := g.AddEdge("finalize", compose.END); err != nil {
		return nil, err
	}

	return g.Compile(ctx, compose.WithGraphName("sentinel_judge"))
}
