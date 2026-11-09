package service

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/internal/llm"
	"github.com/c1ayooo/4zreark/repo"

	"github.com/cloudwego/eino/compose"
)

// SentinelEvaluator 是「过滤 → 装箱 → eino 判定图」的纯函数式封装：
// 不碰数据库、不碰 River，既服务线上 Judge，也服务 cmd/sentinel-eval 离线评测，
// 保证评测看到的 prompt 与线上完全一致。
type SentinelEvaluator struct {
	graph compose.Runnable[JudgePrompt, *JudgeRunOutput]
	model string
	stub  bool
	cfg   config.SentinelConfig
}

// EvalOutcome 是一次评测/判定的完整中间结果。
type EvalOutcome struct {
	Skipped    bool
	SkipReason string
	Pack       *PrepPack
	Run        *JudgeRunOutput
	Verdict    *JudgeVerdict
	Partial    bool
}

// NewSentinelEvaluator 构建评测器；未配置密钥时自动降级为桩模型（stub=true）。
func NewSentinelEvaluator(cfg config.SentinelConfig, llmCfg config.LLMConfig) (*SentinelEvaluator, error) {
	cfg.Normalize()
	llmCfg.Normalize()

	e := &SentinelEvaluator{model: cfg.JudgeModel, cfg: cfg}
	ctx := context.Background()

	cm, err := llm.NewJSONChatModel(ctx, llmCfg)
	if err != nil && !isNoKey(err) {
		return nil, fmt.Errorf("构建判定模型失败: %w", err)
	}
	if isNoKey(err) {
		log.Printf("[Sentinel] 未配置 LLM 密钥（%s），判定降级为桩模型，结论标记 partial",
			firstNonEmptyString(llmCfg.APIKeyEnv, "ZRE_LLM_API_KEY"))
		cm = llm.NewStubModel("未配置 LLM 密钥")
		e.stub = true
		e.model = "stub"
	}

	graph, gErr := BuildJudgeGraph(ctx, cm, decodeJudgeVerdict)
	if gErr != nil {
		return nil, fmt.Errorf("编译判定图失败: %w", gErr)
	}
	e.graph = graph
	return e, nil
}

// IsStub 报告当前是否使用桩模型。
func (e *SentinelEvaluator) IsStub() bool { return e.stub }

// ModelName 返回实际使用的模型名（桩模型为 stub）。
func (e *SentinelEvaluator) ModelName() string { return e.model }

// Evaluate 对一条提交跑完整判定流程。
func (e *SentinelEvaluator) Evaluate(ctx context.Context, commit *repo.GitCommit) (*EvalOutcome, error) {
	files := ParseDiff(commit.Diff)
	if skip, reason := ShouldSkip(commit, files); skip {
		return &EvalOutcome{Skipped: true, SkipReason: reason}, nil
	}

	pack := BuildPack(commit, files, e.cfg)
	// 注入当前审计技能（设置里可切）：同一份检查清单同时服务对话与判定。
	system := sentinelJudgeSystemPrompt
	if suffix := skillPromptSuffix(ctx); suffix != "" {
		system += suffix
	}
	run, err := e.graph.Invoke(ctx, JudgePrompt{
		System: system,
		User:   pack.Prompt,
	})
	if err != nil {
		return nil, llm.Classify(err)
	}

	verdict := run.Verdict
	partial := run.Partial || e.stub
	if verdict == nil {
		verdict = &JudgeVerdict{
			VulnClass: "OTHER",
			Severity:  "info",
			Title:     "模型输出不合法",
			Reasoning: fmt.Sprintf("连续 %d 次输出未通过校验：%s", run.Attempts, run.LastError),
			Evidence:  []string{},
		}
	}
	verdict = applyEvidenceCheck(verdict, HunkHeaders(files))

	return &EvalOutcome{Pack: pack, Run: run, Verdict: verdict, Partial: partial}, nil
}

func isNoKey(err error) bool {
	return errors.Is(err, llm.ErrNoKey)
}
