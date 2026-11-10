// Package llm 是平台统一的模型接入层（eino 组件封装）。
//
// 模型接入一律走 cloudwego/eino 的 model.BaseChatModel 抽象：
//   - 真实模型：eino-ext/components/model/openai（OpenAI 兼容端点，BaseURL 可指向
//     DeepSeek / Qwen / vLLM 等自建网关）；
//   - 联调模型：本包的 StubModel 实现同一接口，未配置密钥时链路仍可端到端跑通。
//
// 编排（重试、结构化校验、分支）不在这里手写，交给 eino 的 compose.Graph，
// 见 service/sentinel_judge_graph.go。
package llm

import (
	"context"
	"errors"
	"strings"
	"time"

	einoopenai "github.com/cloudwego/eino-ext/components/model/openai"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"

	"github.com/c1ayooo/4zreark/config"
)

// NewJSONChatModel 构建强制 JSON 输出的 ChatModel（判定场景专用）。
// 未配置密钥返回 ErrNoKey，调用方据此降级到 StubModel。
func NewJSONChatModel(ctx context.Context, cfg config.LLMConfig) (model.BaseChatModel, error) {
	return newChatModel(ctx, cfg, true)
}

// NewChatModel 构建通用对话模型（不强制 JSON 输出）。
// 对话工作台用它；判定必须有结构化输出，仍走 NewJSONChatModel。
func NewChatModel(ctx context.Context, cfg config.LLMConfig) (model.BaseChatModel, error) {
	return newChatModel(ctx, cfg, false)
}

func newChatModel(ctx context.Context, cfg config.LLMConfig, jsonMode bool) (model.BaseChatModel, error) {
	cfg.Normalize()
	key := strings.TrimSpace(cfg.EffectiveAPIKey())
	if key == "" {
		return nil, ErrNoKey
	}

	maxTokens := cfg.MaxTokens
	temperature := float32(cfg.Temperature)
	conf := &einoopenai.ChatModelConfig{
		BaseURL:     cfg.BaseURL,
		APIKey:      key,
		Model:       cfg.Model,
		Timeout:     time.Duration(cfg.TimeoutSeconds) * time.Second,
		MaxTokens:   &maxTokens,
		Temperature: &temperature,
	}
	if jsonMode {
		conf.ResponseFormat = &einoopenai.ChatCompletionResponseFormat{
			Type: einoopenai.ChatCompletionResponseFormatTypeJSONObject,
		}
	}
	cm, err := einoopenai.NewChatModel(ctx, conf)
	if err != nil {
		return nil, ErrPermanent
	}
	// 重试仍在 eino 抽象内：包装的是 model.BaseChatModel，图外无需感知。
	if cfg.MaxRetries > 0 {
		return &retryModel{base: cm, maxRetries: cfg.MaxRetries, baseDelay: time.Second}, nil
	}
	return cm, nil
}

// retryModel 只对可重试错误（限流/5xx/网络）做指数退避。
// 永久错误与未配置密钥直接返回；Stream 一旦开始输出就不再重试。
// 退避 1s/2s/4s…封顶 15s：中转服务端的 unexpected EOF 抖动通常持续数秒，
// 200ms 级别的快速重试跨不过去，只会把三次尝试都撞在同一窗口里。
type retryModel struct {
	base       model.BaseChatModel
	maxRetries int
	baseDelay  time.Duration
}

func (m *retryModel) Generate(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.Message, error) {
	var lastErr error
	for attempt := 0; attempt <= m.maxRetries; attempt++ {
		msg, err := m.base.Generate(ctx, input, opts...)
		if err == nil && msg != nil && strings.TrimSpace(msg.Content) != "" {
			return msg, nil
		}
		// 服务端断连的另一形态：HTTP 200 但响应体为空。与网络错误同属
		// 瞬时故障（Classify 对未知错误归 ErrTransient），一并退避重试。
		if err == nil {
			err = errors.New("模型返回空内容")
		}
		lastErr = err
		if !retryableLLMError(err) {
			return nil, err
		}
		if attempt == m.maxRetries {
			break
		}
		delay := m.baseDelay << attempt
		if delay > 15*time.Second {
			delay = 15 * time.Second
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(delay):
		}
	}
	return nil, lastErr
}

func (m *retryModel) Stream(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	return m.base.Stream(ctx, input, opts...)
}

func retryableLLMError(err error) bool {
	classified := Classify(err)
	return errors.Is(classified, ErrTransient) || errors.Is(classified, ErrRateLimited)
}

// StubModel 是未配置密钥时的替身模型：实现 model.BaseChatModel，
// 固定返回「不是安全修复」，并自带 token 估算，保证采集→判定→落库链路可跑通。
// 它产出的判定由调用方标记 partial，不会污染真实结论。
type StubModel struct {
	// Reason 会写进 reasoning 字段，便于前端一眼看出是桩。
	Reason string
}

// NewStubModel 构造桩模型。
func NewStubModel(reason string) *StubModel {
	if strings.TrimSpace(reason) == "" {
		reason = "未配置 LLM 密钥，使用桩模型"
	}
	return &StubModel{Reason: reason}
}

const stubContent = `{"is_security_fix":false,"vuln_class":"OTHER","confidence":0,` +
	`"severity":"info","component":"","reasoning":"stub model","evidence":[]}`

// Generate 返回固定的「非安全修复」结论。
func (s *StubModel) Generate(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.Message, error) {
	msg := schema.AssistantMessage(stubContent, nil)
	msg.ResponseMeta = &schema.ResponseMeta{
		FinishReason: "stop",
		Usage: &schema.TokenUsage{
			PromptTokens:     estimateMessages(input),
			CompletionTokens: EstimateTokens(stubContent),
		},
	}
	return msg, nil
}

// Stream 把单条消息包成流，满足 BaseChatModel 接口（判定只用 Generate）。
func (s *StubModel) Stream(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	msg, err := s.Generate(ctx, input, opts...)
	if err != nil {
		return nil, err
	}
	return schema.StreamReaderFromArray([]*schema.Message{msg}), nil
}

func estimateMessages(input []*schema.Message) int {
	total := 0
	for _, m := range input {
		if m != nil {
			total += EstimateTokens(m.Content)
		}
	}
	return total
}
