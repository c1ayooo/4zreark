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
	return cm, nil
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
