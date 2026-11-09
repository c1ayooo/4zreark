package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/internal/llm"

	"github.com/cloudwego/eino/schema"
)

// ErrLLMNotConfigured 表示模型接入没配好。调用方据此给「去设置里配」的明确提示，
// 而不是抛一个 500 让人猜。
var ErrLLMNotConfigured = errors.New("模型接入未配置")

// 对话上下文上限：最近 20 条、单条 32KB。超出直接截断而不是报错，
// 前端输入框本来也限制不到那么长。
const (
	chatMaxMessages    = 20
	chatMaxContentRune = 32000
)

// ChatMessage 是一条对话消息（role: system/user/assistant）。
type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ChatRequest 是对话入参。
type ChatRequest struct {
	Messages []ChatMessage `json:"messages"`
	// SkillID 为空表示不注入技能。
	SkillID string `json:"skill_id"`
	// System 覆盖默认人设（一般不用传）。
	System string `json:"system"`
}

// ChatReply 是一次对话结果。
type ChatReply struct {
	Answer           string
	Model            string
	PromptTokens     int
	CompletionTokens int
	Stub             bool
	Skill            *SentinelSkill
}

// SentinelChatService 负责对话工作台的模型调用。
// 模型配置每次调用时从「设置 → 模型接入」读取，保存即生效，不需要重启。
type SentinelChatService struct {
	fallback config.LLMConfig
}

// NewSentinelChatService 构造对话服务；fallback 是启动配置（环境变量）。
func NewSentinelChatService(cfg config.LLMConfig) *SentinelChatService {
	return &SentinelChatService{fallback: cfg}
}

const sentinelChatPersona = `你是 CommitSentinel 的代码审计助手，服务于安全工程师。
回答要求：
1. 先给结论，再给依据；依据必须落到具体的文件、函数、行或 diff 片段。
2. 不确定就说不确定，不要编造未提供的代码、CVE 编号或行号。
3. 涉及利用时只描述判定要点与可达性，不写可直接武器化的完整利用代码。
4. 中文回答，代码与标识符保持原文。`

// Chat 调一次模型并返回回答。
func (s *SentinelChatService) Chat(ctx context.Context, req ChatRequest) (*ChatReply, error) {
	msgs := normalizeChatMessages(req.Messages)
	if len(msgs) == 0 {
		return nil, errors.New("消息为空")
	}

	// 未指定技能时按内容自动匹配，匹配不到回退默认技能：否则系统提示里没有任何
	// 检查清单，模型被问「你有哪些技能」会答「没有」，与平台里实际存在的技能不一致。
	skill, hasSkill, _ := ResolveSkillForMessage(ctx, req.SkillID, "", lastUserText(msgs))

	system := strings.TrimSpace(req.System)
	if system == "" {
		system = sentinelChatPersona
	}
	if hasSkill {
		system += "\n\n【当前审计技能：" + skill.Name + " " + skill.Version + "】\n" +
			"注意：技能是一份审计检查清单（查什么、按什么顺序查），不是可调用的工具或函数，" +
			"它已经生效；若用户问「你有哪些技能 / 检查项」，直接说明当前技能名称与下列检查项。\n" +
			skill.Prompt
		system += skillCatalogFooter(skill.ID)
	}

	cfg := s.fallback
	if loaded := config.Loaded(); loaded != nil {
		cfg = loaded.LLM
	}
	cfg = EffectiveLLMConfig(ctx, cfg)
	if strings.TrimSpace(cfg.EffectiveAPIKey()) == "" {
		return nil, ErrLLMNotConfigured
	}

	cm, err := llm.NewChatModel(ctx, cfg)
	if err != nil {
		if errors.Is(err, llm.ErrNoKey) {
			return nil, ErrLLMNotConfigured
		}
		return nil, fmt.Errorf("构建模型失败: %w", err)
	}

	payload := make([]*schema.Message, 0, len(msgs)+1)
	payload = append(payload, schema.SystemMessage(system))
	for _, m := range msgs {
		switch m.Role {
		case "assistant":
			payload = append(payload, schema.AssistantMessage(m.Content, nil))
		default:
			payload = append(payload, schema.UserMessage(m.Content))
		}
	}

	out, err := cm.Generate(ctx, payload)
	if err != nil {
		return nil, llm.Classify(err)
	}

	reply := &ChatReply{
		Answer: out.Content,
		Model:  cfg.Model,
	}
	if out.ResponseMeta != nil && out.ResponseMeta.Usage != nil {
		reply.PromptTokens = out.ResponseMeta.Usage.PromptTokens
		reply.CompletionTokens = out.ResponseMeta.Usage.CompletionTokens
	}
	if hasSkill {
		s := skill
		reply.Skill = &s
	}
	return reply, nil
}

// lastUserText 取最后一条用户消息：自动匹配技能时只看这一条，
// 用整段历史会让上一轮的话题把这一轮带偏。
func lastUserText(msgs []ChatMessage) string {
	for i := len(msgs) - 1; i >= 0; i-- {
		if msgs[i].Role != "assistant" {
			return msgs[i].Content
		}
	}
	return ""
}

// normalizeChatMessages 丢掉空消息、裁掉超长内容，只保留最近 N 条。
func normalizeChatMessages(in []ChatMessage) []ChatMessage {
	out := make([]ChatMessage, 0, len(in))
	for _, m := range in {
		content := strings.TrimSpace(m.Content)
		if content == "" {
			continue
		}
		role := strings.ToLower(strings.TrimSpace(m.Role))
		if role != "assistant" {
			role = "user"
		}
		runes := []rune(content)
		if len(runes) > chatMaxContentRune {
			content = string(runes[:chatMaxContentRune]) + "\n…（已截断）"
		}
		out = append(out, ChatMessage{Role: role, Content: content})
	}
	if len(out) > chatMaxMessages {
		out = out[len(out)-chatMaxMessages:]
	}
	return out
}
