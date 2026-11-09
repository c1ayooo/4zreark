package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/internal/llm"
	"github.com/c1ayooo/4zreark/repo"

	"github.com/cloudwego/eino/schema"
)

// ChatSessionService 负责对话工作台的会话持久化与流式回答。
//
// 与 SentinelChatService 的分工：
//   - SentinelChatService：无状态单轮/多轮调用（/chat，兼容旧前端与脚本）；
//   - 本服务：会话落库 + SSE 流式（/conversations/:id/messages），是界面使用的主路径。
type ChatSessionService struct {
	fallback config.LLMConfig
}

func NewChatSessionService(cfg config.LLMConfig) *ChatSessionService {
	return &ChatSessionService{fallback: cfg}
}

// ChatStreamEvent 是推给前端的一条 SSE 事件，形状与前端渲染层一致。
type ChatStreamEvent struct {
	Seq     int            `json:"seq"`
	Type    string         `json:"type"`
	Payload map[string]any `json:"payload"`
}

// ChatEmit 是事件回调；返回 error 表示客户端已断开，应立即停止生成。
type ChatEmit func(ev ChatStreamEvent) error

// ListConversations 返回当前用户的会话列表。
func (s *ChatSessionService) ListConversations(ctx context.Context, userID string) ([]repo.ChatConversation, error) {
	return repo.Default().Chat().ListConversations(ctx, userID, 100)
}

// CreateConversation 新建会话；标题留空时用「新对话」，首条消息发出后自动改名。
func (s *ChatSessionService) CreateConversation(ctx context.Context, userID, title, skillID string) (*repo.ChatConversation, error) {
	if strings.TrimSpace(skillID) != "" {
		if _, ok := FindSentinelSkill(skillID); !ok {
			return nil, errors.New("技能不存在或已停用: " + skillID)
		}
	}
	return repo.Default().Chat().CreateConversation(ctx, &repo.ChatConversation{
		UserID:  userID,
		Title:   strings.TrimSpace(title),
		SkillID: strings.TrimSpace(skillID),
	})
}

// GetConversation 取会话与全部消息。
func (s *ChatSessionService) GetConversation(ctx context.Context, id, userID string) (*repo.ChatConversation, []repo.ChatMessage, error) {
	conv, err := repo.Default().Chat().GetConversation(ctx, id, userID)
	if err != nil {
		return nil, nil, err
	}
	msgs, err := repo.Default().Chat().ListMessages(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	return conv, msgs, nil
}

func (s *ChatSessionService) Rename(ctx context.Context, id, userID, title string) error {
	title = strings.TrimSpace(title)
	if title == "" {
		return errors.New("标题不能为空")
	}
	if len([]rune(title)) > 60 {
		title = string([]rune(title)[:60])
	}
	return repo.Default().Chat().RenameConversation(ctx, id, userID, title)
}

func (s *ChatSessionService) SetSkill(ctx context.Context, id, userID, skillID string) error {
	if strings.TrimSpace(skillID) != "" {
		if _, ok := FindSentinelSkill(skillID); !ok {
			return errors.New("技能不存在或已停用: " + skillID)
		}
	}
	return repo.Default().Chat().SetConversationSkill(ctx, id, userID, strings.TrimSpace(skillID))
}

func (s *ChatSessionService) Delete(ctx context.Context, id, userID string) error {
	return repo.Default().Chat().DeleteConversation(ctx, id, userID)
}

// StreamMessage 是核心：落用户消息 → 调模型流式生成 → 落助手消息。
// 所有中间状态通过 emit 推给前端；即使客户端中途断开，已生成的部分也会落库。
func (s *ChatSessionService) StreamMessage(
	ctx context.Context,
	convID, userID, content string,
	uploadIDs []string,
	skillID string,
	emit ChatEmit,
) (*repo.ChatMessage, error) {
	content = strings.TrimSpace(content)
	if content == "" {
		return nil, errors.New("消息不能为空")
	}

	chatRepo := repo.Default().Chat()
	conv, err := chatRepo.GetConversation(ctx, convID, userID)
	if err != nil {
		return nil, err
	}

	// 技能优先级：本次请求 > 会话绑定 > 消息里点名的技能 > 判定链路默认技能。
	// 第三级是自动匹配：没手动选时按问题内容挑最贴的清单，
	// 否则一段 php 的 unserialize 会一直被钉在 java 的检查顺序上。
	skill, hasSkill, skillAuto := ResolveSkillForMessage(ctx, skillID, conv.SkillID, content)

	// 技能调用记录：先落「运行中」，函数返回时由 defer 回填 tokens / 耗时 / 状态。
	// 放在模型调用之前，模型没配好也能看出「技能选了但没跑起来」，否则这类静默失败会丢样本。
	skillUsageID := ""
	var (
		runStarted = time.Now()
		runStatus  = "finished"
		runErrMsg  string
		runModel   string
		runTokIn   int
		runTokOut  int
	)
	if hasSkill {
		skillUsageID = StartSkillUsage(ctx, skill, convID, userID, "chat", "")
		defer func() {
			FinishSkillUsage(skillUsageID, runStatus, runTokIn, runTokOut,
				int(time.Since(runStarted).Milliseconds()), runErrMsg, runModel)
		}()
	}

	// 1) 附件摘要拼进用户消息（原文太大，模型只需要结构和关键片段）
	attachMeta := make([]map[string]any, 0, len(uploadIDs))
	attachText := ""
	if len(uploadIDs) > 0 {
		uploads, err := chatRepo.GetUploads(ctx, uploadIDs, userID)
		if err != nil {
			return nil, err
		}
		for _, u := range uploads {
			var files []map[string]any
			_ = json.Unmarshal(u.Files, &files)
			attachMeta = append(attachMeta, map[string]any{
				"id": u.ID, "name": u.Name, "size": u.Size, "kind": u.Kind,
				"summary": u.Summary, "files": files,
			})
			attachText += "\n\n【附件 " + u.Name + "（" + u.Kind + "，" + humanSize(u.Size) + "）】\n" + u.Summary
		}
	}
	fullContent := content + attachText
	if len([]rune(fullContent)) > chatMaxContentRune {
		fullContent = string([]rune(fullContent)[:chatMaxContentRune]) + "\n…（已截断）"
	}

	// 2) 落用户消息（含附件元信息，刷新后还能看到当时上传了什么）
	metaJSON, _ := json.Marshal(attachMeta)
	userMsg, err := chatRepo.AppendMessage(ctx, &repo.ChatMessage{
		ConversationID: convID,
		Role:           "user",
		Content:        content,
		Attachments:    metaJSON,
	})
	if err != nil {
		return nil, err
	}

	// 3) 组装上下文：历史 + 本次
	history, err := chatRepo.ListMessages(ctx, convID)
	if err != nil {
		return nil, err
	}
	msgs := make([]ChatMessage, 0, len(history))
	for _, m := range history {
		if m.ID == userMsg.ID {
			continue
		}
		text := m.Content
		// 历史里的附件摘要不再重复注入：回答里已经体现过，重复只会烧 token。
		msgs = append(msgs, ChatMessage{Role: m.Role, Content: text})
	}
	msgs = append(msgs, ChatMessage{Role: "user", Content: fullContent})
	msgs = normalizeChatMessages(msgs)

	// 4) 模型配置
	cfg := s.fallback
	if loaded := config.Loaded(); loaded != nil {
		cfg = loaded.LLM
	}
	cfg = EffectiveLLMConfig(ctx, cfg)
	runModel = cfg.Model
	if strings.TrimSpace(cfg.EffectiveAPIKey()) == "" {
		runStatus, runErrMsg = "error", "未配置模型密钥"
		return userMsg, ErrLLMNotConfigured
	}
	cm, err := llm.NewChatModel(ctx, cfg)
	if err != nil {
		if errors.Is(err, llm.ErrNoKey) {
			runStatus, runErrMsg = "error", "未配置模型密钥"
			return userMsg, ErrLLMNotConfigured
		}
		runStatus, runErrMsg = "error", "构建模型失败: "+err.Error()
		return userMsg, fmt.Errorf("构建模型失败: %w", err)
	}

	// 5) 系统提示
	system := sentinelChatPersona
	if hasSkill {
		// 措辞要点：模型容易把「技能」理解成可调用工具，被问「你有什么 skill」时答「没有」。
		// 这里明确它是检查清单且已生效，避免这种自我否认。
		system += "\n\n【当前审计技能：" + skill.Name + " " + skill.Version + "】\n" +
			"注意：技能是一份审计检查清单（查什么、按什么顺序查），不是可调用的工具或函数，" +
			"它已经在本次对话中生效，无需也不能请求调用权限。" +
			"若用户问「你有哪些技能 / 检查项」，直接说明当前技能名称与下列检查项，不要说没有技能。\n" +
			skill.Prompt
		system += skillCatalogFooter(skill.ID)
	}
	payload := make([]*schema.Message, 0, len(msgs)+1)
	payload = append(payload, schema.SystemMessage(system))
	for _, m := range msgs {
		if m.Role == "assistant" {
			payload = append(payload, schema.AssistantMessage(m.Content, nil))
		} else {
			payload = append(payload, schema.UserMessage(m.Content))
		}
	}

	// 6) 事件序列：与前端 deriveBlocks 的协议保持一致
	seq := 0
	events := make([]ChatStreamEvent, 0, 8)
	send := func(typ string, p map[string]any) error {
		seq++
		ev := ChatStreamEvent{Seq: seq, Type: typ, Payload: p}
		events = append(events, ev)
		return emit(ev)
	}
	// delta 只推给前端、不落库：一句话几百个 chunk，全存下来会把 message 行撑到几 MB，
	// 而历史回放用 content 就够了。
	sendDelta := func(text string) error {
		seq++
		return emit(ChatStreamEvent{Seq: seq, Type: "message.delta", Payload: map[string]any{"delta": text}})
	}

	if hasSkill {
		if err := send("skill.loaded", map[string]any{
			"skill": skill.ID, "name": skill.Name, "version": skill.Version, "checks": skill.Checks,
			"auto": skillAuto,
		}); err != nil {
			return userMsg, err
		}
	}
	if len(attachMeta) > 0 {
		names := make([]string, 0, len(attachMeta))
		for _, a := range attachMeta {
			names = append(names, fmt.Sprint(a["name"]))
		}
		if err := send("attachment.loaded", map[string]any{
			"count": len(attachMeta), "names": names,
		}); err != nil {
			return userMsg, err
		}
	}

	// 7) 流式生成
	stream, err := cm.Stream(ctx, payload)
	if err != nil {
		classErr := llm.Classify(err)
		runStatus, runErrMsg = "error", classErr.Error()
		return userMsg, classErr
	}
	defer stream.Close()

	var answer strings.Builder
	usage := map[string]int{"in": 0, "out": 0}
	streamErr := error(nil)
	for {
		chunk, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			streamErr = llm.Classify(err)
			break
		}
		if chunk == nil {
			continue
		}
		if chunk.Content != "" {
			answer.WriteString(chunk.Content)
			if err := sendDelta(chunk.Content); err != nil {
				// 客户端断开：停止生成，但把已生成内容落库
				streamErr = nil
				goto persist
			}
		}
		if chunk.ResponseMeta != nil && chunk.ResponseMeta.Usage != nil {
			usage["in"] = chunk.ResponseMeta.Usage.PromptTokens
			usage["out"] = chunk.ResponseMeta.Usage.CompletionTokens
		}
	}

persist:
	if streamErr != nil && answer.Len() == 0 {
		return userMsg, streamErr
	}
	if answer.Len() == 0 {
		runStatus, runErrMsg = "error", "模型没有返回内容"
		return userMsg, errors.New("模型没有返回内容")
	}

	finalAnswer := answer.String()
	status := "finished"
	if streamErr != nil {
		status = "error"
	}
	runTokIn, runTokOut = usage["in"], usage["out"]
	if streamErr != nil {
		runStatus, runErrMsg = "error", streamErr.Error()
	}

	// 8) 落助手消息（带事件与用量，刷新可回放）
	eventsJSON, _ := json.Marshal(events)
	usageJSON, _ := json.Marshal(usage)
	assistantMsg, err := chatRepo.AppendMessage(ctx, &repo.ChatMessage{
		ConversationID: convID,
		Role:           "assistant",
		Content:        finalAnswer,
		Events:         eventsJSON,
		Usage:          usageJSON,
		Model:          cfg.Model,
	})
	if err != nil {
		return userMsg, err
	}

	_ = send("message.done", map[string]any{"usage": usage})
	_ = send("run.finished", map[string]any{"status": status, "tokens": usage, "model": cfg.Model})

	// 9) 会话元信息：模型名、首条消息自动命名
	_ = chatRepo.TouchConversation(ctx, convID, cfg.Model)
	if strings.TrimSpace(conv.Title) == "" || conv.Title == "新对话" {
		_ = chatRepo.RenameConversation(ctx, convID, userID, autoTitle(content))
	}

	if streamErr != nil {
		return assistantMsg, streamErr
	}
	return assistantMsg, nil
}

// ChatMessageHistory 把库里的消息转成前端渲染需要的形状（附带事件）。
func ChatMessageHistory(msgs []repo.ChatMessage) []map[string]any {
	out := make([]map[string]any, 0, len(msgs))
	for _, m := range msgs {
		item := map[string]any{
			"id":         m.ID,
			"role":       m.Role,
			"content":    m.Content,
			"created_at": m.CreatedAt,
			"model":      m.Model,
		}
		var attachments, events []map[string]any
		_ = json.Unmarshal(m.Attachments, &attachments)
		_ = json.Unmarshal(m.Events, &events)
		item["attachments"] = attachments
		item["events"] = events
		var usage map[string]int
		_ = json.Unmarshal(m.Usage, &usage)
		item["usage"] = usage
		out = append(out, item)
	}
	return out
}

func autoTitle(content string) string {
	content = strings.TrimSpace(strings.ReplaceAll(content, "\n", " "))
	if content == "" {
		return "新对话"
	}
	runes := []rune(content)
	if len(runes) > 24 {
		return string(runes[:24]) + "…"
	}
	return content
}

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}
