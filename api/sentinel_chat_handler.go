package api

import (
	"errors"

	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

// SentinelChatHandler 是对话工作台的模型入口。
//
// 之前对话页是纯 mock 回放（useRunPlayback + mockRuns），Eino 只接了判定。
// 这里把对话接到同一条模型链路上：设置里的模型配置 → eino ChatModel → 回答，
// 并把结果包装成与前端渲染层一致的事件序列（skill.loaded / message.* / run.finished），
// 页面不需要为「真数据」再写一套渲染。
type SentinelChatHandler struct {
	svc *service.SentinelChatService
}

func NewSentinelChatHandler() *SentinelChatHandler {
	var cfg config.LLMConfig
	if loaded := config.Loaded(); loaded != nil {
		cfg = loaded.LLM
	}
	return &SentinelChatHandler{svc: service.NewSentinelChatService(cfg)}
}

// chatEvent 与前端 deriveBlocks 的事件协议对齐。
type chatEvent struct {
	Seq     int     `json:"seq"`
	Type    string  `json:"type"`
	Payload gin.H   `json:"payload"`
}

// Chat POST /api/sentinel/chat
func (h *SentinelChatHandler) Chat(c *gin.Context) {
	var req service.ChatRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, err.Error())
		return
	}

	reply, err := h.svc.Chat(c.Request.Context(), req)
	if err != nil {
		if errors.Is(err, service.ErrLLMNotConfigured) {
			utils.BadRequest(c, "尚未配置模型接入：设置 → 模型接入 填 Base URL / 模型 / API Key 后重试")
			return
		}
		utils.BadRequest(c, err.Error())
		return
	}

	events := make([]chatEvent, 0, 5)
	seq := 0
	push := func(typ string, payload gin.H) {
		seq++
		events = append(events, chatEvent{Seq: seq, Type: typ, Payload: payload})
	}

	if reply.Skill != nil {
		push("skill.loaded", gin.H{
			"skill":   reply.Skill.ID,
			"name":    reply.Skill.Name,
			"version": reply.Skill.Version,
			"checks":  reply.Skill.Checks,
		})
	}
	push("message.delta", gin.H{"delta": reply.Answer})
	push("message.done", gin.H{
		"usage": gin.H{"in": reply.PromptTokens, "out": reply.CompletionTokens},
	})
	push("run.finished", gin.H{
		"status": "finished",
		"tokens": gin.H{"in": reply.PromptTokens, "out": reply.CompletionTokens},
	})

	utils.Success(c, gin.H{
		"answer": reply.Answer,
		"model":  reply.Model,
		"skill":  reply.Skill,
		"usage":  gin.H{"in": reply.PromptTokens, "out": reply.CompletionTokens},
		"events": events,
	})
}

// Skills GET /api/sentinel/skills —— 内置审计技能清单（对话页与审计页共用）。
func (h *SentinelChatHandler) Skills(c *gin.Context) {
	ctx := c.Request.Context()
	defaultID := ""
	if cur := service.CurrentSentinelSkill(ctx); cur != nil {
		defaultID = cur.ID
	}
	utils.Success(c, gin.H{
		"items":      service.SentinelSkillCatalog(),
		"default_id": defaultID,
	})
}

// SetDefaultSkill PUT /api/sentinel/skills/default —— 设定判定链路使用的审计技能。
func (h *SentinelChatHandler) SetDefaultSkill(c *gin.Context) {
	var body struct {
		SkillID string `json:"skill_id"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	ctx := c.Request.Context()
	if err := service.SetDefaultSentinelSkill(ctx, body.SkillID); err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	cur := service.CurrentSentinelSkill(ctx)
	utils.SuccessWithMessage(c, "默认审计技能已更新", gin.H{"skill": cur})
}
