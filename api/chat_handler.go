package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

// ChatHandler 是对话工作台的主接口：会话持久化 + SSE 流式回答 + 附件上传 + 技能库。
type ChatHandler struct {
	svc *service.ChatSessionService
}

func NewChatHandler() *ChatHandler {
	var cfg config.LLMConfig
	if loaded := config.Loaded(); loaded != nil {
		cfg = loaded.LLM
	}
	return &ChatHandler{svc: service.NewChatSessionService(cfg)}
}

// ListConversations GET /api/sentinel/conversations
func (h *ChatHandler) ListConversations(c *gin.Context) {
	items, err := h.svc.ListConversations(c.Request.Context(), c.GetString("user_id"))
	if err != nil {
		utils.InternalError(c, err.Error())
		return
	}
	utils.Success(c, gin.H{"items": items})
}

// CreateConversation POST /api/sentinel/conversations {title?, skill_id?}
func (h *ChatHandler) CreateConversation(c *gin.Context) {
	var body struct {
		Title   string `json:"title"`
		SkillID string `json:"skill_id"`
	}
	_ = c.ShouldBindJSON(&body)
	conv, err := h.svc.CreateConversation(c.Request.Context(), c.GetString("user_id"), body.Title, body.SkillID)
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "已新建对话", conv)
}

// GetConversation GET /api/sentinel/conversations/:id
func (h *ChatHandler) GetConversation(c *gin.Context) {
	conv, msgs, err := h.svc.GetConversation(c.Request.Context(), c.Param("id"), c.GetString("user_id"))
	if err != nil {
		utils.NotFound(c, "会话不存在")
		return
	}
	utils.Success(c, gin.H{
		"conversation": conv,
		"messages":     service.ChatMessageHistory(msgs),
	})
}

// PatchConversation PATCH /api/sentinel/conversations/:id {title?, skill_id?}
func (h *ChatHandler) PatchConversation(c *gin.Context) {
	var body struct {
		Title   *string `json:"title"`
		SkillID *string `json:"skill_id"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	ctx := c.Request.Context()
	userID := c.GetString("user_id")
	id := c.Param("id")

	if body.Title != nil {
		if err := h.svc.Rename(ctx, id, userID, *body.Title); err != nil {
			utils.BadRequest(c, err.Error())
			return
		}
	}
	if body.SkillID != nil {
		if err := h.svc.SetSkill(ctx, id, userID, *body.SkillID); err != nil {
			utils.BadRequest(c, err.Error())
			return
		}
	}
	conv, _, err := h.svc.GetConversation(ctx, id, userID)
	if err != nil {
		utils.NotFound(c, "会话不存在")
		return
	}
	utils.SuccessWithMessage(c, "已更新", conv)
}

// DeleteConversation DELETE /api/sentinel/conversations/:id
func (h *ChatHandler) DeleteConversation(c *gin.Context) {
	if err := h.svc.Delete(c.Request.Context(), c.Param("id"), c.GetString("user_id")); err != nil {
		utils.NotFound(c, "会话不存在")
		return
	}
	utils.SuccessWithMessage(c, "已删除", nil)
}

// StreamMessage POST /api/sentinel/conversations/:id/messages
//
// SSE：每帧 `data: {"seq":n,"type":"...","payload":{...}}`。
// 事件类型与前端渲染层一致：skill.loaded / attachment.loaded / message.delta /
// message.done / run.finished / error。
func (h *ChatHandler) StreamMessage(c *gin.Context) {
	var body struct {
		Content   string   `json:"content"`
		SkillID   string   `json:"skill_id"`
		UploadIDs []string `json:"upload_ids"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	if strings.TrimSpace(body.Content) == "" && len(body.UploadIDs) == 0 {
		utils.BadRequest(c, "消息不能为空")
		return
	}

	flusher, ok := c.Writer.(http.Flusher)
	if !ok {
		utils.InternalError(c, "当前连接不支持流式输出")
		return
	}

	c.Writer.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	c.Writer.Header().Set("Cache-Control", "no-cache, no-transform")
	c.Writer.Header().Set("Connection", "keep-alive")
	c.Writer.Header().Set("X-Accel-Buffering", "no")
	c.Status(http.StatusOK)
	flusher.Flush()

	emit := func(ev service.ChatStreamEvent) error {
		b, err := json.Marshal(ev)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(c.Writer, "data: %s\n\n", b); err != nil {
			return err
		}
		flusher.Flush()
		return nil
	}

	if _, err := h.svc.StreamMessage(
		c.Request.Context(),
		c.Param("id"),
		c.GetString("user_id"),
		body.Content,
		body.UploadIDs,
		body.SkillID,
		emit,
	); err != nil {
		// 已经写了 SSE 头，不能再用 utils 的错误响应，改推一条 error 事件。
		_ = emit(service.ChatStreamEvent{
			Seq:  9999,
			Type: "error",
			Payload: map[string]any{
				"message": err.Error(),
				"hint":    "模型配置在「设置 → 模型接入」；会话与消息已保存，可直接重试",
			},
		})
	}
}

// Upload POST /api/sentinel/uploads (multipart: file)
func (h *ChatHandler) Upload(c *gin.Context) {
	// 32MB 上限：足够放下常见源码包，又不至于让单次请求拖垮进程内存。
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 32<<20)

	file, err := c.FormFile("file")
	if err != nil {
		utils.BadRequest(c, "未收到文件或文件超过 32MB")
		return
	}
	src, err := file.Open()
	if err != nil {
		utils.BadRequest(c, "读取上传文件失败")
		return
	}
	defer src.Close()

	data, err := io.ReadAll(src)
	if err != nil {
		utils.BadRequest(c, "读取上传文件失败")
		return
	}

	upload, err := service.SaveChatUpload(c.Request.Context(), c.GetString("user_id"), file.Filename, data)
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "已解析附件", gin.H{
		"id":      upload.ID,
		"name":    upload.Name,
		"size":    upload.Size,
		"kind":    upload.Kind,
		"summary": upload.Summary,
	})
}

// ListSkills GET /api/sentinel/skills/manage —— 管理视图，带 prompt 与停用项
func (h *ChatHandler) ListSkills(c *gin.Context) {
	utils.Success(c, gin.H{"items": service.LoadSentinelSkills(c.Request.Context())})
}

// SaveSkill POST /api/sentinel/skills —— 新建或修改（body 带 id 即修改）
func (h *ChatHandler) SaveSkill(c *gin.Context) {
	var in service.SentinelSkillInput
	if err := c.ShouldBindJSON(&in); err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	skill, err := service.UpsertSentinelSkill(c.Request.Context(), in)
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "已保存技能", skill)
}

// DeleteSkill DELETE /api/sentinel/skills/:id
func (h *ChatHandler) DeleteSkill(c *gin.Context) {
	if err := service.DeleteSentinelSkill(c.Request.Context(), c.Param("id")); err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "已删除技能", nil)
}

// ImportSkill POST /api/sentinel/skills/import —— 上传 .json / .yaml / .md 批量导入
func (h *ChatHandler) ImportSkill(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		utils.BadRequest(c, "请选择要导入的技能文件")
		return
	}
	const maxSize = 2 << 20 // 2MB：技能是纯文本清单，超过这个体量基本是误传
	if file.Size > maxSize {
		utils.BadRequest(c, "技能文件不能超过 2MB")
		return
	}
	f, err := file.Open()
	if err != nil {
		utils.InternalError(c, "读取文件失败: "+err.Error())
		return
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxSize))
	if err != nil {
		utils.InternalError(c, "读取文件失败: "+err.Error())
		return
	}

	saved, failed, err := service.ImportSentinelSkills(c.Request.Context(), file.Filename, data)
	if err != nil && len(saved) == 0 {
		utils.BadRequest(c, err.Error())
		return
	}
	utils.SuccessWithMessage(c, fmt.Sprintf("已导入 %d 个技能", len(saved)), gin.H{
		"items":  saved,
		"failed": failed,
	})
}

// SkillUsage GET /api/sentinel/skills/usage —— 技能调用记录（分页 + 汇总）
func (h *ChatHandler) SkillUsage(c *gin.Context) {
	var q service.SkillUsageQuery
	if err := c.ShouldBindQuery(&q); err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	// 管理员/操作员看全局，普通成员只看自己的调用，避免互相看到会话标题外的行为数据。
	if role := c.GetString("role"); role != "admin" && role != "operator" {
		q.ScopeUserID = c.GetString("user_id")
	}
	page, err := service.ListSkillUsage(c.Request.Context(), q)
	if err != nil {
		utils.InternalError(c, err.Error())
		return
	}
	utils.Success(c, page)
}
