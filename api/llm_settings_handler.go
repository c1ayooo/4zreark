package api

import (
	"strings"

	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

// LLMSettingsHandler 管「设置 → 模型接入」：读配置、保存、连通性测试。
//
// 密钥永不出库：GET 只回 api_key_configured + 掩码；PUT 传空表示沿用旧密钥。
type LLMSettingsHandler struct{}

func NewLLMSettingsHandler() *LLMSettingsHandler { return &LLMSettingsHandler{} }

func operatorOf(c *gin.Context) string {
	for _, key := range []string{"username", "user_name", "nickname"} {
		if v := strings.TrimSpace(c.GetString(key)); v != "" {
			return v
		}
	}
	return ""
}

// Get GET /api/llm/settings
func (h *LLMSettingsHandler) Get(c *gin.Context) {
	view, err := service.GetLLMSettings(c.Request.Context())
	if err != nil {
		utils.InternalError(c, "读取模型接入配置失败: "+err.Error())
		return
	}
	utils.Success(c, view)
}

// Save PUT /api/llm/settings
func (h *LLMSettingsHandler) Save(c *gin.Context) {
	var in service.LLMSettingsInput
	if err := c.ShouldBindJSON(&in); err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	view, err := service.SaveLLMSettings(c.Request.Context(), in, operatorOf(c))
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "已保存，判定与对话立即生效", view)
}

// Test POST /api/llm/settings/test —— 用给定参数（密钥可留空读库里）实打实发一次请求。
func (h *LLMSettingsHandler) Test(c *gin.Context) {
	var in service.LLMSettingsInput
	if err := c.ShouldBindJSON(&in); err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	text, err := service.TestLLMSettings(c.Request.Context(), in)
	if err != nil {
		utils.BadRequest(c, "连通失败: "+err.Error())
		return
	}
	utils.Success(c, gin.H{
		"ok":      true,
		"message": "连通成功",
		"reply":   text,
	})
}
