package api

// GitHub Token 池 HTTP 入口：列表（掩码）/新增/删除。

import (
	"strings"

	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

type GitHubTokenHandler struct{}

func NewGitHubTokenHandler() *GitHubTokenHandler { return &GitHubTokenHandler{} }

// List 当前池内 token（掩码）。
func (h *GitHubTokenHandler) List(c *gin.Context) {
	items, err := service.ListGitHubTokens(c.Request.Context())
	if err != nil {
		utils.InternalError(c, "读取 GitHub token 池失败: "+err.Error())
		return
	}
	utils.Success(c, gin.H{"items": items, "total": len(items)})
}

// Add 新增一条。
func (h *GitHubTokenHandler) Add(c *gin.Context) {
	var body struct {
		Name  string `json:"name"`
		Token string `json:"token"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	if strings.TrimSpace(body.Token) == "" {
		utils.BadRequest(c, "token 不能为空")
		return
	}
	v, err := service.AddGitHubToken(c.Request.Context(), body.Name, body.Token)
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "GitHub token 已加入池", v)
}

// Delete 按 id 删除。
func (h *GitHubTokenHandler) Delete(c *gin.Context) {
	if err := service.DeleteGitHubToken(c.Request.Context(), c.Param("id")); err != nil {
		if err == repo.ErrNotFound {
			utils.NotFound(c, "token 不存在")
			return
		}
		utils.InternalError(c, "删除失败: "+err.Error())
		return
	}
	utils.SuccessWithMessage(c, "已删除", nil)
}
