package api

import (
	"context"
	"log"
	"time"

	"github.com/c1ayooo/4zreark/internal/githubtokens"
	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

// GitHubTokensHandler GitHub Token 池管理（迁移自 4zreco/internal/handler/github/github_tokens.go）。
// 池是全局资源（监控轮询 / dork 扫描等多消费方共享 5000 次/日/号配额），
// 路由挂全局 /github-tokens 段，不进项目维度。
type GitHubTokensHandler struct{}

func NewGitHubTokensHandler() *GitHubTokensHandler { return &GitHubTokensHandler{} }

// List 池内全部账号：token 不回显（只有 Masked），配额字段供面板展示。
func (h *GitHubTokensHandler) List(c *gin.Context) {
	store := service.GitHubTokenStore()
	if store == nil {
		utils.InternalError(c, "Token 池未就绪（监控服务未初始化）")
		return
	}
	tokens, err := store.List(c.Request.Context())
	if err != nil {
		utils.InternalError(c, "读取 Token 池失败: "+err.Error())
		return
	}
	if tokens == nil {
		tokens = []githubtokens.Token{}
	}
	utils.Success(c, tokens)
}

// Add 入池一个 PAT：占位值拒绝、同号去重（入池前校验在包层）；成功后立即采集一次配额。
func (h *GitHubTokensHandler) Add(c *gin.Context) {
	var req struct {
		Label string `json:"label"`
		Token string `json:"token" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "请求体不合法（需要 token 字段）")
		return
	}
	store, pool, ok := h.ready(c)
	if !ok {
		return
	}
	t, err := store.Add(c.Request.Context(), req.Label, req.Token)
	if err != nil {
		// 占位值/重复号是用户输入问题，回 400 带原因
		utils.BadRequest(c, err.Error())
		return
	}
	if err := store.Refresh(c.Request.Context(), t.ID, pool.HTTPClient()); err != nil {
		log.Printf("[GitHubTokens] 新 token 配额采集失败: %v", err)
	}
	t, err = store.Get(c.Request.Context(), t.ID)
	if err != nil {
		utils.InternalError(c, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "已入池", t)
}

// Delete 出池一个账号。
func (h *GitHubTokensHandler) Delete(c *gin.Context) {
	store, _, ok := h.ready(c)
	if !ok {
		return
	}
	if err := store.Delete(c.Request.Context(), c.Param("id")); err != nil {
		utils.InternalError(c, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "已删除", nil)
}

// SetEnabled 启用/停用某账号（停用后不再参与轮换，额度数据保留）。
func (h *GitHubTokensHandler) SetEnabled(c *gin.Context) {
	var req struct {
		Enabled *bool `json:"enabled" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Enabled == nil {
		utils.BadRequest(c, "请求体不合法（需要 enabled 字段）")
		return
	}
	store, _, ok := h.ready(c)
	if !ok {
		return
	}
	if err := store.SetEnabled(c.Request.Context(), c.Param("id"), *req.Enabled); err != nil {
		utils.InternalError(c, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "已更新", nil)
}

// RefreshOne 单号配额采集（rate_limit 端点不消耗 search/core 配额）。
func (h *GitHubTokensHandler) RefreshOne(c *gin.Context) {
	store, pool, ok := h.ready(c)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()
	if err := store.Refresh(ctx, c.Param("id"), pool.HTTPClient()); err != nil {
		utils.InternalError(c, "配额采集失败: "+err.Error())
		return
	}
	t, err := store.Get(c.Request.Context(), c.Param("id"))
	if err != nil {
		utils.InternalError(c, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "已刷新", t)
}

// RefreshAll 全池配额采集。
func (h *GitHubTokensHandler) RefreshAll(c *gin.Context) {
	store, pool, ok := h.ready(c)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 60*time.Second)
	defer cancel()
	if errs := pool.RefreshRates(ctx); len(errs) > 0 {
		// 部分号失败不算全失败：返回当前状态，错误信息带出去
		tokens, lerr := store.List(c.Request.Context())
		if lerr != nil {
			utils.InternalError(c, "刷新完成但读取状态失败: "+lerr.Error())
			return
		}
		utils.SuccessWithMessage(c, "部分账号刷新失败： "+errs[0].Error(), tokens)
		return
	}
	tokens, err := store.List(c.Request.Context())
	if err != nil {
		utils.InternalError(c, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "全部已刷新", tokens)
}

// PrunePlaceholders 清理历史遗留的占位/示例 token 行（幂等），返回被删标签。
func (h *GitHubTokensHandler) PrunePlaceholders(c *gin.Context) {
	store, _, ok := h.ready(c)
	if !ok {
		return
	}
	removed, err := store.PrunePlaceholders(c.Request.Context())
	if err != nil {
		utils.InternalError(c, err.Error())
		return
	}
	if removed == nil {
		removed = []string{}
	}
	utils.SuccessWithMessage(c, "清理完成", gin.H{"removed": removed})
}

// ready 返回（store, pool）；服务未就绪时直接回 503。
func (h *GitHubTokensHandler) ready(c *gin.Context) (*githubtokens.Store, *githubtokens.Pool, bool) {
	store := service.GitHubTokenStore()
	pool := service.GitHubTokenPool()
	if store == nil || pool == nil {
		utils.InternalError(c, "Token 池未就绪（监控服务未初始化）")
		return nil, nil, false
	}
	return store, pool, true
}
