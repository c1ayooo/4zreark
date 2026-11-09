package api

// GitHub Token 池 HTTP 入口（设置页「GitHub Token」面板）：
// 列表（掩码）/新增/删除。存储与 /github-tokens（监控面板）是同一个
// github_token_pool 表——历史上两条池并存导致「设置页加了 token、
// 监控/情报看不到」，现全部收敛到统一池，此处只是形状兼容的别名路由。

import (
	"log"

	"github.com/c1ayooo/4zreark/internal/githubtokens"
	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

type GitHubTokenHandler struct{}

func NewGitHubTokenHandler() *GitHubTokenHandler { return &GitHubTokenHandler{} }

// List 统一池内全部 token（掩码，含配额字段供展示）。
func (h *GitHubTokenHandler) List(c *gin.Context) {
	store := service.GitHubTokenStore()
	if store == nil {
		utils.InternalError(c, "Token 池未就绪（数据库未初始化）")
		return
	}
	tokens, err := store.List(c.Request.Context())
	if err != nil {
		utils.InternalError(c, "读取 GitHub token 池失败: "+err.Error())
		return
	}
	if tokens == nil {
		tokens = []githubtokens.Token{}
	}
	utils.Success(c, gin.H{"items": tokens, "total": len(tokens)})
}

// Add 入池一条（占位值拒绝、同号去重在 store 层）；成功后立即采集一次配额。
// 兼容两种备注字段名：label（统一池形状）/ name（本路由历史形状）。
func (h *GitHubTokenHandler) Add(c *gin.Context) {
	var body struct {
		Label string `json:"label"`
		Name  string `json:"name"`
		Token string `json:"token"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	label := body.Label
	if label == "" {
		label = body.Name
	}
	store := service.GitHubTokenStore()
	if store == nil {
		utils.InternalError(c, "Token 池未就绪（数据库未初始化）")
		return
	}
	t, err := store.Add(c.Request.Context(), label, body.Token)
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	if pool := service.GitHubTokenPool(); pool != nil {
		if err := store.Refresh(c.Request.Context(), t.ID, pool.HTTPClient()); err != nil {
			log.Printf("[GitHubTokens] 新 token 配额采集失败: %v", err)
		}
		t, err = store.Get(c.Request.Context(), t.ID)
		if err != nil {
			utils.InternalError(c, err.Error())
			return
		}
	}
	utils.SuccessWithMessage(c, "GitHub token 已加入池", t)
}

// Delete 按 id 从统一池删除。
func (h *GitHubTokenHandler) Delete(c *gin.Context) {
	store := service.GitHubTokenStore()
	if store == nil {
		utils.InternalError(c, "Token 池未就绪（数据库未初始化）")
		return
	}
	if err := store.Delete(c.Request.Context(), c.Param("id")); err != nil {
		utils.InternalError(c, "删除失败: "+err.Error())
		return
	}
	utils.SuccessWithMessage(c, "已删除", nil)
}
