package api

import (
	"errors"
	"strconv"

	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"
	"github.com/gin-gonic/gin"
)

// DictLearningHandler 字典自学习：学习条目（子域热词/路径热词）与阈值配置。
type DictLearningHandler struct{}

func NewDictLearningHandler() *DictLearningHandler { return &DictLearningHandler{} }

// ListLearning 学习条目分页。
// GET /api/dict-learning?kind=subdomain&page=1&page_size=50
func (h *DictLearningHandler) ListLearning(c *gin.Context) {
	if repo.Default() == nil {
		utils.Error(c, utils.ErrCodeDatabaseError, "数据层未初始化")
		return
	}
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))
	items, total, err := repo.Default().DictLearning().List(c.Request.Context(), c.Query("kind"), pageSize, (page-1)*pageSize)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, gin.H{"items": items, "total": total, "page": page, "page_size": pageSize})
}

// GetLearningConfig 读取自学习配置。
// GET /api/dict-learning/config
func (h *DictLearningHandler) GetLearningConfig(c *gin.Context) {
	cfg, err := service.LoadDictLearningConfig(c.Request.Context())
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, cfg)
}

// UpdateLearningConfig 保存自学习配置（开关 + 晋升阈值）。
// PUT /api/dict-learning/config {"enabled":true,"subdomain_min_hits":3,"path_min_hits":3}
func (h *DictLearningHandler) UpdateLearningConfig(c *gin.Context) {
	var cfg service.DictLearningConfig
	if err := c.ShouldBindJSON(&cfg); err != nil {
		utils.BadRequest(c, "请求体格式错误")
		return
	}
	if err := service.SaveDictLearningConfig(c.Request.Context(), cfg); err != nil {
		utils.Error(c, utils.ErrCodeInvalidParams, err.Error())
		return
	}
	utils.Success(c, gin.H{"ok": true})
}

// SetDenied 剔除/恢复学习条目：剔除后不再计频不再晋升，也从词表消失。
// POST /api/dict-learning/:id/deny {"denied":true}
func (h *DictLearningHandler) SetDenied(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		utils.BadRequest(c, "非法条目 ID")
		return
	}
	var body struct {
		Denied *bool `json:"denied"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Denied == nil {
		utils.BadRequest(c, "请求体需要 denied 字段")
		return
	}
	if repo.Default() == nil {
		utils.Error(c, utils.ErrCodeDatabaseError, "数据层未初始化")
		return
	}
	if err := repo.Default().DictLearning().SetDenied(c.Request.Context(), id, *body.Denied); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			utils.NotFound(c, "条目不存在")
			return
		}
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, gin.H{"ok": true})
}

// LearningStats 各类型学习条目计数（字典页角标）。
// GET /api/dict-learning/stats
func (h *DictLearningHandler) LearningStats(c *gin.Context) {
	if repo.Default() == nil {
		utils.Error(c, utils.ErrCodeDatabaseError, "数据层未初始化")
		return
	}
	ctx := c.Request.Context()
	lr := repo.Default().DictLearning()
	sub, err := lr.CountByKind(ctx, repo.DictKindSubdomain)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	paths, err := lr.CountByKind(ctx, repo.DictKindPath)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, gin.H{repo.DictKindSubdomain: sub, repo.DictKindPath: paths})
}
