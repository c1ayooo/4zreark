package api

import (
	"errors"
	"strconv"

	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

// VerificationHandler 是验证域的操作面：
// 历史查询、批量核验预览、强制复验、失联删除。
type VerificationHandler struct {
	ops *service.VerificationOpsService
}

func NewVerificationHandler() *VerificationHandler {
	return &VerificationHandler{ops: service.NewVerificationOpsService()}
}

// ListVerifications 跨站点验证历史。
// GET /api/verifications?project_id=&site_id=&status=&reason_code=&page=&page_size=
func (h *VerificationHandler) ListVerifications(c *gin.Context) {
	var f repo.VerificationFilter
	f.ProjectID, _ = strconv.ParseInt(c.Query("project_id"), 10, 64)
	f.SiteID, _ = strconv.ParseInt(c.Query("site_id"), 10, 64)
	f.Status = c.Query("status")
	f.ReasonCode = c.Query("reason_code")
	f.Page, _ = strconv.Atoi(c.DefaultQuery("page", "1"))
	f.PageSize, _ = strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if f.Page < 1 {
		f.Page = 1
	}
	if f.PageSize < 1 || f.PageSize > 500 {
		f.PageSize = 20
	}

	items, total, err := h.ops.List(c.Request.Context(), f)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, gin.H{
		"items":     items,
		"total":     total,
		"page":      f.Page,
		"page_size": f.PageSize,
	})
}

// PreviewBatch 批量核验预览：只返回受影响的站点数与样本。
// POST /api/verifications/batches/preview
func (h *VerificationHandler) PreviewBatch(c *gin.Context) {
	var body struct {
		ProjectID int64  `json:"project_id"`
		Q         string `json:"q"`
		Catalog   string `json:"catalog"`
		View      string `json:"view"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	res, err := h.ops.PreviewBatch(c.Request.Context(), repo.AssetQuery{
		ProjectID: body.ProjectID,
		Q:         body.Q,
		Catalog:   body.Catalog,
		View:      body.View,
	})
	if err != nil {
		if errors.Is(err, repo.ErrDSLSyntax) {
			utils.Error(c, utils.ErrCodeInvalidParams, err.Error())
			return
		}
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, res)
}

type verificationIDsBody struct {
	SiteIDs []int64 `json:"site_ids" binding:"required"`
}

// RecheckAssets 强制复验：重置 attempts 与失联状态，下一次探测立即重跑。
// POST /api/assets/verification-recheck
func (h *VerificationHandler) RecheckAssets(c *gin.Context) {
	var body verificationIDsBody
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	actor, _ := c.Get("username")
	name, _ := actor.(string)
	report, err := h.ops.Recheck(c.Request.Context(), body.SiteIDs, name, c.ClientIP())
	if err != nil {
		if errors.Is(err, service.ErrVerificationInput) {
			utils.BadRequest(c, err.Error())
			return
		}
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, report)
}

// DeleteLostAssets 逐条复核后删除失联站点。
// POST /api/assets/lost-delete
func (h *VerificationHandler) DeleteLostAssets(c *gin.Context) {
	var body verificationIDsBody
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	actor, _ := c.Get("username")
	name, _ := actor.(string)
	report, err := h.ops.DeleteLost(c.Request.Context(), body.SiteIDs, name, c.ClientIP())
	if err != nil {
		if errors.Is(err, service.ErrVerificationInput) {
			utils.BadRequest(c, err.Error())
			return
		}
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, report)
}

// ExecuteBatch 按筛选条件批量复验（与预览共用筛选口径，单批最多 500 条）。
// POST /api/verifications/batches
func (h *VerificationHandler) ExecuteBatch(c *gin.Context) {
	var body struct {
		ProjectID int64  `json:"project_id"`
		Q         string `json:"q"`
		Catalog   string `json:"catalog"`
		View      string `json:"view"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	actor, _ := c.Get("username")
	name, _ := actor.(string)
	res, err := h.ops.ExecuteBatch(c.Request.Context(), repo.AssetQuery{
		ProjectID: body.ProjectID, Q: body.Q, Catalog: body.Catalog, View: body.View,
	}, name, c.ClientIP())
	if err != nil {
		switch {
		case errors.Is(err, repo.ErrDSLSyntax), errors.Is(err, service.ErrVerificationInput):
			utils.Error(c, utils.ErrCodeInvalidParams, err.Error())
		default:
			utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		}
		return
	}
	utils.SuccessWithMessage(c, "批量复验完成", res)
}

// Stats 验证状态与失败原因分布。
// GET /api/verifications/stats?project_id=
func (h *VerificationHandler) Stats(c *gin.Context) {
	projectID, _ := strconv.ParseInt(c.Query("project_id"), 10, 64)
	st, err := h.ops.Stats(c.Request.Context(), projectID)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, st)
}
