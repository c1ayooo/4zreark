package api

import (
	"strconv"

	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

// RetentionHandler 是数据保留策略的查看与手动触发入口。
type RetentionHandler struct {
	svc *service.RetentionService
}

func NewRetentionHandler() *RetentionHandler {
	return &RetentionHandler{svc: service.NewRetentionService()}
}

// Policy 当前保留策略。
// GET /api/governance/retention
func (h *RetentionHandler) Policy(c *gin.Context) {
	utils.Success(c, h.svc.Policy())
}

// Run 手动执行一轮清理；?dry_run=1 只统计。
// POST /api/governance/retention/run
func (h *RetentionHandler) Run(c *gin.Context) {
	dryRun, _ := strconv.ParseBool(c.DefaultQuery("dry_run", "0"))
	actor, _ := c.Get("username")
	name, _ := actor.(string)
	rep, err := h.svc.RunOnce(c.Request.Context(), dryRun, name, c.ClientIP())
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, rep)
}
