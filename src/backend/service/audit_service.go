package service

import (
	"context"
	"errors"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/repo"
)

// AuditService 审计日志查询（写入口在 middleware/logger.go 与各域自动动作）。
type AuditService struct{}

func NewAuditService() *AuditService { return &AuditService{} }

func (s *AuditService) List(ctx context.Context, f repo.AuditFilter) ([]*models.OperationLog, int64, error) {
	r := repo.Default()
	if r == nil {
		return nil, 0, errors.New("数据层未初始化")
	}
	return r.Audits().ListFiltered(ctx, f)
}
