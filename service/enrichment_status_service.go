package service

import (
	"context"
	"errors"

	"github.com/c1ayooo/4zreark/repo"
)

// EnrichmentStatusService 汇总情报富化进度，只读。
type EnrichmentStatusService struct{}

func NewEnrichmentStatusService() *EnrichmentStatusService { return &EnrichmentStatusService{} }

func (s *EnrichmentStatusService) Status(ctx context.Context) (*repo.EnrichmentStats, error) {
	if repo.Default() == nil {
		return nil, errors.New("数据层未初始化")
	}
	return repo.Default().IntelOps().EnrichmentStats(ctx)
}
