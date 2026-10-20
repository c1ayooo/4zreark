package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/c1ayooo/4zreark/repo"
)

// AssetService 是资产治理域的读侧与导入入口。
// handler 不再直接碰 repo：分层规矩和 users/tasks 保持一致，越界的 SQL 只能出现在 repo 包里。
type AssetService struct{}

func NewAssetService() *AssetService { return &AssetService{} }

func (s *AssetService) repo() (*repo.AssetRepo, error) {
	if repo.Default() == nil {
		return nil, errors.New("数据层未初始化")
	}
	return repo.NewAssetRepo(), nil
}

// Overview 是首页统计：原始记录与归并站点分开计，口径见 v2 §2.3。
func (s *AssetService) Overview(ctx context.Context) (*repo.Overview, error) {
	a, err := s.repo()
	if err != nil {
		return nil, err
	}
	return a.Overview(ctx)
}

func (s *AssetService) ListProjects(ctx context.Context) ([]*repo.Project, error) {
	a, err := s.repo()
	if err != nil {
		return nil, err
	}
	return a.ListProjects(ctx)
}

// ListAssets 是资产列表：view × kind × catalog 三层正交维度 + DSL 查询串。
// DSL 语法错误会带上出错位置返回；结构化参数非法则静默回落缺省（v4 §11.4 的容错边界）。
func (s *AssetService) ListAssets(ctx context.Context, q repo.AssetQuery) (*repo.AssetPage, error) {
	a, err := s.repo()
	if err != nil {
		return nil, err
	}
	switch {
	case q.PageSize < 1:
		q.PageSize = 20
	case q.PageSize > 500:
		// 硬上限 500：请求 1000 返回 500 条，而不是回落到 20
		q.PageSize = 500
	}
	return a.ListAssets(ctx, q)
}

// CheckQuery 只编译不查库，供前端语法框实时反馈。
func (s *AssetService) CheckQuery(q string) (string, error) {
	expr, _, err := repo.BuildAssetWhere(q)
	if err != nil {
		return "", err
	}
	return expr, nil
}

// ImportRecords 批量导入原始记录并归并。上限 5000 条，超过请分片调用。
func (s *AssetService) ImportRecords(ctx context.Context, projectID int64, source string, records []repo.RawRecord) (*repo.ImportResult, error) {
	a, err := s.repo()
	if err != nil {
		return nil, err
	}
	if projectID <= 0 {
		return nil, errors.New("project_id 必填")
	}
	if len(records) == 0 || len(records) > 5000 {
		return nil, fmt.Errorf("records 数量需在 1..5000，收到 %d", len(records))
	}
	if source == "" {
		source = "api"
	}
	return a.ImportRecords(ctx, projectID, source, records)
}

// VerifySite 是人工判定（不发网络请求）。真实探测走 VerifyService.ProbeSite。
func (s *AssetService) VerifySite(ctx context.Context, siteID int64, reachable bool, code int, reason string) error {
	a, err := s.repo()
	if err != nil {
		return err
	}
	return a.VerifySite(ctx, siteID, reachable, code, reason)
}

func (s *AssetService) RecentEvents(ctx context.Context, limit int) ([]map[string]any, error) {
	a, err := s.repo()
	if err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	return a.RecentEvents(ctx, limit)
}
