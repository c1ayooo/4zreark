package test

import (
	"context"
	"testing"

	"github.com/c1ayooo/4zreark/internal/fpscore"
	"github.com/c1ayooo/4zreark/repo"
)

// 指纹评分的 PG 集成测试：验证候选查询、评分、筛选在真实数据上能跑通。
// 未设置 ZRE_PG_PASSWORD 时由 openTestRepo 自动跳过。
func TestFingerprintScoresIntegration(t *testing.T) {
	openTestRepo(t)
	a := repo.NewAssetRepo()
	ctx := context.Background()

	page, err := a.ListFpScores(ctx, repo.FpScoreQuery{Page: 1, PageSize: 20})
	if err != nil {
		t.Fatalf("查询指纹评分失败: %v", err)
	}
	if page.Total < int64(len(page.Items)) {
		t.Fatalf("total=%d 小于当前页条数 %d", page.Total, len(page.Items))
	}
	for i := 1; i < len(page.Items); i++ {
		if page.Items[i-1].Score < page.Items[i].Score {
			t.Fatalf("默认排序不是分数倒序: %d < %d", page.Items[i-1].Score, page.Items[i].Score)
		}
	}
	for _, b := range page.Facets.Bands {
		if b.Label == "" {
			t.Fatalf("分档 %s 缺少展示名", b.Level)
		}
	}

	// 分数区间过滤：结果必须全部落在区间内。
	if page.Total > 0 {
		high, err := a.ListFpScores(ctx, repo.FpScoreQuery{MinScore: 40, PageSize: 50})
		if err != nil {
			t.Fatalf("按分数筛选失败: %v", err)
		}
		for _, s := range high.Items {
			if s.Score < 40 {
				t.Fatalf("min_score=40 返回了 %d 分的资产", s.Score)
			}
		}
	}

	// 分类过滤：分类来自规则命中或技术栈反推。
	if len(page.Facets.Categories) > 0 {
		cat := page.Facets.Categories[0]
		byCat, err := a.ListFpScores(ctx, repo.FpScoreQuery{Category: cat.Name, PageSize: 10})
		if err != nil {
			t.Fatalf("按分类筛选失败: %v", err)
		}
		for _, s := range byCat.Items {
			found := false
			for _, c := range s.Categories {
				if fpscore.CategoryKey(c) == cat.Name {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("分类筛选返回了不属于 %s 的资产 %s: %v", cat.Name, s.Host, s.Categories)
			}
		}
	}

	// 项目过滤。
	byProject, err := a.ListFpScores(ctx, repo.FpScoreQuery{ProjectID: 1, PageSize: 5})
	if err != nil {
		t.Fatalf("按项目筛选失败: %v", err)
	}
	for _, s := range byProject.Items {
		if s.ProjectID != 1 {
			t.Fatalf("project_id=1 返回了项目 %d 的资产", s.ProjectID)
		}
	}
}
