package test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/internal/enterprise"
	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
)

// digitalFakeProvider 数字资产采集编排的 fake 数据源：两个企业候选，第二个拉取失败。
type digitalFakeProvider struct{}

func (f *digitalFakeProvider) Name() string { return "fakedigital" }
func (f *digitalFakeProvider) Search(context.Context, string, int) ([]enterprise.CompanyRef, error) {
	return []enterprise.CompanyRef{
		{ExtID: "ent-1", Name: "示例公司"},
		{ExtID: "ent-2", Name: "坏公司"},
	}, nil
}
func (f *digitalFakeProvider) Detail(_ context.Context, extID string) (*enterprise.CompanyDetail, error) {
	return &enterprise.CompanyDetail{ExtID: extID, Name: extID + "-公司"}, nil
}
func (f *digitalFakeProvider) Branches(context.Context, string, int, int) ([]enterprise.CompanyRef, bool, error) {
	return nil, false, nil
}
func (f *digitalFakeProvider) Investments(context.Context, string, int, int) ([]enterprise.CompanyRef, bool, error) {
	return nil, false, nil
}
func (f *digitalFakeProvider) Domains(context.Context, string, int, int) ([]enterprise.DomainHit, bool, error) {
	return nil, false, nil
}
func (f *digitalFakeProvider) DigitalAssets(_ context.Context, extID string, _, _ int) ([]enterprise.DigitalHit, bool, error) {
	if extID == "ent-2" {
		return nil, false, fmt.Errorf("上游签名校验失败")
	}
	return []enterprise.DigitalHit{
		{Kind: "app", Name: "示例App", Platform: "Android", EntityName: "示例公司", Evidence: "详情页 apps"},
		{Kind: "miniapp", Name: "示例小程序", Platform: "微信", EntityName: "示例公司"},
		{Kind: "app", Name: "已有应用", EntityName: "示例公司"},
	}, false, nil
}

// 数字资产采集编排：定位企业 → 拉取 → 入池对账；单企业失败记 warning 不中断。
func TestDigitalCandidatesCollect(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	code := fmt.Sprintf("digcollect-%d", time.Now().UnixNano())
	var projectID int64
	if err := r.Pool().QueryRow(ctx,
		`INSERT INTO projects (code, name) VALUES ($1, $2) RETURNING id`, code, code).Scan(&projectID); err != nil {
		t.Fatalf("建测试项目失败: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = r.Pool().Exec(bg, `DELETE FROM import_batches WHERE project_id = $1`, projectID)
		_, _ = r.Pool().Exec(bg, `DELETE FROM projects WHERE id = $1`, projectID)
	})

	dig := service.NewDigitalService()
	preview, err := dig.Preview(ctx, projectID, "app", []string{"已有应用"}, "", "", "test")
	if err != nil {
		t.Fatalf("名单预览失败: %v", err)
	}
	if _, _, err := dig.Commit(ctx, preview.Token, "tester"); err != nil {
		t.Fatalf("名单确认失败: %v", err)
	}

	res, err := dig.CollectCandidates(ctx, service.DigitalCollectInput{
		ProjectID:        projectID,
		Keyword:          "示例公司",
		ProviderOverride: &digitalFakeProvider{},
	})
	if err != nil {
		t.Fatalf("采集失败: %v", err)
	}
	if res.Entities != 1 || res.Found != 3 || res.Candidates != 2 || res.Imported != 1 {
		t.Fatalf("采集统计不符: %+v", res)
	}
	if len(res.Warnings) != 1 || !warningsContain(res.Warnings, "坏公司") {
		t.Fatalf("坏公司应产生 warning: %+v", res.Warnings)
	}

	items, total, err := dig.ListCandidates(ctx, repo.DigitalCandidateFilter{ProjectID: projectID, Status: "candidate"})
	if err != nil || total != 2 || len(items) != 2 {
		t.Fatalf("候选池不符: total=%d len=%d err=%v", total, len(items), err)
	}
	for _, c := range items {
		if c.Source != "fakedigital" || c.EntityName != "示例公司" {
			t.Fatalf("候选来源/归属企业不符: %+v", c)
		}
	}
}

func warningsContain(ss []string, sub string) bool {
	for _, s := range ss {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// 数字资产候选池：入池对账 -> 批量确认落名单 -> 撤销回退 -> 忽略终态 -> 重复入池状态保留。
func TestDigitalCandidatesLifecycle(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	code := fmt.Sprintf("digcand-%d", time.Now().UnixNano())
	var projectID int64
	if err := r.Pool().QueryRow(ctx,
		`INSERT INTO projects (code, name) VALUES ($1, $2) RETURNING id`, code, code).Scan(&projectID); err != nil {
		t.Fatalf("建测试项目失败: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = r.Pool().Exec(bg, `DELETE FROM import_batches WHERE project_id = $1`, projectID)
		_, _ = r.Pool().Exec(bg, `DELETE FROM projects WHERE id = $1`, projectID)
	})

	dig := service.NewDigitalService()

	// 先放一条既有名单，验证入池对账。
	preview, err := dig.Preview(ctx, projectID, "app", []string{"已有应用"}, "示例公司", "", "test")
	if err != nil {
		t.Fatalf("名单预览失败: %v", err)
	}
	if _, _, err := dig.Commit(ctx, preview.Token, "tester"); err != nil {
		t.Fatalf("名单确认失败: %v", err)
	}

	// 入池：一条撞名单（直接 imported），两条新候选。
	hits := []repo.DigitalCandidateInput{
		{Kind: "app", Name: "已有应用", Source: "fake", EntityName: "示例公司", Evidence: "详情页"},
		{Kind: "app", Name: "候选一", Source: "fake", EntityName: "示例公司"},
		{Kind: "miniapp", Name: "候选小程序", Source: "fake", EntityName: "示例公司"},
	}
	candidates, imported, err := dig.UpsertCandidates(ctx, projectID, hits)
	if err != nil {
		t.Fatalf("候选入池失败: %v", err)
	}
	if candidates != 2 || imported != 1 {
		t.Fatalf("入池计数不符: candidates=%d imported=%d", candidates, imported)
	}

	findByName := func(name string) *repo.DigitalCandidate {
		items, _, err := dig.ListCandidates(ctx, repo.DigitalCandidateFilter{ProjectID: projectID, Query: name})
		if err != nil {
			t.Fatalf("候选查询失败: %v", err)
		}
		for _, c := range items {
			if c.Name == name {
				return c
			}
		}
		return nil
	}

	if c := findByName("已有应用"); c == nil || c.Status != "imported" || c.BatchID != nil {
		t.Fatalf("撞名单的候选应直接 imported 且无批次: %+v", c)
	}

	// 忽略是终态：重复入池只刷新证据，不复活 rejected。
	rejectedOne := findByName("候选小程序")
	if rejectedOne == nil {
		t.Fatal("候选小程序应已入池")
	}
	if _, err := dig.RejectCandidates(ctx, []int64{rejectedOne.ID}); err != nil {
		t.Fatalf("忽略候选失败: %v", err)
	}
	if _, _, err := dig.UpsertCandidates(ctx, projectID, []repo.DigitalCandidateInput{
		{Kind: "miniapp", Name: "候选小程序", Source: "fake", Evidence: "二次采集"},
	}); err != nil {
		t.Fatalf("重复入池失败: %v", err)
	}
	if c := findByName("候选小程序"); c == nil || c.Status != "rejected" {
		t.Fatalf("rejected 不应被重复入池复活: %+v", c)
	}

	// 批量确认：落名单 + 生成回执 + 候选置 imported 记批次。
	confirmOne := findByName("候选一")
	if confirmOne == nil {
		t.Fatal("候选一应已入池")
	}
	batch, confirmed, err := dig.ConfirmCandidates(ctx, projectID, []int64{confirmOne.ID}, "tester")
	if err != nil {
		t.Fatalf("批量确认失败: %v", err)
	}
	if confirmed != 1 || batch == nil || batch.Status != "committed" {
		t.Fatalf("确认结果不符: confirmed=%d batch=%+v", confirmed, batch)
	}
	assets, total, err := dig.List(ctx, repo.DigitalFilter{ProjectID: projectID, Query: "候选一"})
	if err != nil || total != 1 || len(assets) != 1 || assets[0].Name != "候选一" {
		t.Fatalf("确认后名单不符: total=%d items=%v err=%v", total, assets, err)
	}
	if c := findByName("候选一"); c == nil || c.Status != "imported" || c.BatchID == nil || *c.BatchID != batch.ID {
		t.Fatalf("确认后候选状态不符: %+v", c)
	}

	// 已确认候选不能二次确认。
	if _, _, err := dig.ConfirmCandidates(ctx, projectID, []int64{confirmOne.ID}, "tester"); err == nil {
		t.Fatal("已确认候选不应可再次确认")
	}

	// 撤销回执：名单行被删的候选回退为待确认并清批次；撞名单的 imported 不动。
	if _, err := dig.Undo(ctx, batch.ID); err != nil {
		t.Fatalf("撤销回执失败: %v", err)
	}
	if _, total, err := dig.List(ctx, repo.DigitalFilter{ProjectID: projectID, Query: "候选一"}); err != nil || total != 0 {
		t.Fatalf("撤销后名单应已回滚: total=%d err=%v", total, err)
	}
	if c := findByName("候选一"); c == nil || c.Status != "candidate" || c.BatchID != nil {
		t.Fatalf("撤销后候选应回退为待确认: %+v", c)
	}
	if c := findByName("已有应用"); c == nil || c.Status != "imported" {
		t.Fatalf("撞名单的候选不应随撤销回退: %+v", c)
	}
}

// 数字资产巡航采集核心：一轮入池，二轮 diff 不重复入池。
func TestDigitalCruiseCycle(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	code := fmt.Sprintf("digcruise-%d", time.Now().UnixNano())
	var projectID int64
	if err := r.Pool().QueryRow(ctx,
		`INSERT INTO projects (code, name) VALUES ($1, $2) RETURNING id`, code, code).Scan(&projectID); err != nil {
		t.Fatalf("建测试项目失败: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = r.Pool().Exec(bg, `DELETE FROM import_batches WHERE project_id = $1`, projectID)
		_, _ = r.Pool().Exec(bg, `DELETE FROM projects WHERE id = $1`, projectID)
	})

	// 录入一条企业线索（巡航按项目企业线索遍历）。
	if _, err := r.Enterprises().Upsert(ctx, projectID, repo.EnterpriseInput{
		Name: "示例公司", Source: "test", Status: "unverified",
	}); err != nil {
		t.Fatalf("录入企业线索失败: %v", err)
	}

	first := service.RunDigitalCollectCycle(ctx, &digitalFakeProvider{}, projectID, 5, 50)
	if first.Err != nil {
		t.Fatalf("首轮采集失败: %v", first.Err)
	}
	if first.Entities != 1 || first.Checked != 1 || first.Found != 3 || first.Candidates != 3 || first.Imported != 0 {
		t.Fatalf("首轮统计不符: %+v", first)
	}

	second := service.RunDigitalCollectCycle(ctx, &digitalFakeProvider{}, projectID, 5, 50)
	if second.Err != nil {
		t.Fatalf("二轮采集失败: %v", second.Err)
	}
	if second.Found != 3 || second.Candidates != 0 || second.Imported != 0 {
		t.Fatalf("二轮应只刷新证据不重复入池: %+v", second)
	}
}
