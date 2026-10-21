package test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
)

// G4 验收：两段式导入（含过期）、字典词表与引用保护、每日预算切片。
func TestG4ImportDictionaryBudget(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	code := fmt.Sprintf("g4-%d", time.Now().UnixNano())
	var projectID int64
	if err := r.Pool().QueryRow(ctx,
		`INSERT INTO projects (code, name) VALUES ($1, $2) RETURNING id`, code, code).Scan(&projectID); err != nil {
		t.Fatalf("建测试项目失败: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = r.Pool().Exec(bg, `DELETE FROM projects WHERE id = $1`, projectID)
	})

	assets := service.NewAssetService()
	base := code + ".test"

	// 1) 两段式导入：预览 -> 确认
	preview, err := assets.PreviewImport(ctx, projectID, "g4-test", []repo.RawRecord{
		{Host: "a." + base, Protocol: "https", StatusCode: 200, Title: "A"},
		{Host: "b." + base, Protocol: "https", StatusCode: 200, Title: "B"},
	})
	if err != nil {
		t.Fatalf("预览失败: %v", err)
	}
	if preview.Unique != 2 {
		t.Fatalf("预览去重后应为 2，实际 %d", preview.Unique)
	}
	res, err := assets.CommitImport(ctx, preview.Token)
	if err != nil {
		t.Fatalf("确认导入失败: %v", err)
	}
	if res.NewSites != 2 {
		t.Fatalf("应新建 2 个站点，实际 %d", res.NewSites)
	}
	// 已消费 token 不能再次提交
	if _, err := assets.CommitImport(ctx, preview.Token); err == nil {
		t.Fatal("预览 token 应一次性消费")
	}
	// 不存在的 token
	if _, err := assets.CommitImport(ctx, "not-a-token"); err == nil {
		t.Fatal("无效 token 应被拒绝")
	}

	// 2) 字典：预览 -> 导入 -> 条目 -> 引用保护
	plugin := service.NewPluginService()
	dictName := "g4-dict-" + code
	dp, err := plugin.PreviewDictionary(dictName, "subdomain", "www\napi\nwww\n")
	if err != nil {
		t.Fatalf("字典预览失败: %v", err)
	}
	dict, inserted, err := plugin.ImportDictionary(ctx, dp.Token)
	if err != nil {
		t.Fatalf("字典导入失败: %v", err)
	}
	if inserted != 2 || dict.LineCount != 2 {
		t.Fatalf("字典条目数不符: inserted=%d line_count=%d", inserted, dict.LineCount)
	}
	entries, total, err := plugin.ListDictionaryEntries(ctx, dict.ID.Hex(), 0, 1, 50)
	if err != nil || total != 2 || len(entries) != 2 {
		t.Fatalf("读取字典条目失败: total=%d entries=%v err=%v", total, entries, err)
	}

	seeds := r.Seeds()
	seed := &repo.Seed{ProjectID: projectID, Kind: "dict", Value: dict.ID.Hex(), Enabled: true}
	if err := seeds.CreateSeed(ctx, seed); err != nil {
		t.Fatalf("建字典种子失败: %v", err)
	}
	if err := plugin.DeleteDictionary(dict.ID.Hex()); err == nil || !strings.Contains(err.Error(), "引用") {
		t.Fatalf("被引用的字典应拒绝删除，实际 err=%v", err)
	}
	if err := seeds.DeleteSeed(ctx, seed.ID); err != nil {
		t.Fatalf("删种子失败: %v", err)
	}
	if err := plugin.DeleteDictionary(dict.ID.Hex()); err != nil {
		t.Fatalf("解除引用后应可删除字典: %v", err)
	}
	var entryLeft int
	if err := r.Pool().QueryRow(ctx, `SELECT count(*) FROM dict_entries WHERE dict_id = $1`,
		dict.ID.Hex()).Scan(&entryLeft); err != nil {
		t.Fatal(err)
	}
	if entryLeft != 0 {
		t.Fatalf("删字典应级联清条目，剩余 %d", entryLeft)
	}

	// 3) 每日预算：4 个目标、daily_targets=2 -> 只展开 2 条
	if _, err := assets.ImportRecords(ctx, projectID, "g4-budget", []repo.RawRecord{
		{Host: "a." + base, Port: 80, Protocol: "http", StatusCode: 200},
		{Host: "b." + base, Port: 80, Protocol: "http", StatusCode: 200},
		{Host: "c." + base, Port: 80, Protocol: "http", StatusCode: 200},
		{Host: "d." + base, Port: 80, Protocol: "http", StatusCode: 200},
	}); err != nil {
		t.Fatalf("预算测试导入失败: %v", err)
	}
	domainSeed := &repo.Seed{ProjectID: projectID, Kind: "domain", Value: base, Enabled: true}
	if err := seeds.CreateSeed(ctx, domainSeed); err != nil {
		t.Fatalf("建域名种子失败: %v", err)
	}
	plan := &repo.Plan{SeedID: domainSeed.ID, IntervalHours: 24, Enabled: true,
		Budget: map[string]any{"daily_targets": float64(2)}}
	if err := seeds.CreatePlan(ctx, plan); err != nil {
		t.Fatalf("建计划失败: %v", err)
	}

	run, created, err := service.NewCycleService().TriggerPlan(ctx, plan.ID)
	if err != nil || !created {
		t.Fatalf("触发计划失败: created=%v err=%v", created, err)
	}
	targets, err := r.Runs().ListTargets(ctx, run.ID, "", 100)
	if err != nil {
		t.Fatalf("读取目标失败: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("daily_targets=2 应只展开 2 条，实际 %d", len(targets))
	}
}
