package test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/oid"
	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
)

// 命中表有两个写入方：扫描器引擎按规则名写（ImportRecords），探测复核按规则 ID 写
// （ApplyToSite）。此前探测侧的 PruneHits 会删掉「本站点本次没命中」的所有行，
// 于是探活复核一跑就把扫描阶段写入的命中清零——任务日志说命中 N 行、库里 0 行，
// 且无任何报错。这里锁住三点：
//  1. 探测侧清理不得动扫描侧写的命中；
//  2. 探测侧自己写的命中仍然会被清理（老化能力不能丢）；
//  3. 规则库没加载出来（universe 为空）时一条都不删。
func TestPruneHitsScope(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	ruleName := "fpprune-" + suffix

	project, err := service.NewAssetService().CreateProject(ctx, repo.ProjectInput{
		Code: "fpprune" + suffix, Name: "prune scope test",
	})
	if err != nil {
		t.Fatalf("创建测试项目失败: %v", err)
	}
	t.Cleanup(func() {
		_ = r.Fingerprints().DeleteRule(context.Background(), ruleName)
		_, _ = r.Pool().Exec(context.Background(),
			`DELETE FROM fingerprint_hits WHERE site_id IN (SELECT id FROM sites WHERE project_id = $1)`, project.ID)
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM sites WHERE project_id = $1`, project.ID)
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM projects WHERE id = $1`, project.ID)
		service.NewFingerprintService().Invalidate()
	})

	ruleID := oid.NewObjectID().Hex()
	if err := r.Fingerprints().UpsertRule(ctx, &repo.FpRule{
		ID: ruleID, Name: ruleName, Enabled: true, DSLVersion: 2,
		Condition: &repo.Condition{Type: "title", Op: "contains", Value: "KeepMe"},
		Source:    "test",
	}); err != nil {
		t.Fatalf("写入规则失败: %v", err)
	}
	svc := service.NewFingerprintService()
	svc.Invalidate()

	host := "fpprune-" + suffix + ".example.com"
	// 扫描侧：按规则名写命中（evidence.source 是采集来源，不是 dsl_probe）。
	if _, err := repo.NewAssetRepo().ImportRecords(ctx, project.ID, "scan", []repo.RawRecord{
		{Host: host, Port: 443, Protocol: "https", StatusCode: 200, Tech: []string{ruleName}},
	}); err != nil {
		t.Fatalf("导入站点失败: %v", err)
	}
	siteID, err := repo.NewAssetRepo().SiteIDByHost(ctx, project.ID, host)
	if err != nil {
		t.Fatal(err)
	}

	countHits := func() int {
		var n int
		if err := r.Pool().QueryRow(ctx,
			`SELECT count(*) FROM fingerprint_hits WHERE site_id = $1`, siteID).Scan(&n); err != nil {
			t.Fatalf("统计命中失败: %v", err)
		}
		return n
	}
	if n := countHits(); n != 1 {
		t.Fatalf("扫描侧命中应为 1 行，实际 %d 行", n)
	}

	// 探测侧复核：标题不含 KeepMe，本轮没命中任何规则。
	if _, _, err := svc.ApplyToSite(ctx, siteID, service.ResponseSnapshot{
		Title: "unrelated", StatusCode: 200,
	}, nil); err != nil {
		t.Fatalf("ApplyToSite 失败: %v", err)
	}
	if n := countHits(); n != 1 {
		t.Fatalf("探测侧清理误删了扫描侧命中：期望 1 行，实际 %d 行", n)
	}

	// 探测侧命中：同一规则这轮命中了，应新增一行（与扫描侧同行 upsert 为 dsl_probe）。
	if _, _, err := svc.ApplyToSite(ctx, siteID, service.ResponseSnapshot{
		Title: "KeepMe please", StatusCode: 200,
	}, nil); err != nil {
		t.Fatalf("ApplyToSite 失败: %v", err)
	}
	if n := countHits(); n != 1 {
		t.Fatalf("命中行仍应为 1 行（同站点同规则唯一），实际 %d 行", n)
	}
	var src string
	if err := r.Pool().QueryRow(ctx,
		`SELECT coalesce(evidence->>'source','') FROM fingerprint_hits WHERE site_id = $1`, siteID).Scan(&src); err != nil {
		t.Fatalf("读取命中来源失败: %v", err)
	}
	if src != repo.HitSourceProbe {
		t.Fatalf("探测侧写入应标记 source=%s，实际 %q", repo.HitSourceProbe, src)
	}

	// 再来一轮不命中：此时该行属于探测侧，允许被清理（老化能力保留）。
	if _, _, err := svc.ApplyToSite(ctx, siteID, service.ResponseSnapshot{
		Title: "unrelated again", StatusCode: 200,
	}, nil); err != nil {
		t.Fatalf("ApplyToSite 失败: %v", err)
	}
	if n := countHits(); n != 0 {
		t.Fatalf("探测侧自己写的命中应被清理，实际仍剩 %d 行", n)
	}
}
