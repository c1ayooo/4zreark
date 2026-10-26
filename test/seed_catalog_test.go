package test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
)

func TestSeedCatalogCapabilitiesAndDomainCounts(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	project, err := service.NewAssetService().CreateProject(ctx, repo.ProjectInput{
		Code: fmt.Sprintf("seedcat%d", time.Now().UnixNano()),
		Name: "seed catalog test",
	})
	if err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	t.Cleanup(func() {
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM projects WHERE id = $1`, project.ID)
	})

	if _, err := repo.NewAssetRepo().ImportRecords(ctx, project.ID, "test", []repo.RawRecord{
		{Host: "a.example", Port: 443, Protocol: "https", Value: "https://a.example"},
		{Host: "sub.a.example", Port: 443, Protocol: "https", Value: "https://sub.a.example"},
		{Host: "other.example", Port: 443, Protocol: "https", Value: "https://other.example"},
	}); err != nil {
		t.Fatalf("导入站点失败: %v", err)
	}

	seeds := r.Seeds()
	for _, value := range []string{"a.example", "b.example"} {
		if err := seeds.CreateSeed(ctx, &repo.Seed{
			ProjectID: project.ID, Kind: "domain", Value: value, Enabled: true,
		}); err != nil {
			t.Fatalf("创建种子 %s 失败: %v", value, err)
		}
	}

	svc := service.NewSeedCatalogService()
	caps := svc.Capabilities()
	if len(caps.Kinds) != 6 || caps.MaxExpandTargets != 5000 || caps.PreviewSample != 200 {
		t.Fatalf("能力声明不符: %+v", caps)
	}
	byKind := map[string]service.SeedKindCapability{}
	for _, k := range caps.Kinds {
		byKind[k.Kind] = k
	}
	if !byKind["domain"].Static || byKind["app"].Supported {
		t.Fatalf("domain/app 能力标记不符: %+v", byKind)
	}

	counts, err := svc.DomainCounts(ctx, project.ID)
	if err != nil {
		t.Fatalf("domain counts 失败: %v", err)
	}
	got := map[string]int64{}
	for _, c := range counts {
		got[c.Value] = c.SiteCount
	}
	if got["a.example"] != 2 || got["b.example"] != 0 {
		t.Fatalf("覆盖计数不符（a 应含子域 2，b 应 0）: %+v", got)
	}

	actor := fmt.Sprintf("seedcat-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM operation_logs WHERE username = $1`, actor)
	})
	batch, err := svc.CreateBatch(ctx, service.SeedBatchRequest{
		ProjectID: project.ID,
		Items: []service.SeedBatchItem{
			{Kind: "domain", Value: "batch.example", IntervalHours: 12},
			{Kind: "domain", Value: "a.example"},
			{Kind: "bogus", Value: "x.example"},
		},
	}, actor, "127.0.0.1")
	if err != nil {
		t.Fatalf("批量建种子失败: %v", err)
	}
	if batch.Requested != 3 || batch.Created != 1 || batch.Duplicate != 1 || batch.Invalid != 1 {
		t.Fatalf("批量计数不符: %+v", batch)
	}
	var createdPlanID int64
	for _, it := range batch.Items {
		if it.Value == "batch.example" {
			if it.Status != "created" || it.SeedID == 0 || it.PlanID == 0 {
				t.Fatalf("新种子应同时建计划: %+v", it)
			}
			createdPlanID = it.PlanID
		}
		if it.Value == "a.example" && it.Status != "duplicate" {
			t.Fatalf("重复种子状态不符: %+v", it)
		}
		if it.Kind == "bogus" && it.Status != "invalid" {
			t.Fatalf("非法 kind 状态不符: %+v", it)
		}
	}
	if p, err := r.Seeds().GetPlan(ctx, createdPlanID); err != nil || p.IntervalHours != 12 {
		t.Fatalf("批量创建的计划不符: %+v err=%v", p, err)
	}
}
