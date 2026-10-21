package test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/repo"
)

// 企业身份线索：写入 / 查询 / 批量导入 / 与数字资产名单归属对齐。
func TestEnterpriseEntities(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	code := fmt.Sprintf("ent-%d", time.Now().UnixNano())
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

	ent := r.Enterprises()
	name := "示例企业-" + code

	// 先放一条数字资产，company 与后续企业名一致。
	dg := r.Digital()
	if _, _, err := dg.InsertBatch(ctx, projectID, "digital", []repo.DigitalAssetInput{
		{Kind: "app", Name: "示例应用", Company: name, Source: "test"},
	}, nil, "tester"); err != nil {
		t.Fatalf("准备数字资产失败: %v", err)
	}

	saved, err := ent.Upsert(ctx, projectID, repo.EnterpriseInput{
		Name: name, LegalPerson: "张三", ICPNumbers: []string{"京ICP备12345678号"},
		Domains: []repo.EnterpriseDomain{{Domain: "example.test", ICP: "京ICP备12345678号"}},
		Source:  "manual", Status: "verified", Notes: "测试",
	})
	if err != nil {
		t.Fatalf("写入企业线索失败: %v", err)
	}
	if saved.DigitalCount != 1 {
		t.Fatalf("APP 归属对齐计数应为 1，实际 %d", saved.DigitalCount)
	}

	items, total, err := ent.List(ctx, repo.EnterpriseFilter{ProjectID: projectID, Query: name})
	if err != nil || total != 1 || len(items) != 1 {
		t.Fatalf("查询不符: total=%d len=%d err=%v", total, len(items), err)
	}
	if items[0].ICPNumbers[0] != "京ICP备12345678号" || len(items[0].Domains) != 1 {
		t.Fatalf("JSON 字段回读不符: %+v", items[0])
	}

	aligned, err := ent.AlignedDigitalAssets(ctx, projectID, name)
	if err != nil || len(aligned) != 1 || aligned[0].Name != "示例应用" {
		t.Fatalf("对齐名单不符: %+v err=%v", aligned, err)
	}

	inserted, updated, err := ent.UpsertMany(ctx, projectID, []repo.EnterpriseInput{
		{Name: name, LegalPerson: "李四", Source: "import"},
		{Name: "第二家企业-" + code, Source: "import"},
	}, "import")
	if err != nil {
		t.Fatalf("批量导入失败: %v", err)
	}
	if inserted != 1 || updated != 1 {
		t.Fatalf("批量导入计数不符: inserted=%d updated=%d", inserted, updated)
	}
	got, err := ent.Get(ctx, saved.ID)
	if err != nil || got.LegalPerson != "李四" {
		t.Fatalf("更新未生效: %+v err=%v", got, err)
	}

	ok, err := ent.Delete(ctx, saved.ID)
	if err != nil || !ok {
		t.Fatalf("删除失败: ok=%v err=%v", ok, err)
	}
	if _, err := ent.Get(ctx, saved.ID); err == nil {
		t.Fatal("删除后仍能查到")
	}
}
