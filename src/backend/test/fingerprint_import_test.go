package test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
)

// 指纹导入：三类计数、来源隔离、force 覆盖、token 一次性、批量启停。
func TestFingerprintImportAndBulk(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	prefix := fmt.Sprintf("t-imp-%d", time.Now().UnixNano())
	nameNew := prefix + "-new"
	nameExisting := prefix + "-existing"
	nameBad := prefix + "-bad"
	nameDddd := prefix + "-dddd"
	nameYaml := prefix + "-yaml"
	nameLegacy := prefix + "-legacy"
	allNames := []string{nameNew, nameExisting, nameBad, nameDddd, nameYaml, nameLegacy}
	actor := prefix + "-actor"

	fp := r.Fingerprints()
	t.Cleanup(func() {
		for _, name := range allNames {
			_ = fp.DeleteRule(context.Background(), name)
		}
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM operation_logs WHERE username = $1`, actor)
	})

	mustUpsert := func(rule *repo.FpRule) {
		t.Helper()
		if err := fp.UpsertRule(ctx, rule); err != nil {
			t.Fatalf("准备规则 %s 失败: %v", rule.Name, err)
		}
	}
	mustUpsert(&repo.FpRule{
		Name: nameExisting, Category: "old", Enabled: true, DSLVersion: 2, Source: "custom",
		Condition: &repo.Condition{Type: "body", Op: "contains", Value: "old"},
	})
	mustUpsert(&repo.FpRule{
		Name: nameDddd, Category: "dddd-original", Enabled: true, DSLVersion: 2, Source: "dddd",
		Condition: &repo.Condition{Type: "body", Op: "contains", Value: "dddd"},
	})

	svc := service.NewFingerprintImportService()
	preview, err := svc.Preview(ctx, service.FpImportRequest{
		Source: "custom",
		Rules: []service.FpImportRuleInput{
			{Name: nameNew, Category: "new", Condition: &repo.Condition{Type: "title", Op: "contains", Value: "foo"}},
			{Name: nameExisting, Category: "updated", Condition: &repo.Condition{Type: "title", Op: "contains", Value: "bar"}},
			{Name: nameBad},
			{Name: nameDddd, Category: "hijack", Condition: &repo.Condition{Type: "title", Op: "contains", Value: "baz"}},
		},
	})
	if err != nil {
		t.Fatalf("导入预览失败: %v", err)
	}
	if preview.Total != 4 || preview.Importable != 1 || preview.Conflicts != 2 || preview.Invalid != 1 {
		t.Fatalf("三类计数不符: %+v", preview)
	}
	status := map[string]service.FpImportItem{}
	for _, item := range preview.Items {
		status[item.Name] = item
	}
	if status[nameNew].Status != "importable" {
		t.Fatalf("新规则应可导入: %+v", status[nameNew])
	}
	if status[nameExisting].Status != "conflict" || !status[nameExisting].WillOverwrite {
		t.Fatalf("同来源同名规则应可覆盖: %+v", status[nameExisting])
	}
	if status[nameDddd].Status != "conflict" || status[nameDddd].WillOverwrite {
		t.Fatalf("跨来源同名规则默认应跳过: %+v", status[nameDddd])
	}
	if status[nameBad].Status != "invalid" {
		t.Fatalf("缺条件树的规则应无效: %+v", status[nameBad])
	}

	commit, err := svc.Commit(ctx, preview.Token, actor, "127.0.0.1")
	if err != nil {
		t.Fatalf("确认导入失败: %v", err)
	}
	if commit.Imported != 2 || commit.Source != "custom" {
		t.Fatalf("导入回执不符: %+v", commit)
	}
	if _, err := svc.Commit(ctx, preview.Token, actor, "127.0.0.1"); !errors.Is(err, service.ErrFpImportInput) {
		t.Fatalf("token 应为一次性，第二次实际 %v", err)
	}

	got, err := fp.GetRuleByName(ctx, nameExisting)
	if err != nil || got.Category != "updated" || got.Condition == nil || got.Condition.Value != "bar" {
		t.Fatalf("同名规则应被覆盖: %+v err=%v", got, err)
	}
	got, err = fp.GetRuleByName(ctx, nameDddd)
	if err != nil || got.Source != "dddd" || got.Category != "dddd-original" {
		t.Fatalf("跨来源规则不应被普通导入改动: %+v err=%v", got, err)
	}

	// 跨来源 force：显式允许后可以接管
	forcePreview, err := svc.Preview(ctx, service.FpImportRequest{
		Source: "custom", Force: true,
		Rules: []service.FpImportRuleInput{
			{Name: nameDddd, Category: "hijack", Condition: &repo.Condition{Type: "title", Op: "contains", Value: "baz"}},
		},
	})
	if err != nil || forcePreview.Conflicts != 1 || !forcePreview.Items[0].WillOverwrite {
		t.Fatalf("force 预览不符: %+v err=%v", forcePreview, err)
	}
	if _, err := svc.Commit(ctx, forcePreview.Token, actor, "127.0.0.1"); err != nil {
		t.Fatalf("force 导入失败: %v", err)
	}
	got, err = fp.GetRuleByName(ctx, nameDddd)
	if err != nil || got.Source != "custom" || got.Category != "hijack" {
		t.Fatalf("force 后规则应被接管: %+v err=%v", got, err)
	}

	// YAML 内容解析
	yamlPreview, err := svc.Preview(ctx, service.FpImportRequest{
		Source: "custom", Format: "yaml",
		Content: fmt.Sprintf("- name: %s\n  category: yaml\n  condition_tree:\n    type: body\n    op: contains\n    value: yaml\n", nameYaml),
	})
	if err != nil || yamlPreview.Importable != 1 {
		t.Fatalf("YAML 预览失败: %+v err=%v", yamlPreview, err)
	}
	if _, err := svc.Commit(ctx, yamlPreview.Token, actor, "127.0.0.1"); err != nil {
		t.Fatalf("YAML 导入失败: %v", err)
	}
	if got, err := fp.GetRuleByName(ctx, nameYaml); err != nil || got.Condition == nil || got.Condition.Value != "yaml" {
		t.Fatalf("YAML 规则落库不符: %+v err=%v", got, err)
	}

	// 旧扁平 rules 仍可导入
	legacyPreview, err := svc.Preview(ctx, service.FpImportRequest{
		Source: "legacy",
		Rules: []service.FpImportRuleInput{{
			Name:  nameLegacy,
			Rules: []repo.LegacyMatch{{Type: "body", Pattern: "legacy", Operator: "contains"}},
		}},
	})
	if err != nil || legacyPreview.Importable != 1 {
		t.Fatalf("旧规则预览失败: %+v err=%v", legacyPreview, err)
	}
	if _, err := svc.Commit(ctx, legacyPreview.Token, actor, "127.0.0.1"); err != nil {
		t.Fatalf("旧规则导入失败: %v", err)
	}
	if got, err := fp.GetRuleByName(ctx, nameLegacy); err != nil || got.DSLVersion != 1 || len(got.Legacy) != 1 {
		t.Fatalf("旧规则落库不符: %+v err=%v", got, err)
	}

	// 批量启停：不存在名字计入 skipped
	bulk, err := svc.BulkToggle(ctx, []string{nameNew, nameYaml, prefix + "-missing"}, false, actor, "127.0.0.1")
	if err != nil {
		t.Fatalf("批量停用失败: %v", err)
	}
	if bulk.Requested != 3 || bulk.Updated != 2 || bulk.Skipped != 1 || bulk.Enabled {
		t.Fatalf("批量停用回执不符: %+v", bulk)
	}
	if got, _ := fp.GetRuleByName(ctx, nameNew); got.Enabled {
		t.Fatal("nameNew 应已停用")
	}
	if _, err := svc.BulkToggle(ctx, []string{nameNew}, true, actor, "127.0.0.1"); err != nil {
		t.Fatalf("批量启用失败: %v", err)
	}
	if got, _ := fp.GetRuleByName(ctx, nameNew); !got.Enabled {
		t.Fatal("nameNew 应已启用")
	}

	var logs int
	if err := r.Pool().QueryRow(ctx,
		`SELECT count(*) FROM operation_logs WHERE username = $1 AND action IN ('fingerprint_import','fingerprint_bulk_toggle')`,
		actor).Scan(&logs); err != nil {
		t.Fatal(err)
	}
	if logs < 4 {
		t.Fatalf("导入与批量启停应落审计，实际 %d 条", logs)
	}
}
