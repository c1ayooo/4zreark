package test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/repo"
)

// 指纹库页面依赖的分页/筛选与 expression 规则读写。
func TestFingerprintRulePage(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	fp := r.Fingerprints()

	// dddd 规则只有 expression，也必须能在指纹库列表里分页看到。
	rules, total, err := fp.ListRulesPage(ctx, repo.FpRuleFilter{
		Source: "dddd", Page: 1, PageSize: 5,
	})
	if err != nil {
		t.Fatalf("分页查询失败: %v", err)
	}
	if total < 1000 || len(rules) != 5 {
		t.Fatalf("dddd 分页不符: total=%d len=%d", total, len(rules))
	}
	if rules[0].Expression == "" {
		t.Fatalf("列表应带出 expression: %+v", rules[0])
	}

	name := fmt.Sprintf("zz-fp-admin-%d", time.Now().UnixNano())
	enabled := false
	if err := fp.UpsertRule(ctx, &repo.FpRule{
		Name: name, Category: "smoke", Enabled: enabled, DSLVersion: 1,
		Expression: `body="smoke-word"`, Source: "custom",
	}); err != nil {
		t.Fatalf("写入 expression 规则失败: %v", err)
	}
	t.Cleanup(func() { _ = fp.DeleteRule(context.Background(), name) })

	got, err := fp.GetRuleByName(ctx, name)
	if err != nil {
		t.Fatalf("读取规则失败: %v", err)
	}
	if got.Expression != `body="smoke-word"` || got.Source != "custom" || got.Enabled {
		t.Fatalf("规则字段不符: %+v", got)
	}

	if err := fp.SetRuleEnabled(ctx, name, true); err != nil {
		t.Fatalf("启停失败: %v", err)
	}
	rules, total, err = fp.ListRulesPage(ctx, repo.FpRuleFilter{
		Keyword: name, Page: 1, PageSize: 10,
	})
	if err != nil || total != 1 || len(rules) != 1 || !rules[0].Enabled {
		t.Fatalf("名称过滤/启用态不符: total=%d len=%d err=%v", total, len(rules), err)
	}
}
