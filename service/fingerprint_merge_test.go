package service

import (
	"strings"
	"testing"

	reconfp "github.com/c1ayooo/4zreark/internal/recon/fingerprint"
)

// rule_hash 对名字做了小写归一，大小写变体必须在合并阶段就归成一条，
// 否则插入时会撞 fingerprint_rule_hash_uq（真实上游 wappalyzergo 出现过）。
func TestMergeUpstreamRulesCaseInsensitive(t *testing.T) {
	rules, merged, skipped := mergeUpstreamRules([]reconfp.Rule{
		{Name: "FastSpring", Category: "a", Expression: `body="one"`},
		{Name: "fastspring", Category: "b", Expression: `body="two"`},
		{Name: "", Expression: `body="skip"`},
	})
	if len(rules) != 1 {
		t.Fatalf("大小写同名规则应合并为 1 条，实际 %d", len(rules))
	}
	if merged != 1 || skipped != 1 {
		t.Fatalf("merged/skipped 不符: merged=%d skipped=%d", merged, skipped)
	}
	if rules[0].Name != "FastSpring" || !strings.Contains(rules[0].Expression, `body="one"`) ||
		!strings.Contains(rules[0].Expression, `body="two"`) {
		t.Fatalf("合并结果不符: %+v", rules[0])
	}
	if rules[0].RuleHash == "" {
		t.Fatal("合并后应重算 rule_hash")
	}
}

func TestGroupEmbeddedRulesCaseInsensitive(t *testing.T) {
	groups := groupEmbeddedRules([]reconfp.Rule{
		{Name: "SameApp", Expression: `body="a"`, Enabled: true, Source: reconfp.SourceDddd},
		{Name: "sameapp", Expression: `body="b"`, Enabled: true, Source: reconfp.SourceDddd},
	})
	if len(groups) != 1 || len(groups[0].rules) != 1 {
		t.Fatalf("内置规则大小写同名应合并为 1 条: %+v", groups)
	}
	if groups[0].merged != 1 {
		t.Fatalf("merged 应为 1，实际 %d", groups[0].merged)
	}
}
