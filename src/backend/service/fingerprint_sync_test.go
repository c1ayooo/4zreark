package service

import (
	"strings"
	"testing"

	reconfp "github.com/c1ayooo/4zreark/internal/recon/fingerprint"
)

func TestGroupEmbeddedRulesMergesDuplicates(t *testing.T) {
	raw := []reconfp.Rule{
		{Name: "Acme", Category: "cms", Expression: `body="acme-one"`, Enabled: true, Source: reconfp.SourceDddd},
		{Name: "Acme", Category: "cms", Expression: `body="acme-two"`, Enabled: true, Source: reconfp.SourceDddd},
		{Name: "SeedApp", Category: "seed", Expression: `title="seed"`, Enabled: true, Source: reconfp.SourceCustom},
		{Name: "Disabled", Expression: `body="x"`, Enabled: false, Source: reconfp.SourceDddd},
		{Name: "", Expression: `body="x"`, Enabled: true, Source: reconfp.SourceDddd},
	}

	groups := groupEmbeddedRules(raw)
	if len(groups) != 2 {
		t.Fatalf("应分成 dddd/seed 两组，实际 %d 组: %+v", len(groups), groups)
	}

	var dddd, seed *fpSyncGroup
	for i := range groups {
		switch groups[i].source {
		case "dddd":
			dddd = &groups[i]
		case "seed":
			seed = &groups[i]
		}
	}
	if dddd == nil || seed == nil {
		t.Fatalf("来源分组缺失: %+v", groups)
	}

	if len(dddd.rules) != 1 || dddd.merged != 1 {
		t.Fatalf("同名规则应合并为 1 条且记 merged=1，实际 rules=%d merged=%d", len(dddd.rules), dddd.merged)
	}
	if !strings.Contains(dddd.rules[0].Expression, `body="acme-one"`) ||
		!strings.Contains(dddd.rules[0].Expression, `body="acme-two"`) {
		t.Fatalf("合并表达式不符: %q", dddd.rules[0].Expression)
	}
	if len(dddd.rules[0].RuleHash) != 64 {
		t.Fatalf("rule_hash 应为 64 位十六进制: %q", dddd.rules[0].RuleHash)
	}
	if seed.skipped != 0 || len(seed.rules) != 1 || seed.rules[0].Name != "SeedApp" {
		t.Fatalf("种子分组不符: %+v", seed)
	}
	if dddd.skipped != 1 {
		t.Fatalf("空名规则应计入 skipped，实际 %d", dddd.skipped)
	}
	if dddd.contentHash == "" || dddd.contentHash == seed.contentHash {
		t.Fatalf("两组 content_hash 应为非空且不同")
	}
}
