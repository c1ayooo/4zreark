package permute

import (
	"strings"
	"testing"
)

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// 对仗替换：已知 api.dev.example.com 应派生 api.prod（及 prod.api 等 token 形态）。
func TestGenerateSemanticSwaps(t *testing.T) {
	known := []string{"api.dev.example.com", "www.example.com"}
	got := Generate(known, "example.com", 0)
	joined := strings.Join(got, "\n")

	for _, want := range []string{
		"api.prod.example.com", // dev→prod 对仗替换
		"api.test.example.com", // dev→test 对仗替换
		"dev.example.com",      // 组合阶段：已知 token 独立子域
	} {
		if !contains(got, want) {
			t.Fatalf("候选应包含 %s\n实际：%s", want, joined)
		}
	}
	// 已知子域本身不应出现在候选里。
	if contains(got, "api.dev.example.com") {
		t.Fatal("候选不应包含已知子域")
	}
}

// 双向替换：观测到 prod 侧也要派生 dev 侧。
func TestGenerateSwapsBothWays(t *testing.T) {
	got := Generate([]string{"api.prod.example.com"}, "example.com", 0)
	if !contains(got, "api.dev.example.com") {
		t.Fatalf("prod→dev 的反向替换缺失：%v", got)
	}
}

// 对仗替换优先于组合阶段消费预算：预算极小时也应先产出对仗候选。
func TestGenerateSwapBudgetPriority(t *testing.T) {
	known := []string{"api.dev.example.com"}
	// 预算 1：唯一候选应是对仗产物而不是组合产物。
	got := Generate(known, "example.com", 1)
	if len(got) != 1 {
		t.Fatalf("预算 1 应只产出 1 个候选，实际 %v", got)
	}
	if !strings.Contains(got[0], "prod") && !strings.Contains(got[0], "test") {
		t.Fatalf("预算紧张时应优先产出对仗候选，实际 %v", got)
	}
}

// 预算硬上限仍然生效：对仗 + 组合的总量不超过 maxCandidates。
func TestGenerateBudgetCap(t *testing.T) {
	known := []string{
		"api.dev.example.com", "api.test.example.com", "db.prod.example.com",
		"git.gitlab.example.com", "mail.smtp.example.com", "img.static.example.com",
	}
	got := Generate(known, "example.com", 50)
	if len(got) > 50 {
		t.Fatalf("候选数 %d 超过预算 50", len(got))
	}
	// 去重：结果内无重复。
	seen := map[string]bool{}
	for _, name := range got {
		if seen[name] {
			t.Fatalf("候选重复: %s", name)
		}
		seen[name] = true
	}
}

// 不含可替换词的已知子域不影响既有组合行为（回归保护）。
func TestGenerateComboUnchanged(t *testing.T) {
	got := Generate([]string{"dashboard.example.com"}, "example.com", 0)
	if !contains(got, "dashboard-dev.example.com") || !contains(got, "dev-dashboard.example.com") {
		t.Fatalf("组合派生行为回归：%v", got)
	}
}
