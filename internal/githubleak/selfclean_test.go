package githubleak

import (
	"context"
	"testing"

	"github.com/c1ayooo/4zreark/internal/lz"
)

// selfclean_test.go — R7-1 规则自净（FP 占比超阈自动停用 + 一次性通知）
// 与 rule 维度静默的回归（docs/GitHub敏感信息监控改进建议.md R7）。

func TestValidSuppressionTypeAcceptsRule(t *testing.T) {
	for _, ok := range []string{SuppressionRepo, SuppressionOrg, SuppressionPathGlob, SuppressionFingerprintPrefix, SuppressionRule} {
		if !validSuppressionType(ok) {
			t.Fatalf("type %q should be valid", ok)
		}
	}
	if validSuppressionType("everything") {
		t.Fatal("unknown type should be invalid")
	}
}

func TestCompileSuppressionsRuleDimension(t *testing.T) {
	set, skipped := compileSuppressions([]Suppression{
		{PatternType: SuppressionRule, Pattern: "Noisy-Rule", Note: "自净停用"},
		{PatternType: SuppressionRepo, Pattern: "owner/repo"},
	})
	if skipped != 0 {
		t.Fatalf("skipped = %d, want 0", skipped)
	}
	if !set.suppressRule("noisy-rule") {
		t.Fatal("rule suppression did not match (case-insensitive expected)")
	}
	if set.suppressRule("other-rule") {
		t.Fatal("unrelated rule matched")
	}
	if !set.suppressItem("owner/repo", "any.py") {
		t.Fatal("repo suppression lost after adding rule dimension")
	}
	var nilSet *suppressionSet
	if nilSet.suppressRule("x") {
		t.Fatal("nil set should never match")
	}
}

// selfCleanStore 复用 serviceTestPersistence（满足 persistence），叠加
// 精确率统计与静默写入记录。
type selfCleanStore struct {
	serviceTestPersistence
	stats    []RulePrecision
	added    []string
	addCalls int
	firstAdd bool
}

func (s *selfCleanStore) RulePrecisionStats(context.Context) ([]RulePrecision, error) {
	return s.stats, nil
}

func (s *selfCleanStore) AddSuppression(_ context.Context, patternType, pattern, _, _ string) (bool, error) {
	s.addCalls++
	// firstAdd 模拟 ON CONFLICT 幂等：仅首次真正新增，其后返回 false。
	if s.firstAdd {
		s.firstAdd = false
	}
	s.added = append(s.added, patternType+":"+pattern)
	return len(s.added) == 1, nil
}

func TestAutoDisableNoisyRules(t *testing.T) {
	store := &selfCleanStore{stats: []RulePrecision{
		{RuleName: "noisy-rule", Total: 10, Confirmed: 1, FalsePositive: 9},
		{RuleName: "healthy-rule", Total: 10, Confirmed: 8, FalsePositive: 2},
		{RuleName: "off-rule", Total: 20, FalsePositive: 20},
		{RuleName: "low-sample-rule", Total: 5, FalsePositive: 5},
	}, firstAdd: true}
	settings := serviceSettings(true)
	settings.Keywords = nil
	settings.Rules = []Rule{
		{Enabled: true, Name: "noisy-rule", Keywords: []string{"alpha"}},
		{Enabled: true, Name: "healthy-rule", Keywords: []string{"beta"}},
		{Enabled: false, Name: "off-rule", Keywords: []string{"gamma"}},
	}
	service, err := newService(store, settings, &quotaProbingProvider{}, serviceTestDetector{}, lz.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	var events []Event
	service.notify = func(e Event) { events = append(events, e) }

	service.autoDisableNoisyRules(context.Background())

	if len(store.added) != 1 || store.added[0] != "rule:noisy-rule" {
		t.Fatalf("suppressions added = %v, want only rule:noisy-rule", store.added)
	}
	if len(events) != 1 || events[0].Kind != KindGithubLeakRuleDisabled {
		t.Fatalf("events = %+v, want one rule-disabled notification", events)
	}
}

func TestAutoDisableNoisyRulesIdempotent(t *testing.T) {
	store := &selfCleanStore{stats: []RulePrecision{
		{RuleName: "noisy-rule", Total: 12, FalsePositive: 9, Ignored: 2},
	}, firstAdd: true}
	settings := serviceSettings(true)
	settings.Keywords = nil
	settings.Rules = []Rule{{Enabled: true, Name: "noisy-rule", Keywords: []string{"alpha"}}}
	service, err := newService(store, settings, &quotaProbingProvider{}, serviceTestDetector{}, lz.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	var events []Event
	service.notify = func(e Event) { events = append(events, e) }

	// 两轮调用：第一轮真实新增（通知），第二轮 AddSuppression 返回 false（已在
	// 清单中，幂等）——不再通知。
	service.autoDisableNoisyRules(context.Background())
	service.autoDisableNoisyRules(context.Background())

	if store.addCalls != 2 {
		t.Fatalf("add calls = %d, want 2 (both rounds attempted)", store.addCalls)
	}
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1 (idempotent, no re-notify)", len(events))
	}
}
