package githubleak

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestSettingsNormalizeDefaultsAndCanonicalizesKeywords(t *testing.T) {
	got, err := (Settings{
		Token:          "  unit-test-token  ",
		FingerprintKey: "  unit-test-fingerprint-key  ",
		Keywords:       []string{" storage-service ", "storage-service", "vendor.example"},
	}).Normalize()
	if err != nil {
		t.Fatal(err)
	}
	if got.Token != "unit-test-token" || got.FingerprintKey != "unit-test-fingerprint-key" {
		t.Fatal("secret settings were not trimmed")
	}
	if got.IntervalSeconds != DefaultIntervalSeconds || got.RequestTimeoutSeconds != DefaultTimeoutSeconds ||
		got.PollIntervalSeconds != DefaultPollSeconds || got.MaxResultsPerKeyword != DefaultMaxResults {
		t.Fatalf("defaults = interval:%d timeout:%d poll:%d max:%d", got.IntervalSeconds, got.RequestTimeoutSeconds, got.PollIntervalSeconds, got.MaxResultsPerKeyword)
	}
	if len(got.Keywords) != 2 || got.Keywords[0] != "storage-service" || got.Keywords[1] != "vendor.example" {
		t.Fatalf("keywords = %#v", got.Keywords)
	}
	if !got.Configured() {
		t.Fatal("normalized token and keywords should be configured")
	}
}

func TestRuntimeAndFindingJSONExposeNamedRuleMetadata(t *testing.T) {
	query := `"clientid" AND "vendor.example" in:file`
	runtimeData, err := json.Marshal(RuntimeStatus{LastWarning: "coverage limited", Rules: []RuleStatus{{
		Enabled: true, Name: "example-corp-clientid", Keywords: []string{"clientid", "vendor.example"}, Query: query,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	findingData, err := json.Marshal(Finding{RuleName: "example-corp-clientid", Keyword: query, BlobSHA: strings.Repeat("a", 40)})
	if err != nil {
		t.Fatal(err)
	}
	var decoded RuntimeStatus
	if err = json.Unmarshal(runtimeData, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.LastWarning != "coverage limited" || len(decoded.Rules) != 1 || decoded.Rules[0].Query != query ||
		!strings.Contains(string(runtimeData), `"last_warning":"coverage limited"`) ||
		!strings.Contains(string(runtimeData), `"rules"`) ||
		!strings.Contains(string(findingData), `"rule_name":"example-corp-clientid"`) || !strings.Contains(string(findingData), `"keyword"`) {
		t.Fatalf("rule metadata missing: runtime=%s finding=%s", runtimeData, findingData)
	}
	if strings.Contains(string(findingData), strings.Repeat("a", 40)) {
		t.Fatalf("finding JSON exposed blob SHA: %s", findingData)
	}
}

func TestKeywordRuleRequiresAllEscapedLiteralsInOneFile(t *testing.T) {
	rule, err := newKeywordRule([]string{`vendor.example`, `storage-service`, `repo:evil" OR secret`})
	if err != nil {
		t.Fatal(err)
	}
	want := `"repo:evil\" OR secret" AND "storage-service" AND "vendor.example" in:file`
	if rule.Query != want {
		t.Fatalf("query = %q, want %q", rule.Query, want)
	}
}

func TestSettingsNormalizeEnforcesSafetyBounds(t *testing.T) {
	tooMany := make([]string, MaxKeywords+1)
	for i := range tooMany {
		tooMany[i] = "keyword" + strings.Repeat("x", i+1)
	}
	invalidUTF8 := string([]byte{0xff, 0xfe})
	tests := []struct {
		name     string
		settings Settings
	}{
		{name: "interval at thirty seconds", settings: Settings{IntervalSeconds: MinIntervalSeconds - 1, Keywords: []string{"storage-service"}}},
		{name: "negative timeout", settings: Settings{RequestTimeoutSeconds: -1, Keywords: []string{"storage-service"}}},
		{name: "excessive timeout", settings: Settings{RequestTimeoutSeconds: 301, Keywords: []string{"storage-service"}}},
		{name: "excessive results", settings: Settings{MaxResultsPerKeyword: 101, Keywords: []string{"storage-service"}}},
		{name: "too many keywords", settings: Settings{Keywords: tooMany}},
		{name: "one byte keyword", settings: Settings{Keywords: []string{"x"}}},
		{name: "overlong utf8 keyword", settings: Settings{Keywords: []string{strings.Repeat("中", 67)}}},
		{name: "invalid utf8 keyword", settings: Settings{Keywords: []string{invalidUTF8}}},
		{name: "nul keyword", settings: Settings{Keywords: []string{"s3\x00plus"}}},
		{name: "multiline keyword", settings: Settings{Keywords: []string{"storage-service\nvendor.example"}}},
		{name: "combined literals too long", settings: Settings{Keywords: []string{strings.Repeat("a", 130), strings.Repeat("b", 130)}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.settings.Normalize(); err == nil {
				t.Fatal("invalid settings were accepted")
			}
		})
	}
}

func TestSettingsPollIntervalCannotUndercutRequestInterval(t *testing.T) {
	got, err := (Settings{IntervalSeconds: 45, PollIntervalSeconds: 31, Keywords: []string{"storage-service"}}).Normalize()
	if err != nil {
		t.Fatal(err)
	}
	if got.PollIntervalSeconds != got.IntervalSeconds {
		t.Fatalf("poll interval = %d, request interval = %d", got.PollIntervalSeconds, got.IntervalSeconds)
	}
}

func TestSettingsNamedRulesTakePrecedenceOverLegacyKeywords(t *testing.T) {
	got, err := (Settings{
		Token:    "unit-test-token",
		Keywords: []string{"hidden-legacy", "vendor.example"},
		Rules: []Rule{
			{Enabled: true, Name: " example-corp-clientid ", Keywords: []string{"vendor.example", "clientid"}},
			{Enabled: false, Name: "aws-accesskey", Keywords: []string{"example.com", "ACCESSKEY"}},
		},
	}).Normalize()
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Keywords) != 0 {
		t.Fatalf("legacy keywords remained active with named rules: %#v", got.Keywords)
	}
	if !got.Configured() || len(got.Rules) != 2 || got.Rules[0].Name != "example-corp-clientid" {
		t.Fatalf("normalized named rules = %+v", got)
	}
	compiled, err := compiledRules(got, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(compiled) != 1 || compiled[0].Name != "example-corp-clientid" || compiled[0].Query != `"clientid" AND "vendor.example" in:file` {
		t.Fatalf("enabled rules = %+v", compiled)
	}
}

func TestSettingsNamedRuleValidation(t *testing.T) {
	base := Settings{Token: "unit-test-token", Rules: []Rule{{Enabled: true, Name: "one", Keywords: []string{"vendor.example", "clientid"}}}}
	tests := []struct {
		name     string
		settings Settings
	}{
		{name: "duplicate name", settings: Settings{Rules: []Rule{
			{Enabled: true, Name: "Rule", Keywords: []string{"vendor.example", "clientid"}},
			{Enabled: true, Name: "rule", Keywords: []string{"example.com", "accesskey"}},
		}}},
		{name: "duplicate canonical query", settings: Settings{Rules: []Rule{
			{Enabled: true, Name: "one", Keywords: []string{"vendor.example", "clientid"}},
			{Enabled: true, Name: "two", Keywords: []string{"CLIENTID", "vendor.example"}},
		}}},
		{name: "empty keywords", settings: Settings{Rules: []Rule{{Enabled: false, Name: "empty"}}}},
		{name: "control in name", settings: Settings{Rules: []Rule{{Enabled: true, Name: "bad\nname", Keywords: []string{"clientid"}}}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.settings.Normalize(); err == nil {
				t.Fatal("invalid named rules were accepted")
			}
		})
	}

	disabled := base
	disabled.Rules[0].Enabled = false
	got, err := disabled.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	if got.Configured() {
		t.Fatal("token plus only disabled rules must not be configured")
	}
}

func TestSettingsRejectsMoreThanMaxRules(t *testing.T) {
	rules := make([]Rule, MaxRules+1)
	for i := range rules {
		rules[i] = Rule{Enabled: true, Name: fmt.Sprintf("rule-%d", i), Keywords: []string{fmt.Sprintf("keyword-%d", i)}}
	}
	if _, err := (Settings{Rules: rules}).Normalize(); err == nil {
		t.Fatalf("more than %d rules were accepted", MaxRules)
	}
}
