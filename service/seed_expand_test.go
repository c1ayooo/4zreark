package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/c1ayooo/4zreark/repo"
)

func TestNormalizeDomainValue(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "ExAmPle.COM.", want: "example.com"},
		{in: "https://Example.com:8443/path?q=1", want: "example.com"},
		{in: "  example.com  ", want: "example.com"},
		{in: "例子.测试", want: "xn--fsqu00a.xn--0zwm56d"},
		{in: "192.0.2.1", want: "192.0.2.1"},
		{in: "bad_domain.example.com", wantErr: true},
		{in: "-bad.example.com", wantErr: true},
		{in: "single-label", wantErr: true},
		{in: "", wantErr: true},
	}
	for _, tc := range cases {
		got, err := normalizeDomainValue(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("normalizeDomainValue(%q) expected error, got %q", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Fatalf("normalizeDomainValue(%q) error: %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("normalizeDomainValue(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestExpandCIDR(t *testing.T) {
	tests := []struct {
		name     string
		cidr     string
		ports    any
		wantN    int
		wantErr  bool
		warnPart string
	}{
		{name: "/30 两台可用主机", cidr: "203.0.113.0/30", ports: []any{80.0, 443.0}, wantN: 4, warnPart: "网络地址"},
		{name: "/31 RFC3021", cidr: "203.0.113.0/31", ports: []int{443}, wantN: 2, warnPart: "RFC 3021"},
		{name: "/32 单地址", cidr: "203.0.113.7/32", ports: []int{443}, wantN: 1},
		{name: "过大网段", cidr: "10.0.0.0/8", wantErr: true},
		{name: "不支持 IPv6", cidr: "2001:db8::/64", wantErr: true},
		{name: "非法 CIDR", cidr: "not-a-cidr", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			capability := map[string]any{}
			if tc.ports != nil {
				capability["ports"] = tc.ports
			}
			got, warnings, err := expandCIDR(tc.cidr, capability, SeedMaxTargets)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %d targets", len(got))
				}
				if !errors.Is(err, ErrSeedValidation) {
					t.Fatalf("expected ErrSeedValidation, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("expandCIDR error: %v", err)
			}
			if len(got) != tc.wantN {
				t.Fatalf("got %d targets, want %d: %+v", len(got), tc.wantN, got)
			}
			if tc.warnPart != "" && !strings.Contains(strings.Join(warnings, " "), tc.warnPart) {
				t.Fatalf("warnings %v missing %q", warnings, tc.warnPart)
			}
			for _, target := range got {
				if target.Host == "" || target.Port <= 0 {
					t.Fatalf("invalid target: %+v", target)
				}
				if target.Capability["source"] != "cidr" {
					t.Fatalf("capability source = %v, want cidr", target.Capability["source"])
				}
			}
		})
	}
}

func TestExpandCIDRCap(t *testing.T) {
	got, warnings, err := expandCIDR("203.0.113.0/24", map[string]any{
		"ports":     []int{443},
		"max_hosts": 5,
	}, SeedMaxTargets)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 {
		t.Fatalf("got %d targets, want 5", len(got))
	}
	if !strings.Contains(strings.Join(warnings, " "), "已截断") {
		t.Fatalf("warnings missing truncation: %v", warnings)
	}
}

func TestFinalizeSeedTargets(t *testing.T) {
	in := []repo.TargetInput{
		{Host: "b.example.com", Port: 443},
		{Host: "a.example.com", Port: 443},
		{Host: "a.example.com", Port: 443},
		{Host: "a.example.com", Port: 80},
		{Host: "", Port: 80},
	}
	got, total, warnings := finalizeSeedTargets(in, 2)
	if total != 2 || len(got) != 2 {
		t.Fatalf("total=%d len=%d want 2", total, len(got))
	}
	if got[0].Host != "a.example.com" || got[0].Port != 80 {
		t.Fatalf("first target = %+v", got[0])
	}
	if got[0].Capability["probe"] != true {
		t.Fatalf("default capability not applied: %+v", got[0])
	}
	if !strings.Contains(strings.Join(warnings, " "), "超过上限") {
		t.Fatalf("warnings missing cap: %v", warnings)
	}
}

func TestCapabilityPorts(t *testing.T) {
	cases := []struct {
		name    string
		in      any
		want    []int
		wantErr bool
	}{
		{name: "nil 用默认", in: nil, want: []int{80, 443}},
		{name: "数组去重排序", in: []any{443.0, 80.0, 443.0}, want: []int{80, 443}},
		{name: "字符串数组", in: []string{"8443", "443"}, want: []int{443, 8443}},
		{name: "越界", in: []int{70000}, wantErr: true},
		{name: "空数组", in: []int{}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := capabilityPorts(tc.in, []int{80, 443})
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("capabilityPorts error: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v, want %v", got, tc.want)
				}
			}
		})
	}
}

func TestExpandSeedStaticExternalKinds(t *testing.T) {
	svc := NewCycleService()
	for _, kind := range []string{"company", "repo", "app"} {
		res, err := svc.ExpandSeed(context.Background(), &repo.Seed{
			ProjectID: 1, Kind: kind, Value: "示例公司", Enabled: true,
		}, false, 100, 10)
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		if res.Total != 0 || len(res.Targets) != 0 {
			t.Fatalf("%s: expected no targets, got %d", kind, res.Total)
		}
		if res.EmptyReason != kind+"_live_source_required" {
			t.Fatalf("%s: empty_reason = %q", kind, res.EmptyReason)
		}
		if len(res.Warnings) == 0 {
			t.Fatalf("%s: expected warnings", kind)
		}
	}
}

func TestExpandCompanyLive(t *testing.T) {
	oldKeys, oldSearch := companyEngineKeys, companySearchRows
	defer func() { companyEngineKeys, companySearchRows = oldKeys, oldSearch }()

	companyEngineKeys = func(context.Context) map[string]string {
		return map[string]string{"fofa": "test-key"}
	}
	companySearchRows = func(_ context.Context, _ map[string]string, engine, query string, limit int) ([]map[string]any, error) {
		if engine != "fofa" {
			t.Fatalf("unexpected engine %q", engine)
		}
		if !strings.Contains(query, "示例公司") {
			t.Fatalf("query missing company: %q", query)
		}
		return []map[string]any{
			{"domain": "a.example.com"},
			{"domain": "b.example.com"},
			{"domain": "a.example.com"},
		}, nil
	}

	svc := NewCycleService()
	svc.expandDomainHook = func(_ context.Context, _ int64, domain string, _ int) ([]repo.TargetInput, []string, error) {
		return []repo.TargetInput{{Host: domain, Port: 443}}, nil, nil
	}
	res, err := svc.ExpandSeed(context.Background(), &repo.Seed{
		ProjectID: 1, Kind: "company", Value: "示例公司",
		Capability: map[string]any{"live": true}, Enabled: true,
	}, true, 100, 100)
	if err != nil {
		t.Fatal(err)
	}
	if res.Total != 2 {
		t.Fatalf("total = %d, want 2: %+v", res.Total, res.Targets)
	}
	for _, target := range res.Targets {
		if target.Capability["via"] != "company" {
			t.Fatalf("capability missing via=company: %+v", target)
		}
	}
	if !strings.Contains(strings.Join(res.Warnings, " "), "fofa") {
		t.Fatalf("warnings missing engine summary: %v", res.Warnings)
	}
}

func TestExpandCompanyLiveWithoutKeys(t *testing.T) {
	oldKeys, oldSearch := companyEngineKeys, companySearchRows
	defer func() { companyEngineKeys, companySearchRows = oldKeys, oldSearch }()

	companyEngineKeys = func(context.Context) map[string]string { return map[string]string{} }
	companySearchRows = func(context.Context, map[string]string, string, string, int) ([]map[string]any, error) {
		t.Fatal("search should not be called without keys")
		return nil, nil
	}

	svc := NewCycleService()
	res, err := svc.ExpandSeed(context.Background(), &repo.Seed{
		ProjectID: 1, Kind: "company", Value: "示例公司",
		Capability: map[string]any{"live": true}, Enabled: true,
	}, true, 100, 100)
	if err != nil {
		t.Fatal(err)
	}
	if res.Total != 0 || res.EmptyReason != "company_no_domains" {
		t.Fatalf("total=%d reason=%q, want 0/company_no_domains", res.Total, res.EmptyReason)
	}
	if !strings.Contains(strings.Join(res.Warnings, " "), "API Key") {
		t.Fatalf("warnings missing key hint: %v", res.Warnings)
	}
}

func TestExpandDomainLive(t *testing.T) {
	oldKeys, oldSearch := companyEngineKeys, companySearchRows
	defer func() { companyEngineKeys, companySearchRows = oldKeys, oldSearch }()

	companyEngineKeys = func(context.Context) map[string]string {
		return map[string]string{"quake": "test-key", "github": "gh"}
	}
	companySearchRows = func(_ context.Context, _ map[string]string, engine, query string, limit int) ([]map[string]any, error) {
		if engine != "quake" {
			t.Fatalf("unexpected engine %q", engine)
		}
		if !strings.Contains(query, "meituan.com") {
			t.Fatalf("query missing domain: %q", query)
		}
		return []map[string]any{
			{"domain": "a.meituan.com"},
			{"domain": "b.meituan.com"},
			{"domain": "a.meituan.com"},
		}, nil
	}

	svc := NewCycleService()
	svc.expandDomainHook = func(_ context.Context, _ int64, domain string, _ int) ([]repo.TargetInput, []string, error) {
		return []repo.TargetInput{{Host: domain, Port: 443}}, nil, nil
	}
	res, err := svc.ExpandSeed(context.Background(), &repo.Seed{
		ProjectID: 5, Kind: "domain", Value: "https://Meituan.com/",
		Capability: map[string]any{"live": true, "engines": []any{"quake"}}, Enabled: true,
	}, true, 100, 100)
	if err != nil {
		t.Fatal(err)
	}
	if res.NormalizedValue != "meituan.com" {
		t.Fatalf("normalized = %q", res.NormalizedValue)
	}
	if res.Total != 3 {
		t.Fatalf("total=%d, want 3: %+v", res.Total, res.Targets)
	}
	for _, target := range res.Targets {
		if target.Capability["via"] != "domain_live" {
			t.Fatalf("capability missing via=domain_live: %+v", target)
		}
	}
	if !strings.Contains(strings.Join(res.Warnings, " "), "quake") {
		t.Fatalf("warnings missing engine summary: %v", res.Warnings)
	}
}

func TestExpandSeedProbeFalse(t *testing.T) {
	oldKeys, oldSearch := companyEngineKeys, companySearchRows
	defer func() { companyEngineKeys, companySearchRows = oldKeys, oldSearch }()
	companyEngineKeys = func(context.Context) map[string]string { return map[string]string{"quake": "k"} }
	companySearchRows = func(context.Context, map[string]string, string, string, int) ([]map[string]any, error) {
		return []map[string]any{{"domain": "a.meituan.com"}}, nil
	}
	svc := NewCycleService()
	svc.expandDomainHook = func(_ context.Context, _ int64, domain string, _ int) ([]repo.TargetInput, []string, error) {
		return []repo.TargetInput{{Host: domain, Port: 443, Capability: map[string]any{"probe": true}}}, nil, nil
	}
	res, err := svc.ExpandSeed(context.Background(), &repo.Seed{
		ProjectID: 5, Kind: "domain", Value: "meituan.com",
		Capability: map[string]any{"live": true, "engines": []any{"quake"}, "probe": false}, Enabled: true,
	}, true, 100, 100)
	if err != nil {
		t.Fatal(err)
	}
	if res.Total != 2 {
		t.Fatalf("total=%d want 2", res.Total)
	}
	for _, target := range res.Targets {
		if target.Capability["probe"] != false {
			t.Fatalf("probe should be false: %+v", target)
		}
	}
}

func TestParseRepoRef(t *testing.T) {
	cases := []struct {
		in      string
		owner   string
		name    string
		kind    string
		wantErr bool
	}{
		{in: "https://github.com/acme/demo.git", owner: "acme", name: "demo", kind: "github"},
		{in: "github.com/acme/demo", owner: "acme", name: "demo", kind: "github"},
		{in: "https://gitlab.com/acme/demo", owner: "acme", name: "demo", kind: "gitlab"},
		{in: "https://gitlab.example.com/acme/demo", owner: "acme", name: "demo", kind: "gitlab"},
		{in: "https://bitbucket.org/acme/demo", wantErr: true},
		{in: "https://github.com/acme", wantErr: true},
		{in: "", wantErr: true},
	}
	for _, tc := range cases {
		ref, err := parseRepoRef(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("parseRepoRef(%q) expected error, got %+v", tc.in, ref)
			}
			continue
		}
		if err != nil {
			t.Fatalf("parseRepoRef(%q): %v", tc.in, err)
		}
		if ref.Owner != tc.owner || ref.Name != tc.name || ref.Kind != tc.kind {
			t.Fatalf("parseRepoRef(%q) = %+v", tc.in, ref)
		}
	}
}

func TestExtractDomains(t *testing.T) {
	text := `
	api.example.com
	CONFIG=config.yaml
	schema.json
	https://www.example.org/path
	localhost
	api.example.com
	github.com
	tracker.example.net?x=1
	`
	got := extractDomains(text)
	want := map[string]bool{"api.example.com": true, "www.example.org": true, "tracker.example.net": true}
	if len(got) != len(want) {
		t.Fatalf("got %v, want keys %v", got, want)
	}
	for _, d := range got {
		if !want[d] {
			t.Fatalf("unexpected domain %q in %v", d, got)
		}
	}
}

func TestExpandRepoLive(t *testing.T) {
	oldFetch := repoDomainsFetch
	defer func() { repoDomainsFetch = oldFetch }()
	repoDomainsFetch = func(_ context.Context, _ string, owner, name string, limit int) ([]string, error) {
		if owner != "acme" || name != "demo" {
			t.Fatalf("unexpected repo %s/%s", owner, name)
		}
		return []string{"b.example.com", "a.example.com"}, nil
	}

	svc := NewCycleService()
	svc.expandDomainHook = func(_ context.Context, _ int64, domain string, _ int) ([]repo.TargetInput, []string, error) {
		return []repo.TargetInput{{Host: domain, Port: 443}}, nil, nil
	}
	res, err := svc.ExpandSeed(context.Background(), &repo.Seed{
		ProjectID: 1, Kind: "repo", Value: "https://github.com/acme/demo",
		Capability: map[string]any{"live": true}, Enabled: true,
	}, true, 100, 100)
	if err != nil {
		t.Fatal(err)
	}
	if res.Total != 2 {
		t.Fatalf("total=%d, want 2: %+v", res.Total, res.Targets)
	}
	for _, target := range res.Targets {
		if target.Capability["via"] != "repo" {
			t.Fatalf("capability missing via=repo: %+v", target)
		}
	}
	if !strings.Contains(strings.Join(res.Warnings, " "), "仓库") {
		t.Fatalf("warnings missing repo summary: %v", res.Warnings)
	}
}

func TestExpandRepoLiveGitLab(t *testing.T) {
	oldFetch := repoGitLabFetch
	defer func() { repoGitLabFetch = oldFetch }()
	repoGitLabFetch = func(_ context.Context, apiBase, _ string, owner, name string, limit int) ([]string, error) {
		if apiBase != "https://gitlab.example.com/api/v4" || owner != "acme" || name != "demo" {
			t.Fatalf("unexpected gitlab args: base=%s repo=%s/%s", apiBase, owner, name)
		}
		return []string{"gl.example.com"}, nil
	}

	svc := NewCycleService()
	svc.expandDomainHook = func(_ context.Context, _ int64, domain string, _ int) ([]repo.TargetInput, []string, error) {
		return []repo.TargetInput{{Host: domain, Port: 443}}, nil, nil
	}
	res, err := svc.ExpandSeed(context.Background(), &repo.Seed{
		ProjectID: 1, Kind: "repo", Value: "https://gitlab.example.com/acme/demo",
		Capability: map[string]any{"live": true, "api_base": "https://gitlab.example.com/api/v4"},
		Enabled:    true,
	}, true, 100, 100)
	if err != nil {
		t.Fatal(err)
	}
	if res.Total != 1 || res.Targets[0].Capability["via"] != "repo" {
		t.Fatalf("gitlab expansion mismatch: %+v", res)
	}
}

func TestPreviewSeedValidation(t *testing.T) {
	svc := NewCycleService()
	cases := []SeedPreviewRequest{
		{ProjectID: 0, Kind: "domain", Value: "example.com"},
		{ProjectID: 1, Kind: "unknown", Value: "example.com"},
		{ProjectID: 1, Kind: "domain", Value: ""},
	}
	for _, req := range cases {
		if _, err := svc.PreviewSeed(context.Background(), req); err == nil {
			t.Fatalf("expected validation error for %+v", req)
		} else if !errors.Is(err, ErrSeedValidation) {
			t.Fatalf("expected ErrSeedValidation, got %v", err)
		}
	}
}

func TestIsValidDictLabel(t *testing.T) {
	valid := []string{"www", "api-v2", "a1"}
	invalid := []string{"", "-api", "api-", "a.b", "白", "a b"}
	for _, v := range valid {
		if !isValidDictLabel(v) {
			t.Fatalf("%q should be valid", v)
		}
	}
	for _, v := range invalid {
		if isValidDictLabel(v) {
			t.Fatalf("%q should be invalid", v)
		}
	}
}
