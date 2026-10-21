package githubpoc_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/c1ayooo/reconkit/githubpoc"
	"github.com/c1ayooo/reconkit/triage"
)

func TestEnrichSearchAdvisoryAndTriage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/search/repositories":
			if r.URL.Query().Get("q") != "CVE-2024-0001" {
				t.Errorf("unexpected query: %s", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`{"items":[{
				"full_name":"researcher/poc",
				"html_url":"https://github.com/researcher/poc",
				"description":"Proof of concept exploit for CVE-2024-0001",
				"stargazers_count":120,
				"pushed_at":"` + time.Now().Format(time.RFC3339) + `"
			}]}`))
		case "/advisories":
			_, _ = w.Write([]byte(`[{
				"summary":"Critical remote code execution in foo",
				"severity":"critical",
				"cvss":{"vector_string":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","score":9.8},
				"cwes":[{"cwe_id":"CWE-79"}],
				"vulnerabilities":[{
					"package":{"ecosystem":"npm","name":"foo"},
					"vulnerable_version_range":"< 1.2.3"
				}]
			}]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := githubpoc.NewClient(func() string { return "test-token" })
	c.BaseURL = srv.URL
	c.MinGap = time.Nanosecond

	inKEV := true
	res, err := c.Enrich(context.Background(), triage.CVEMeta{
		CVEID:       "CVE-2024-0001",
		Description: "remote code execution",
		CVSSScore:   7.5,
		InKEV:       &inKEV,
	})
	if err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if res.CVSSScore != 9.8 {
		t.Fatalf("advisory CVSS should win, got %v", res.CVSSScore)
	}
	if res.CVSSVector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" {
		t.Fatalf("unexpected vector: %q", res.CVSSVector)
	}
	if len(res.CWEs) != 1 || res.CWEs[0] != "CWE-79" {
		t.Fatalf("unexpected CWEs: %v", res.CWEs)
	}
	if len(res.Affected) != 1 || res.Affected[0] != "npm/foo" {
		t.Fatalf("unexpected affected: %v", res.Affected)
	}
	if len(res.POCs) != 1 {
		t.Fatalf("expected one surviving POC, got %d", len(res.POCs))
	}
	if res.POCs[0].Verdict != string(triage.VerdictACT) {
		t.Fatalf("KEV should force ACT, got %q", res.POCs[0].Verdict)
	}
}

func TestNoTokenSkipsSearch(t *testing.T) {
	c := githubpoc.NewClient(func() string { return "" })
	res, err := c.Enrich(context.Background(), triage.CVEMeta{CVEID: "CVE-2024-0002"})
	if err != nil {
		t.Fatalf("Enrich without token should not fail: %v", err)
	}
	if len(res.Repos) != 0 || len(res.POCs) != 0 {
		t.Fatalf("expected empty result, got repos=%d pocs=%d", len(res.Repos), len(res.POCs))
	}
}
