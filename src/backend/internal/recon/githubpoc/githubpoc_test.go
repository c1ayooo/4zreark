package githubpoc_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/internal/recon/githubpoc"
	"github.com/c1ayooo/4zreark/internal/recon/triage"
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

// TestEnrichFetchesRepoFiles 证明分诊确实用上了仓库文件：
// 同一份搜索/公告数据，有代码文件时能产出 PoC；只有 README 时按占位仓库过滤。
func TestEnrichFetchesRepoFiles(t *testing.T) {
	var withCode atomic.Bool
	withCode.Store(true)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/search/repositories":
			_, _ = w.Write([]byte(`{"items":[{
				"full_name":"researcher/poc",
				"html_url":"https://github.com/researcher/poc",
				"description":"Proof of concept exploit for CVE-2024-0002",
				"stargazers_count":100,
				"pushed_at":"` + time.Now().Format(time.RFC3339) + `",
				"default_branch":"main"
			}]}`))
		case r.URL.Path == "/advisories":
			_, _ = w.Write([]byte(`[]`))
		case r.URL.Path == "/repos/researcher/poc/git/trees/main":
			if withCode.Load() {
				_, _ = w.Write([]byte(`{"tree":[
					{"path":"README.md","type":"blob","size":36},
					{"path":"exploit.py","type":"blob","size":120},
					{"path":"src/main.py","type":"blob","size":150}
				]}`))
			} else {
				_, _ = w.Write([]byte(`{"tree":[{"path":"README.md","type":"blob","size":36}]}`))
			}
		case strings.HasPrefix(r.URL.Path, "/raw/"):
			w.Header().Set("Content-Type", "text/plain")
			if strings.HasSuffix(r.URL.Path, "README.md") {
				_, _ = w.Write([]byte("Proof of concept for CVE-2024-0002\n"))
				return
			}
			_, _ = w.Write([]byte("import os\nos.system(\"id\")\n# reverse shell\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := githubpoc.NewClient(func() string { return "test-token" })
	c.BaseURL = srv.URL
	c.RawBaseURL = srv.URL + "/raw"
	c.MinGap = time.Nanosecond
	meta := triage.CVEMeta{
		CVEID: "CVE-2024-0002", CVSSScore: 9.8, CWE: []int{78},
		Description: "remote code execution",
	}

	res, err := c.Enrich(context.Background(), meta)
	if err != nil {
		t.Fatalf("Enrich with files: %v", err)
	}
	if len(res.POCs) != 1 {
		t.Fatalf("有代码文件时应产出 1 个 PoC，实际 %d（%+v）", len(res.POCs), res.POCs)
	}
	joined := strings.Join(res.POCs[0].Reasons, " ")
	if !strings.Contains(joined, "真实利用证据") {
		t.Fatalf("分诊理由应包含文件内容证据: %s", joined)
	}
	if res.LabOnly {
		t.Fatal("已有可用 PoC 时不应把整个 CVE 标成 lab_only")
	}

	withCode.Store(false)
	res, err = c.Enrich(context.Background(), meta)
	if err != nil {
		t.Fatalf("Enrich without files: %v", err)
	}
	if len(res.POCs) != 0 {
		t.Fatalf("只有 README 时应按占位仓库过滤，实际 %+v", res.POCs)
	}
}
