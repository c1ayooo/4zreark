package nucleiruntime

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestTemplateIndexPicksUpCustomChanges(t *testing.T) {
	officialDir := t.TempDir()
	customDir := t.TempDir()
	writeFile(t, filepath.Join(officialDir, "http", "official.yaml"), `
id: official-demo
info:
  name: Official Demo
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
`)

	idx := NewMultiIndex([]IndexDir{
		{Path: officialDir, Source: SourceOfficial},
		{Path: customDir, Source: SourceCustom},
	})
	if _, total, err := idx.List(ListOptions{Page: 1, Size: 10}); err != nil || total != 1 {
		t.Fatalf("initial total=%d err=%v, want 1", total, err)
	}

	// External file drop: no Manager CRUD call, just a file appearing on disk.
	writeFile(t, filepath.Join(customDir, "custom-new.yaml"), `
id: custom-new
info:
  name: Custom New
  severity: medium
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
`)
	idx.mu.Lock()
	idx.lastCheck = time.Time{}
	idx.mu.Unlock()
	if _, total, err := idx.List(ListOptions{Page: 1, Size: 10}); err != nil || total != 2 {
		t.Fatalf("after add total=%d err=%v, want 2", total, err)
	}

	// Same path, changed severity: mtime/size must trigger a rebuild too.
	writeFile(t, filepath.Join(customDir, "custom-new.yaml"), `
id: custom-new
info:
  name: Custom New
  severity: critical
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
`)
	idx.mu.Lock()
	idx.lastCheck = time.Time{}
	idx.mu.Unlock()
	meta, ok := idx.Get("custom-new")
	if !ok || meta.Severity != "critical" {
		t.Fatalf("after edit meta=%+v ok=%v, want critical", meta, ok)
	}

	// Deletion also refreshes.
	if err := os.Remove(filepath.Join(customDir, "custom-new.yaml")); err != nil {
		t.Fatal(err)
	}
	idx.mu.Lock()
	idx.lastCheck = time.Time{}
	idx.mu.Unlock()
	if _, total, err := idx.List(ListOptions{Page: 1, Size: 10}); err != nil || total != 1 {
		t.Fatalf("after remove total=%d err=%v, want 1", total, err)
	}
}

func TestTemplateIndexSearchAndResolve(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "http", "demo.yaml"), `
id: CVE-2024-0001
info:
  name: Demo Product RCE
  severity: critical
  description: demo product remote code execution
  tags: demo,rce
  classification:
    cve-id: CVE-2024-0001
http:
  - method: GET
    path:
      - "{{BaseURL}}/x"
`)
	writeFile(t, filepath.Join(dir, "dns", "demo-dns.yaml"), `
id: demo-dns
info:
  name: Demo DNS Check
  severity: low
  tags: [dns, demo]
  classification:
    cve-id: [CVE-2024-0002, CVE-2024-0003]
dns:
  - name: "{{FQDN}}"
    type: A
`)
	// 没有 id/info 的 helper 文件不应进入索引。
	writeFile(t, filepath.Join(dir, "helpers", "ignore.yaml"), "payloads:\n  - x\n")

	idx := NewIndex(dir)
	items, total, err := idx.Search("demo", Filters{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(items) != 2 {
		t.Fatalf("search demo = %d/%d, want 2/2", total, len(items))
	}
	if items[0].Severity != "critical" {
		t.Fatalf("critical should sort first, got %+v", items[0])
	}

	items, total, err = idx.Search("", Filters{Severity: []string{"critical"}}, 10)
	if err != nil || total != 1 || items[0].ID != "CVE-2024-0001" {
		t.Fatalf("severity filter: %+v %d %v", items, total, err)
	}
	items, total, err = idx.Search("", Filters{Tags: []string{"rce"}}, 10)
	if err != nil || total != 1 || items[0].ID != "CVE-2024-0001" {
		t.Fatalf("tag filter: %+v %d %v", items, total, err)
	}
	items, total, err = idx.Search("", Filters{Type: "dns"}, 10)
	if err != nil || total != 1 || items[0].ID != "demo-dns" {
		t.Fatalf("type filter: %+v %d %v", items, total, err)
	}
	if got := idx.Count(); got != 2 {
		t.Fatalf("Count = %d, want 2", got)
	}

	paths, err := idx.Resolve([]string{"demo-dns", "http/demo.yaml"})
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 {
		t.Fatalf("Resolve = %v", paths)
	}
	for _, p := range paths {
		if !filepath.IsAbs(p) || !strings.HasPrefix(p, dir) {
			t.Fatalf("resolved path escaped templates dir: %s", p)
		}
	}
	if _, err := idx.Resolve([]string{"../../etc/passwd"}); err == nil {
		t.Fatal("traversal path must be rejected")
	}
	if _, err := idx.Resolve([]string{"/etc/passwd"}); err == nil {
		t.Fatal("absolute path must be rejected")
	}
	if _, err := idx.Resolve([]string{"no-such-template"}); err == nil {
		t.Fatal("unknown id must be rejected")
	}
}

func TestParseResultLine(t *testing.T) {
	line := []byte(`{"template-id":"CVE-2024-0001","info":{"name":"Demo RCE","severity":"HIGH","tags":["demo","rce"],"classification":{"cve-id":["CVE-2024-0001"]}},"type":"http","host":"example.com","matched-at":"http://example.com/x","matcher-name":"word","extracted-results":["root:x"],"curl-command":"curl -s http://example.com/x","timestamp":"2026-01-01T00:00:00Z"}`)
	r, ok := parseResultLine(line)
	if !ok {
		t.Fatal("line should parse")
	}
	if r.TemplateID != "CVE-2024-0001" || r.Severity != "high" || r.MatchedAt != "http://example.com/x" {
		t.Fatalf("unexpected result: %+v", r)
	}
	if len(r.Extracted) != 1 || r.Extracted[0] != "root:x" {
		t.Fatalf("extracted: %+v", r.Extracted)
	}
	if _, ok := parseResultLine([]byte(`{"foo":"bar"}`)); ok {
		t.Fatal("non-nuclei JSON should be ignored")
	}
}
