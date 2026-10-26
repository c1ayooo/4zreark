package nucleiruntime

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestAssetNameAndURL(t *testing.T) {
	asset, binary, err := assetName("v3.11.1", "linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if asset != "nuclei_3.11.1_linux_amd64.zip" || binary != "nuclei" {
		t.Fatalf("asset=%q binary=%q", asset, binary)
	}
	u, err := downloadURL("3.11.1", "linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(u, "/v3.11.1/nuclei_3.11.1_linux_amd64.zip") {
		t.Fatalf("url = %s", u)
	}
	if _, binary, err := assetName("3.11.1", "windows", "amd64"); err != nil || binary != "nuclei.exe" {
		t.Fatalf("windows binary = %q, %v", binary, err)
	}
	if _, _, err := assetName("3.11.1", "darwin", "386"); err == nil {
		t.Fatal("darwin/386 should be rejected")
	}
}

func TestBuildArgs(t *testing.T) {
	m := New(t.TempDir(), nil)
	args := m.buildArgs(RunOptions{
		Tags: []string{"cve", "rce"}, Severity: []string{"high"}, ExcludeTags: []string{"dos"},
		TemplateType: "http", Automatic: true, Proxy: "http://127.0.0.1:8080",
		Headers: map[string]string{"Authorization": "Bearer x"},
	}, "targets.txt", "out.jsonl", []string{"/tmp/t/demo.yaml"})
	got := strings.Join(args, " ")
	for _, want := range []string{
		"-jsonl", "-silent", "-nc", "-duc", "-irr", "-ni",
		"-l targets.txt", "-o out.jsonl", "-t /tmp/t/demo.yaml",
		"-tags cve,rce", "-severity high", "-exclude-tags dos",
		"-type http", "-as", "-proxy http://127.0.0.1:8080",
		"-H Authorization: Bearer x",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("args missing %q: %s", want, got)
		}
	}
	interactsh := strings.Join(m.buildArgs(RunOptions{Interactsh: true}, "t", "o", nil), " ")
	if strings.Contains(interactsh, " -ni") {
		t.Fatalf("interactsh=true should not pass -ni: %s", interactsh)
	}
}

func TestEnsureWithoutAutoDoesNotDownload(t *testing.T) {
	m := New(t.TempDir(), nil)
	if _, err := m.Ensure(context.Background(), false); err == nil {
		t.Fatal("missing binary with auto=false must fail")
	}
}

func TestRunWithFakeBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake shell script is unix-only")
	}
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "templates", "http", "demo.yaml"), `
id: CVE-2024-0001
info:
  name: Demo RCE
  severity: critical
  tags: demo,rce
http:
  - method: GET
    path:
      - "{{BaseURL}}/x"
`)
	bin := filepath.Join(root, "bin", "nuclei")
	writeFile(t, bin, `#!/bin/sh
out=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2;;
    *) shift;;
  esac
done
[ -n "$out" ] || exit 2
printf '%s\n' '{"template-id":"CVE-2024-0001","info":{"name":"Demo RCE","severity":"critical"},"type":"http","host":"example.com","matched-at":"http://example.com/x","matcher-name":"word","curl-command":"curl -s http://example.com/x"}' > "$out"
`)
	if err := os.Chmod(bin, 0o755); err != nil {
		t.Fatal(err)
	}

	m := New(root, nil)
	res, err := m.Run(context.Background(), RunOptions{
		Targets:   []string{"http://example.com"},
		Templates: []string{"CVE-2024-0001"},
		ResultDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Total != 1 || len(res.Results) != 1 {
		t.Fatalf("results = %+v", res)
	}
	r := res.Results[0]
	if r.TemplateID != "CVE-2024-0001" || r.Severity != "critical" || r.MatchedAt != "http://example.com/x" {
		t.Fatalf("unexpected result: %+v", r)
	}
	if _, err := os.Stat(res.ResultFile); err != nil {
		t.Fatalf("result file missing: %v", err)
	}

	if _, err := m.Run(context.Background(), RunOptions{Targets: []string{"http://example.com"}}); err == nil {
		t.Fatal("scan without selectors must fail")
	}
}
