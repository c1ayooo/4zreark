package vulnscan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestBuildArgsFileMode 校验本地路径目标会自动开启 -file，URL 与裸域名不会。
func TestBuildArgsFileMode(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte("var a=1;"), 0o600); err != nil {
		t.Fatal(err)
	}

	s := &NucleiCLIScanner{templatesDir: "/tmp/tpl", concurrency: 10, rateLimit: 50}

	cases := []struct {
		name    string
		targets []string
		want    bool
	}{
		{"url", []string{"https://example.com"}, false},
		{"url-http", []string{"http://10.0.0.1:8080"}, false},
		{"bare-domain", []string{"example.com"}, false},
		{"local-dir", []string{dir}, true},
		{"local-file", []string{filepath.Join(dir, "app.js")}, true},
		{"mixed", []string{"https://example.com", dir}, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			args := s.buildArgs(c.targets, nil)
			got := false
			for _, a := range args {
				if a == "-file" {
					got = true
				}
			}
			if got != c.want {
				t.Fatalf("file mode = %v, want %v, args=%v", got, c.want, args)
			}
			if !strings.Contains(strings.Join(args, " "), "-u") {
				t.Fatalf("缺少 -u 目标参数: %v", args)
			}
		})
	}
}
