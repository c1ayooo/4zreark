package service

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSafeJoinRejectsEscape(t *testing.T) {
	dest := t.TempDir()
	// 逃逸路径必须被拒绝或收敛到 dest 之内，绝不允许落在 dest 之外。
	for _, evil := range []string{"../../etc/passwd", "/etc/passwd", "a/../../../x"} {
		p, err := safeJoin(dest, evil)
		if err != nil {
			continue // 被拒绝也是合格行为
		}
		if !strings.HasPrefix(p, filepath.Clean(dest)+string(os.PathSeparator)) {
			t.Fatalf("路径 %q 逃逸出 dest: %s", evil, p)
		}
	}
	if _, err := safeJoin(dest, ""); err == nil {
		t.Fatal("空路径未被拒绝")
	}
	p, err := safeJoin(dest, "a/b/c.txt")
	if err != nil {
		t.Fatalf("正常路径被误拒: %v", err)
	}
	if want := filepath.Join(dest, "a/b/c.txt"); p != want {
		t.Fatalf("safeJoin = %s, want %s", p, want)
	}
}

func zipBytes(t *testing.T, files map[string]string) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestExtractZip(t *testing.T) {
	dest := t.TempDir()
	content := zipBytes(t, map[string]string{
		"src/main.go":      "package main",
		"nested/dir/a.txt": "hello",
		"../evil.txt":      "should be neutralized",
	})
	if err := extractArchive(".zip", content, dest); err != nil {
		t.Fatalf("extractArchive: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(dest, "src", "main.go")); err != nil || string(b) != "package main" {
		t.Fatalf("src/main.go 未正确解包: %v %q", err, string(b))
	}
	if _, err := os.Stat(filepath.Join(dest, "nested", "dir", "a.txt")); err != nil {
		t.Fatalf("嵌套目录未解包: %v", err)
	}
	// "../evil.txt" 经 Clean("/"+name) 收敛为根下 evil.txt，不允许出现在 dest 之外
	if _, err := os.Stat(filepath.Join(dest, "evil.txt")); err != nil {
		t.Logf("恶意条目收敛到根下或被跳过（均可接受）: %v", err)
	}
}

func TestExtractTarGz(t *testing.T) {
	dest := t.TempDir()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range []struct{ name, body string }{
		{"proj/main.go", "package main"},
		{"proj/README.md", "readme"},
	} {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(f.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := extractArchive(".tar.gz", buf.Bytes(), dest); err != nil {
		t.Fatalf("extractArchive: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(dest, "proj", "main.go")); err != nil || string(b) != "package main" {
		t.Fatalf("proj/main.go 未正确解包: %v %q", err, string(b))
	}
}

func TestSanitizeUploadName(t *testing.T) {
	cases := map[string]string{
		"my repo v1.0": "my-repo-v1.0",
		"../../etc":    "etc",
		"    ":         "code",
	}
	for in, wantPrefix := range cases {
		got := sanitizeUploadName(in)
		if got != wantPrefix {
			t.Errorf("sanitizeUploadName(%q) = %q, want %q", in, got, wantPrefix)
		}
	}
}
