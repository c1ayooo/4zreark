package nucleiruntime

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

func TestExtractZipBinary(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "release.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	// 真实 release 里二进制可能带一层目录；用 basename 匹配即可。
	w, err := zw.Create("nuclei_3.11.1_linux_amd64/nuclei")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("fake-nuclei")); err != nil {
		t.Fatal(err)
	}
	// 非目标文件不应被选中。
	w2, _ := zw.Create("nuclei_3.11.1_linux_amd64/README.md")
	_, _ = w2.Write([]byte("readme"))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	dest := filepath.Join(dir, "nuclei")
	if err := extractZipBinary(zipPath, "nuclei", dest); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "fake-nuclei" {
		t.Fatalf("extracted = %q", got)
	}
	if err := extractZipBinary(zipPath, "nuclei.exe", filepath.Join(dir, "nuclei.exe")); err == nil {
		t.Fatal("missing binary should error")
	}
}
