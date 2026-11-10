package datadir

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestBinRootEnv(t *testing.T) {
	t.Setenv(binRootEnv, "/custom/bin")
	if got := BinRoot(); got != "/custom/bin" {
		t.Fatalf("BinRoot = %q, want /custom/bin", got)
	}
	if got := Sub("browser"); got != filepath.Join("/custom/bin", "browser") {
		t.Fatalf("Sub = %q", got)
	}
}

func TestBinRootDefault(t *testing.T) {
	once = sync.Once{} // 重置缓存测默认分支
	defer func() { once = sync.Once{} }()
	t.Setenv(binRootEnv, "")
	if got := BinRoot(); got != filepath.Join("data", "bin") {
		t.Fatalf("默认 BinRoot = %q", got)
	}
}

// 收编主路径：旧目录有内容 + 目标不存在 → rename 迁移，旧壳不残留。
func TestAdoptMigrates(t *testing.T) {
	dir := t.TempDir()
	legacy := filepath.Join(dir, "data", "tools")
	dst := filepath.Join(dir, "bin", "tools")
	if err := os.MkdirAll(legacy, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacy, "gogo"), []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	got := adoptForTest(legacy, dst)
	if got != dst {
		t.Fatalf("Adopt 返回 %q, want %q", got, dst)
	}
	if _, err := os.Stat(filepath.Join(dst, "gogo")); err != nil {
		t.Fatalf("数据应已迁移: %v", err)
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatal("旧目录应已消失")
	}
}

// 目标已存在且旧目录空壳 → 清壳用目标（重复启动幂等）。
func TestAdoptIdempotent(t *testing.T) {
	dir := t.TempDir()
	legacy := filepath.Join(dir, "data", "nuclei")
	dst := filepath.Join(dir, "bin", "nuclei")
	if err := os.MkdirAll(dst, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dst, "nuclei"), []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(legacy, 0o750); err != nil {
		t.Fatal(err)
	}
	got := adoptForTest(legacy, dst)
	if got != dst {
		t.Fatalf("got %q", got)
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatal("空壳应被清理")
	}
}

// 两边都有内容（异常态）：以 bin 为准合并——同名保留 bin 版本，
// 旧目录独有文件搬进 bin，旧目录移除；平台不再被困在旧路径。
func TestAdoptMergesWhenBothExist(t *testing.T) {
	dir := t.TempDir()
	legacy := filepath.Join(dir, "data", "tools")
	dst := filepath.Join(dir, "bin", "tools")
	for _, d := range []string{legacy, dst} {
		if err := os.MkdirAll(filepath.Join(d, "sub"), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	// 同名：bin 是权威，旧目录版本应被丢弃
	if err := os.WriteFile(filepath.Join(legacy, "keep"), []byte("legacy"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dst, "keep"), []byte("bin"), 0o600); err != nil {
		t.Fatal(err)
	}
	// 旧目录独有：必须搬进 bin，不丢数据
	if err := os.WriteFile(filepath.Join(legacy, "sub", "rem"), []byte("old-rem"), 0o755); err != nil {
		t.Fatal(err)
	}
	// bin 独有：原样保留
	if err := os.WriteFile(filepath.Join(dst, "only-bin"), []byte("bin-only"), 0o600); err != nil {
		t.Fatal(err)
	}

	got := adoptForTest(legacy, dst)
	if got != dst {
		t.Fatalf("合并后应使用 bin 目录 %q, got %q", dst, got)
	}
	if string(mustRead(t, filepath.Join(dst, "keep"))) != "bin" {
		t.Fatal("bin 内同名文件不应被旧目录覆盖")
	}
	if string(mustRead(t, filepath.Join(dst, "sub", "rem"))) != "old-rem" {
		t.Fatal("旧目录独有文件应并入 bin")
	}
	if string(mustRead(t, filepath.Join(dst, "only-bin"))) != "bin-only" {
		t.Fatal("bin 独有文件应保留")
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatal("旧目录应在合并后移除")
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
