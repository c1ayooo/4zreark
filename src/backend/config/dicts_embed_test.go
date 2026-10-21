package config

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// 二进制内置字典：磁盘路径不存在时仍能读到词表。
func TestEmbeddedDictsFallback(t *testing.T) {
	data, err := ReadDictFile("/nonexistent/config/dicts/txt/subdomains.txt")
	if err != nil {
		t.Fatalf("内置字典读取失败: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("内置字典为空")
	}

	// 重置进程级缓存，强制走不存在的基础目录。
	dictConfigOnce = sync.Once{}
	dictConfig = nil
	SetDictBasePath("/nonexistent/config/dicts")
	t.Cleanup(func() {
		dictConfigOnce = sync.Once{}
		dictConfig = nil
		dictBasePath = ""
	})
	cfg := LoadDictConfig()
	if len(cfg.Subdomains) == 0 || len(cfg.Directories) == 0 {
		t.Fatalf("内置词表未加载: sub=%d dir=%d", len(cfg.Subdomains), len(cfg.Directories))
	}
	if cfg.Ports == nil || cfg.CDN == nil {
		t.Fatal("内置 yaml 配置未加载")
	}

	dest := t.TempDir()
	if err := WriteEmbeddedDicts(dest); err != nil {
		t.Fatalf("展开内置字典失败: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "yaml", "ports.yaml")); err != nil {
		t.Fatalf("展开后缺少 yaml/ports.yaml: %v", err)
	}
}
