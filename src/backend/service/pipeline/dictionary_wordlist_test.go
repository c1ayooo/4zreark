package pipeline

import (
	"context"
	"testing"
)

func TestDirScanModuleUsesConfiguredWordlist(t *testing.T) {
	m := NewDirScanModule(context.Background(), nil, 1, []string{"/tmp/custom-dir.txt"})
	if len(m.wordlist) != 1 || m.wordlist[0] != "/tmp/custom-dir.txt" {
		t.Fatalf("目录扫描模块未接收自定义词表: %+v", m.wordlist)
	}
}

func TestSubdomainModuleUsesConfiguredWordlist(t *testing.T) {
	cfg := DefaultSubdomainScanConfig()
	cfg.Wordlist = []string{"www", "api"}
	m := NewSubdomainScanModuleWithConfig(context.Background(), nil, cfg)
	if m.config == nil || len(m.config.Wordlist) != 2 {
		t.Fatalf("子域模块未接收自定义词表: %+v", m.config)
	}
}
