package creds

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TOFU 语义：首次记录、后续强校验、mismatch 拒绝、overwrite 显式替换。
func TestSSHHostKeyCallbackTOFU(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ZRE_DATA_DIR", dir)

	key1, err := GenerateTestHostKey()
	if err != nil {
		t.Fatal(err)
	}
	key2, err := GenerateTestHostKey()
	if err != nil {
		t.Fatal(err)
	}
	addr := fakeAddr("10.0.0.9:22")

	// 首次连接：TOFU 记录，通过
	cb, _, err := SSHHostKeyCallback("node1", 22, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := cb("node1:22", addr, key1); err != nil {
		t.Fatalf("首次连接应记录并放行: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "ssh_known_hosts.json")); err != nil {
		t.Fatalf("known-hosts 文件应落盘: %v", err)
	}

	// 同指纹：放行
	if err := cb("node1:22", addr, key1); err != nil {
		t.Fatalf("同指纹应放行: %v", err)
	}

	// 换指纹：拒绝（中间人/重装）
	if err := cb("node1:22", addr, key2); err == nil {
		t.Fatalf("指纹不匹配应拒绝")
	} else if !strings.Contains(err.Error(), "指纹不匹配") {
		t.Fatalf("错误信息应说明指纹不匹配: %v", err)
	}
	// 目录外文件不被触碰（恶意 hostname 已由 JoinHostPort 规避，这里验证记录只在该主机条目）
	kh, _ := loadKnownHosts()
	if len(kh.Entries) != 1 {
		t.Fatalf("记录应只有 node1 一条: %v", kh.Entries)
	}

	// overwrite：显式替换后新指纹放行
	cb2, _, err := SSHHostKeyCallback("node1", 22, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := cb2("node1:22", addr, key2); err != nil {
		t.Fatalf("overwrite 后应放行新指纹: %v", err)
	}
	// 替换后旧指纹反而不匹配
	cb3, _, _ := SSHHostKeyCallback("node1", 22, false)
	if err := cb3("node1:22", addr, key1); err == nil {
		t.Fatalf("替换后旧指纹应拒绝")
	}
}

type fakeAddr string

func (f fakeAddr) Network() string { return "tcp" }
func (f fakeAddr) String() string  { return string(f) }
