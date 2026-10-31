package browser

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 探活：文件存在 ≠ 能用。合格候选通过；snap 式坏 stub（运行即报错）与
// 无执行位候选淘汰——此前 crawler 的检测只查 LookPath，坏 stub 会误报可用。
func TestProbeChrome(t *testing.T) {
	if testing.Short() {
		t.Skip("short 模式跳过进程探活")
	}
	dir := t.TempDir()

	good := filepath.Join(dir, "good-chrome")
	if err := os.WriteFile(good, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if !ProbeChrome(good) {
		t.Fatal("可正常 --version 的候选应通过")
	}

	bad := filepath.Join(dir, "bad-chrome")
	if err := os.WriteFile(bad, []byte("#!/bin/sh\necho 'requires snap' >&2\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if ProbeChrome(bad) {
		t.Fatal("运行即失败的候选不应通过")
	}

	noexec := filepath.Join(dir, "noexec-chrome")
	if err := os.WriteFile(noexec, []byte("#!/bin/sh\nexit 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if ProbeChrome(noexec) {
		t.Fatal("无执行位候选不应通过")
	}
}

// 候选枚举：环境变量（ZRE_CHROME > ZRE_XLB_CHROME 兼容名）排最前。
func TestCandidatesEnvFirst(t *testing.T) {
	t.Setenv("ZRE_CHROME", "/custom/chrome")
	got := Candidates()
	if len(got) == 0 || got[0] != "/custom/chrome" {
		t.Fatalf("ZRE_CHROME 候选应排首位: %v", got[:1])
	}
	if len(got) < 2 {
		t.Fatal("除环境变量外应还有标准位/PATH 候选")
	}
}

func TestCandidatesLegacyEnvCompat(t *testing.T) {
	t.Setenv("ZRE_XLB_CHROME", "/legacy/chrome")
	got := Candidates()
	if len(got) == 0 || got[0] != "/legacy/chrome" {
		t.Fatalf("兼容名 ZRE_XLB_CHROME 应被识别: %v", got[:1])
	}
}

// 缺失提示：含三条可操作路径（安装 / 环境变量 / 替代方式）。
func TestMissingErrorActionable(t *testing.T) {
	msg := MissingError("测试用途").Error()
	for _, want := range []string{"测试用途", "ZRE_CHROME", "apt install", "替代"} {
		if !strings.Contains(msg, want) {
			t.Errorf("缺失提示应含 %q: %s", want, msg)
		}
	}
}
