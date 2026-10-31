package enterprise

import (
	"context"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func discardLogger() *log.Logger { return log.New(os.Stderr, "", 0) }

// 树穿透能力闸门：Branches/Investments 为占位空实现的数据源（qcc）必须被
// 拒绝并给出替代源指引——此前静默空转一轮后标 done（nodes=1 entities=0），
// 用户以为采集过了。
func TestWalkRejectsProviderWithoutTreeExpansion(t *testing.T) {
	c := &Collector{log: discardLogger(), store: nil}
	p := &qccProvider{}
	job := Job{Depth: 2, MaxNodes: 10}

	_, err := c.walk(context.Background(), p, job, CompanyRef{ExtID: "x", Name: "x"}, nil)
	if err == nil {
		t.Fatal("qcc 应被能力闸门拒绝")
	}
	if !strings.Contains(err.Error(), "xiaolanben") || !strings.Contains(err.Error(), "qcc") {
		t.Fatalf("错误信息应含数据源名与替代源指引: %v", err)
	}
}

// 节点配额哨兵：达到上限返回哨兵（终态转 done+提示），不再误标 error。
func TestNodeCapSentinel(t *testing.T) {
	if !NodeCapReached(errNodeCapReached) {
		t.Fatal("哨兵应被识别")
	}
	if NodeCapReached(errors.New("other")) || NodeCapReached(nil) {
		t.Fatal("普通错误/nil 不应误判")
	}
	msg := nodeCapMessage(200)
	if !strings.Contains(msg, "200") || !strings.Contains(msg, "续穿") {
		t.Fatalf("提示应含配额与续穿指引: %s", msg)
	}
}

// 浏览器探测：可执行位+可运行验证。用测试自身的二进制冒充「可用浏览器」
//（带 --version 参数运行会失败退出？——不行，probe 要求退出码 0。改为
// 用 shell 脚本验证流程：可执行且 --version 成功 → 选中；存在但不可执行/
// 运行报错 → 跳过并记录）。
func TestProbeChrome(t *testing.T) {
	if testing.Short() {
		t.Skip("short 模式跳过进程探活")
	}
	dir := t.TempDir()

	// 合格候选：--version 退出 0
	good := filepath.Join(dir, "good-chrome")
	if err := os.WriteFile(good, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if !probeChrome(good) {
		t.Fatal("可正常 --version 的候选应通过")
	}

	// snap 式坏 stub：文件存在可执行但运行即报错退出
	bad := filepath.Join(dir, "bad-chrome")
	if err := os.WriteFile(bad, []byte("#!/bin/sh\necho 'requires snap' >&2\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if probeChrome(bad) {
		t.Fatal("运行即失败的候选（坏 stub）不应通过")
	}

	// 不可执行位
	noexec := filepath.Join(dir, "noexec-chrome")
	if err := os.WriteFile(noexec, []byte("#!/bin/sh\nexit 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if probeChrome(noexec) {
		t.Fatal("无执行位候选不应通过")
	}
}

// 候选枚举：环境变量最高优先。
func TestXlbChromeCandidatesEnvFirst(t *testing.T) {
	t.Setenv("ZRE_XLB_CHROME", "/custom/chrome")
	got := xlbChromeCandidates()
	if len(got) == 0 || got[0] != "/custom/chrome" {
		t.Fatalf("环境变量候选应排首位: %v", got[:1])
	}
	// 后续至少含标准位或 PATH 查找结果
	if len(got) < 2 {
		t.Fatal("除环境变量外应还有其他候选")
	}
}
