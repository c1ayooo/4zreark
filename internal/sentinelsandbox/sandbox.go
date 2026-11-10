// Package sentinelsandbox 是 pocsmith 的 Docker 差分沙箱（v0.3 §7.6-7.9）。
//
// 与 internal/verifyrunner 的 shell-out 风格一致：直接调 docker CLI，不引 SDK。
// oracle 不做容器内哨兵——容器退出码 + 完整日志已经覆盖 §7.8 的判定输入：
// 硬崩溃规则按语言匹配日志特征，__POC_START__ 标记检测崩溃是否发生在
// PoC 入口之后（§7.9 否决 2：crash-before-poc-point 是环境问题不是漏洞）。
package sentinelsandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// PocStartMarker 是 PoC 脚本入口标记：PoC 必须在真正触发漏洞前输出它。
const PocStartMarker = "__POC_START__"

// ExecResult 是一次容器内 PoC 执行的完整证据。
type ExecResult struct {
	ExitCode int
	Log      string
	TimedOut bool
	// ReachedPocPoint：日志里出现过 __POC_START__（崩溃发生在 PoC 入口之后）。
	ReachedPocPoint bool
	// HardCrash：按 §7.8 规则判定的硬崩溃（只有硬崩溃计入复现通过）。
	HardCrash  bool
	CrashBrief string
}

// Sandbox 是一台 docker 宿主上的差分沙箱。
type Sandbox struct {
	// Workdir 是 PoC 文件的宿主目录：执行时只读挂载到容器 /poc。
	Workdir string
	// MountSource 是 docker -v 的挂载源。pocsmith 直接跑在宿主机时留空（用
	// Workdir）；跑在容器里通过 docker.sock 操作宿主 daemon（DooD）时，必须传
	// 命名卷名或宿主 daemon 能解析的路径，否则容器内路径在宿主上不存在，
	// docker 会新建一个空目录挂进 PoC 容器，PoC 文件自然读不到。
	MountSource string
	// TimeoutSeconds 是单次 PoC 执行上限（§7.8 默认 30）。
	TimeoutSeconds int
}

func pocMountSource(workdir, source string) string {
	if s := strings.TrimSpace(source); s != "" {
		return s
	}
	return workdir
}

// Available 探测 docker 可用性；pocsmith 启动与入队前置检查共用。
func Available(ctx context.Context) error {
	out, err := exec.CommandContext(ctx, "docker", "info", "--format", "{{.ServerVersion}}").CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker 不可用: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Run 在镜像里执行命令并回收 oracle 证据。pocPath 是相对 /poc 的 PoC 路径，
// 非空时先 cat 打标记行，保证 ReachedPocPoint 从 PoC 入口起算。
func (s *Sandbox) Run(ctx context.Context, image string, cmd []string) (*ExecResult, error) {
	if image == "" {
		return nil, errors.New("沙箱缺少镜像名")
	}
	timeout := time.Duration(s.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	args := []string{"run", "--rm", "--network", "none",
		"-v", pocMountSource(s.Workdir, s.MountSource) + ":/poc:ro",
		"--memory", "512m", "--cpus", "1",
		image}
	args = append(args, cmd...)

	out, err := exec.CommandContext(runCtx, "docker", args...).CombinedOutput()
	res := &ExecResult{Log: string(out)}
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			res.ExitCode = exitErr.ExitCode()
		} else if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
			res.TimedOut = true
			res.ExitCode = 124
		} else {
			return nil, fmt.Errorf("docker run 失败: %w: %s", err, strings.TrimSpace(string(out)))
		}
	}
	res.ReachedPocPoint = bytes.Contains(out, []byte(PocStartMarker))
	res.HardCrash, res.CrashBrief = classifyCrash(res.ExitCode, res.Log, res.TimedOut)
	return res, nil
}

// CopySourceTo 把 PoC 内容写进沙箱 Workdir（宿主侧，容器内只读可见）。
func (s *Sandbox) WritePoc(name, content string) error {
	if strings.ContainsAny(name, "/\\") || strings.TrimSpace(name) == "" {
		return errors.New("PoC 文件名非法")
	}
	return osWriteFile(s.Workdir+"/"+name, []byte(content), 0o600)
}

// 崩溃特征全文匹配，不锚定行首：前一命令缺尾换行时（cat 无换行输出是常态）
// panic 行会被拼到上一行末尾，行首锚定会漏判（fix 侧漏判 = 假通过，方向危险）。
// 全文匹配的误报代价只是保守否决（复现不通过），宁可漏报不误报。
var (
	reGoHard    = regexp.MustCompile(`panic: |fatal error: `)
	reSegv      = regexp.MustCompile(`(?i)(segmentation fault|sigsegv|sigbus|sigill|sigabrt|core dumped)`)
	reSanitizer = regexp.MustCompile(`(?i)(AddressSanitizer|UndefinedBehaviorSanitizer|LeakSanitizer)`)
	reJVMSig    = regexp.MustCompile(`A fatal error has been detected|OutOfMemoryError|EXCEPTION_ACCESS_VIOLATION`)
	reFatal     = regexp.MustCompile(`(?i)fatal error`)
)

// classifyCrash 实现 §7.8 的硬崩溃判定：
// 超时不算崩溃；退出码 0 永远不算；非零退出按日志特征分级——
// panic/fatal/段错误/ASAN/JVM crash 是硬崩溃，普通非零退出只是弱信号。
func classifyCrash(exitCode int, log string, timedOut bool) (bool, string) {
	if timedOut || exitCode == 0 {
		return false, ""
	}
	switch {
	case reGoHard.MatchString(log):
		return true, "go-panic"
	case reSegv.MatchString(log):
		return true, "signal-crash"
	case reSanitizer.MatchString(log):
		return true, "sanitizer"
	case reJVMSig.MatchString(log):
		return true, "jvm-crash"
	case reFatal.MatchString(log):
		return true, "fatal-error"
	}
	return false, "nonzero-exit"
}
