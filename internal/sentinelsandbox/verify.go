// 靶场验证沙箱：与差分沙箱（sandbox.go）并列的第二种执行形态。
//
// 差分沙箱 --network none，验证「同一段 PoC 在漏洞版崩、修复版不崩」；
// 这边要验证的是「PoC 对真实漏洞环境是否有效」：拉公开靶场镜像起服务，
// 把 PoC 放进同一隔离内网打它。安全边界：
//   - 靶场与 PoC 容器同处一个 docker --internal 网络：容器间可通、无外网出口，
//     PoC 不可能借验证之名探测外网；
//   - 不挂载宿主任何目录（PoC 仍走 WritePoc 只读挂载 /poc）；
//   - AI 只提供镜像名/env/端口/URL 等声明式参数，docker 参数由本文件机械拼装，
//     镜像白名单与 env/target_url 校验在 service 层（sentinel_pocverify.go）。
package sentinelsandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// targetHostName 是靶场容器在隔离网络里的固定主机名：EnvPlan 的 target_url
// 必须指向它，PoC 才打得到靶场、也只打得到靶场。
const TargetHostName = "pocverify-target"

// VerifySandbox 是一台 docker 宿主上的靶场验证沙箱。
type VerifySandbox struct {
	// Workdir 是 PoC 文件的宿主目录（与差分沙箱共用布局：容器内只读 /poc）。
	Workdir string
}

// WritePoc 把 PoC 内容写进沙箱 Workdir（宿主侧，容器内只读可见）。
func (s *VerifySandbox) WritePoc(name, content string) error {
	if strings.ContainsAny(name, "/\\") || strings.TrimSpace(name) == "" {
		return errors.New("PoC 文件名非法")
	}
	return osWriteFile(s.Workdir+"/"+name, []byte(content), 0o600)
}

// FindNucleiBinary 定位宿主上的 nuclei 二进制：PATH → 项目内 data/nuclei/bin
// （vulnscan 运行时自动下载位置）→ 用户目录常见安装位。找不到返回空串。
func FindNucleiBinary() string {
	if p, err := exec.LookPath("nuclei"); err == nil {
		return p
	}
	if st, err := os.Stat("data/nuclei/bin/nuclei"); err == nil && !st.IsDir() {
		return "data/nuclei/bin/nuclei"
	}
	if home, err := os.UserHomeDir(); err == nil {
		for _, p := range []string{
			filepath.Join(home, "go", "bin", "nuclei"),
			filepath.Join(home, ".local", "bin", "nuclei"),
			"/usr/local/bin/nuclei",
		} {
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				return p
			}
		}
	}
	return ""
}

// EnsureNucleiBinary 把项目内部 nuclei 二进制复制进沙箱 workdir（容器内
// /poc/nuclei 只读可见、宿主侧已 chmod 可执行）。安全模型不变：nuclei 与
// PoC 同处只读 /poc，目标只有同内网的靶场容器；不为此拉取任何第三方镜像。
func (s *VerifySandbox) EnsureNucleiBinary(src string) (string, error) {
	if src == "" {
		return "", errors.New("未找到 nuclei 二进制（PATH 或 data/nuclei/bin/nuclei，可先运行一次 nuclei 扫描触发自动下载）")
	}
	in, err := os.Open(src)
	if err != nil {
		return "", fmt.Errorf("读取 nuclei 二进制失败: %w", err)
	}
	defer in.Close()
	dst := s.Workdir + "/nuclei"
	out, err := os.Create(dst)
	if err != nil {
		return "", fmt.Errorf("写入沙箱 nuclei 失败: %w", err)
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return "", fmt.Errorf("复制 nuclei 二进制失败: %w", err)
	}
	if err := out.Close(); err != nil {
		return "", err
	}
	if err := os.Chmod(dst, 0o755); err != nil {
		return "", err
	}
	return "/poc/nuclei", nil
}

// Pull 拉取靶场镜像。镜像名合法性（白名单）由调用方校验。
func (s *VerifySandbox) Pull(ctx context.Context, image string) error {
	if image == "" {
		return errors.New("缺少镜像名")
	}
	out, err := exec.CommandContext(ctx, "docker", "pull", image).CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker pull %s 失败: %w: %s", image, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// CreateNetwork 创建 --internal 隔离网络：容器间互通、无外网出口。
func (s *VerifySandbox) CreateNetwork(ctx context.Context, name string) error {
	out, err := exec.CommandContext(ctx, "docker", "network", "create", "--internal", name).CombinedOutput()
	if err != nil {
		// 并发/残留同名网络时创建失败：先删再建一次。
		_ = exec.CommandContext(ctx, "docker", "network", "rm", name).Run()
		if out2, err2 := exec.CommandContext(ctx, "docker", "network", "create", "--internal", name).CombinedOutput(); err2 != nil {
			return fmt.Errorf("docker network create 失败: %w: %s %s", err2, strings.TrimSpace(string(out)), strings.TrimSpace(string(out2)))
		}
	}
	return nil
}

// RemoveNetwork 删除隔离网络（容器已 rm 时才成功，失败仅记入错误返回）。
func (s *VerifySandbox) RemoveNetwork(ctx context.Context, name string) error {
	out, err := exec.CommandContext(ctx, "docker", "network", "rm", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker network rm 失败: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// StartService 后台起靶场容器（docker run -d --name <TargetHostName> --network <net>）。
// env 只接受 KEY=VALUE 形式，逐条转成 -e 参数；不含挂载/特权等任何高危选项。
// 返回容器 ID。
func (s *VerifySandbox) StartService(ctx context.Context, network, image string, env []string) (string, error) {
	if image == "" || network == "" {
		return "", errors.New("起靶场缺少镜像或网络")
	}
	args := []string{"run", "-d", "--rm",
		"--name", TargetHostName,
		"--network", network,
		"--memory", "1g", "--cpus", "2"}
	for _, e := range env {
		if !ValidEnv(e) {
			return "", fmt.Errorf("非法 env 项: %q", e)
		}
		args = append(args, "-e", e)
	}
	args = append(args, image)

	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("靶场容器启动失败: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

// StopService 强制移除靶场容器（cleanup 用，幂等）。
func (s *VerifySandbox) StopService(ctx context.Context) error {
	// 容器可能带 --rm 已退出：失败不算错误。
	_ = exec.CommandContext(ctx, "docker", "rm", "-f", TargetHostName).Run()
	return nil
}

// ProbeHTTP 在隔离网络内用 python 镜像探测 URL 是否可访问（靶场就绪判定）。
// 宿主访问不到 --internal 网络，探测也必须在网络内发起。
func (s *VerifySandbox) ProbeHTTP(ctx context.Context, network, pyImage, url string, timeout time.Duration) error {
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		cmd := []string{"run", "--rm", "--network", network,
			"--memory", "128m",
			pyImage, "python", "-c",
			"import urllib.request,sys; urllib.request.urlopen(sys.argv[1], timeout=5)",
			url}
		out, err := exec.CommandContext(probeCtx, "docker", cmd...).CombinedOutput()
		if err == nil {
			return nil
		}
		// 4xx/5xx 时 urlopen 抛 HTTPError——服务已应答，同样视为就绪。
		if bytes.Contains(out, []byte("HTTP Error")) {
			return nil
		}
		select {
		case <-probeCtx.Done():
			return errors.New("靶场就绪探测超时")
		case <-time.After(2 * time.Second):
		}
	}
	return errors.New("靶场就绪探测超时")
}

// RunPoC 在指定网络内执行 PoC 容器：网络从 none 换成靶场内网，其余资源
// 限制与差分沙箱一致。env 形如 TARGET=http://pocverify-target:8080/xxx。
func (s *VerifySandbox) RunPoC(ctx context.Context, network, image string, cmd, env []string) (*ExecResult, error) {
	if image == "" || network == "" {
		return nil, errors.New("执行 PoC 缺少镜像或网络")
	}
	timeout := 5 * time.Minute
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	args := []string{"run", "--rm",
		"--network", network,
		"-v", s.Workdir + ":/poc:ro",
		"--memory", "512m", "--cpus", "1"}
	for _, e := range env {
		if !ValidEnv(e) {
			return nil, fmt.Errorf("非法 env 项: %q", e)
		}
		args = append(args, "-e", e)
	}
	args = append(args, image)
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
			return nil, fmt.Errorf("PoC 容器执行失败: %w: %s", err, strings.TrimSpace(string(out)))
		}
	}
	return res, nil
}

// isValidEnv 校验 -e 参数：必须 KEY=VALUE，KEY 是 [A-Za-z_][A-Za-z0-9_]*，
// VALUE 不含换行；防把 -e 当成任意 docker 参数注入。
// ValidEnv 校验 -e 参数是否合法（KEY=VALUE，见 isValidEnv 规则）；service 层复用。
func ValidEnv(e string) bool {
	i := strings.IndexByte(e, '=')
	if i <= 0 {
		return false
	}
	if strings.ContainsAny(e, "\n\r") {
		return false
	}
	for j, c := range e[:i] {
		if j == 0 {
			if !(c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z') {
				return false
			}
			continue
		}
		if !(c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}
