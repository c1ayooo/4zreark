package toolruntime

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestRemReverseForwardVerdict 是 rem 替换 gost（api/node_tunnel.go）的换装判定测试。
//
// 2026-10-22 对 rem v0.3.0 的实测结论（9 组回环实验）：gost
// `-L rtcp://127.0.0.1:LOCAL/127.0.0.1:DEST` + `-F relay://HOST:PORT?bind=true`
// 的反向语义（对端开监听、流量回本端拨 DEST）在 rem v0.3.0 所有文档语法下
// 均无法走通数据面：
//   - `-c LINK -r port://A -l raw://B`：对端注册 portforward 但不实际监听 A，
//     本端把 B 当 raw 监听去 bind（与被转发的真实服务端口冲突）；
//   - `-c LINK -r port://A -l :B`：裸地址被解析成本端 socks5 监听并 bind B；
//   - `-c LINK -r port://A/B`：对端监听 A，但目标解析为 0.0.0.0:0，无数据；
//   - 服务端 `-s ... -l port://A/B`：解析失败，回落默认 socks5。
//
// 因此 node_tunnel.go 保留 gost（已收编 toolruntime：版本 pin + checksums）。
// 上游（chainreactors/rem）发布新版本后，重跑本测试：
//
//	ZRE_REM_BIN=/path/to/rem go test ./internal/toolruntime/ -run TestRemReverseForwardVerdict -v
//
// 通过（PASS）即代表可以改写 node_tunnel.go 换装 rem。
//
// 测试自带 HTTP 后端（127.0.0.1:BACKEND），全回环，不打外网。
func TestRemReverseForwardVerdict(t *testing.T) {
	if os.Getenv("ZRE_REM_VERDICT") != "1" {
		t.Skip("换装判定测试，显式运行：ZRE_REM_VERDICT=1 go test ./internal/toolruntime/ -run TestRemReverseForwardVerdict -v")
	}
	bin := os.Getenv("ZRE_REM_BIN")
	if bin == "" {
		if p := Default().ResolveToolPath("rem"); p != "" {
			bin = p
		}
	}
	if bin == "" {
		t.Skip("rem 二进制不可用；安装后重跑（POST /api/tools/rem/update 或 ZRE_REM_BIN 指定路径）")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("需要 python3 起本地回环 HTTP 后端")
	}

	dir := t.TempDir()
	webRoot := filepath.Join(dir, "www")
	os.MkdirAll(webRoot, 0o755)
	os.WriteFile(filepath.Join(webRoot, "index.html"), []byte("rem-verdict-ok"), 0o644)

	// 后端 HTTP 服务（等价 master 的 :9443 网关）
	backend := startBackendHTTP(t, webRoot)

	const relayPort = 39391
	const tunnelPort = 39392
	key := "zre-verdict-key"

	// 目标机侧：rem 服务端（等价目标机上的 relay 监听）
	srvLog := filepath.Join(dir, "srv.log")
	srv := startBg(t, bin, []string{"-s", fmt.Sprintf("tcp://127.0.0.1:%d", relayPort), "-k", key}, srvLog)
	defer srv.Process.Kill()

	waitTCP(t, relayPort, 5*time.Second)

	link := extractLink(t, srvLog)
	if link == "" {
		t.Fatalf("未从 rem 服务端日志提取到 link（wrapper 变量可能已改名）:\n%s", readFileTail2(srvLog, 2000))
	}

	// master 侧：反向端口转发——对端(目标机)在 tunnelPort 开监听，
	// 流量回来后本端拨 backend。
	cliLog := filepath.Join(dir, "cli.log")
	cli := startBg(t, bin, []string{"-c", link,
		"-r", fmt.Sprintf("port://127.0.0.1:%d/%s", tunnelPort, backend)}, cliLog)
	defer cli.Process.Kill()

	// 数据面判定：等监听 + 拿到后端内容
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if !portListening(tunnelPort) {
			time.Sleep(300 * time.Millisecond)
			continue
		}
		body := httpGet(t, fmt.Sprintf("http://127.0.0.1:%d/", tunnelPort), 3*time.Second)
		if strings.Contains(body, "rem-verdict-ok") {
			t.Logf("rem 反向转发数据面走通（%d -> %s）：可以换装 node_tunnel.go", tunnelPort, backend)
			return
		}
	}
	t.Fatalf("rem 反向端口转发未走通（无监听或无数据）。服务端日志:\n%s\n客户端日志:\n%s",
		readFileTail2(srvLog, 1500), readFileTail2(cliLog, 1500))
}

func startBg(t *testing.T, bin string, args []string, logPath string) *exec.Cmd {
	t.Helper()
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, args...)
	cmd.Stdout = f
	cmd.Stderr = f
	if err := cmd.Start(); err != nil {
		f.Close()
		t.Fatalf("启动 %s 失败: %v", bin, err)
	}
	go func() { _ = cmd.Wait(); _ = f.Close() }()
	return cmd
}

// startBackendHTTP 在预选空闲端口上起本地回环 HTTP 后端，返回 host:port。
// 不解析 python 的启动横幅（非 TTY 下有缓冲，读完会永久阻塞）。
func startBackendHTTP(t *testing.T, root string) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close() // 小概率竞态，测试可容忍

	cmd := exec.Command("python3", "-m", "http.server", strings.SplitN(addr, ":", 2)[1],
		"--bind", "127.0.0.1", "--directory", root)
	if err := cmd.Start(); err != nil {
		t.Fatalf("启动 python http.server 失败: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	waitTCP(t, mustPort(t, addr), 5*time.Second)
	return addr
}

func mustPort(t *testing.T, addr string) int {
	t.Helper()
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := strconv.Atoi(port)
	return n
}

func waitTCP(t *testing.T, port int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("端口 %d 未监听", port)
}

func portListening(port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func httpGet(t *testing.T, url string, timeout time.Duration) string {
	t.Helper()
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	return string(buf[:n])
}

// extractLink 从 rem 服务端日志提取带 wrapper 的完整 link。
func extractLink(t *testing.T, logPath string) string {
	data, err := os.ReadFile(logPath)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		for _, field := range strings.Fields(line) {
			if strings.HasPrefix(field, "tcp://") && strings.Contains(field, "wrapper=") {
				return strings.TrimSuffix(field, ",")
			}
		}
	}
	return ""
}

func readFileTail2(path string, max int) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	s := string(data)
	if len(s) > max {
		s = s[len(s)-max:]
	}
	return s
}
