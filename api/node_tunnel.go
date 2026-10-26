package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/internal/toolruntime"
	"github.com/c1ayooo/4zreark/service"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// rem 反向隧道（gost 退役后的唯一部署隧道）：
//
//	目标机:  rem -s tcp://0.0.0.0:<relayPort> -k <key>          （SSH nohup 拉起）
//	master:  rem -c <LINK> -r port://127.0.0.1:<tunnelPort>/127.0.0.1:<platformPort>
//
// LINK 是目标机 rem 服务端打印的带 wrapper 加密参数的完整链接，从其日志提取；
// worker 连 https://127.0.0.1:<tunnelPort>，流量经隧道回 master 拨节点网关。
// 反向转发的可用性依赖 fork 补丁（/home/c1ay/rem，commit fix: 反向端口转发），
// 官方 v0.3.0 数据面不通；toolruntime 分发的 rem 二进制必须是含补丁的构建。

// remTunnelInfo 记录平台侧隧道客户端进程，节点删除/吊销时据此停止隧道。
// 文件权限 0600，Link 里含通道密钥与 wrapper 参数。
type remTunnelInfo struct {
	PID          int       `json:"pid"`
	NodeID       string    `json:"node_id"`
	PlatformPort int       `json:"platform_port"`
	TunnelPort   int       `json:"tunnel_port"`
	RelayPort    int       `json:"relay_port"`
	RelayHost    string    `json:"relay_host"`
	Key          string    `json:"key"`
	Link         string    `json:"link"`
	LogPath      string    `json:"log_path"`
	CreatedAt    time.Time `json:"created_at"`
}

func tunnelDir() string {
	if cfg := config.Loaded(); cfg != nil && strings.TrimSpace(cfg.Node.TunnelDir) != "" {
		return cfg.Node.TunnelDir
	}
	return filepath.Join(os.TempDir(), "4zreark-tunnels")
}

func tunnelFilePath(nodeID string) string {
	return filepath.Join(tunnelDir(), nodeID+".json")
}

func findRemBinary() (string, error) {
	if cfg := config.Loaded(); cfg != nil && strings.TrimSpace(cfg.Node.RemBinary) != "" {
		p := cfg.Node.RemBinary
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
		return "", fmt.Errorf("node.rem_binary 指向的文件不存在: %s", p)
	}
	// toolruntime 托管优先（data/tools 下的受管版本，带校验与回滚）
	if p := toolruntime.Default().ResolveToolPath("rem"); p != "" {
		return p, nil
	}
	exe, _ := os.Executable()
	for _, p := range []string{"/tmp/rem", filepath.Join(filepath.Dir(exe), "rem"), filepath.Join(filepath.Dir(exe), "..", "rem")} {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return "", fmt.Errorf("找不到 rem 二进制：请先经工具运行时安装（POST /api/tools/rem/update），或配置 node.rem_binary")
}

// ensureTargetRem 确认目标机有 rem；没有就上传平台侧 rem（约 3MB，远小于 gost）。
func ensureTargetRem(client *ssh.Client) (string, error) {
	candidates := []string{"/usr/local/bin/rem", "/usr/bin/rem", "/opt/rem/rem", "/root/rem"}
	if sc, err := sftp.NewClient(client); err == nil {
		for _, p := range candidates {
			if _, err := sc.Stat(p); err == nil {
				_ = sc.Close()
				return p, nil
			}
		}
		_ = sc.Close()
	}

	local, err := findRemBinary()
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(local)
	if err != nil {
		return "", fmt.Errorf("读取本地 rem 失败: %w", err)
	}
	sc, err := sftp.NewClient(client)
	if err != nil {
		return "", fmt.Errorf("建立 SFTP 失败: %w", err)
	}
	defer sc.Close()
	if err := sc.MkdirAll("/usr/local/bin"); err != nil {
		return "", fmt.Errorf("创建 /usr/local/bin 失败: %w", err)
	}
	if err := writeSFTPFile(sc, "/usr/local/bin/rem", data, 0o755, true); err != nil {
		return "", fmt.Errorf("上传 rem 失败: %w", err)
	}
	return "/usr/local/bin/rem", nil
}

var remLinkRe = regexp.MustCompile(`tcp://[^\s,]+wrapper=[^\s,]+`)

// startTargetRelay 在目标机启动（或复用）rem 服务端，并从其日志提取
// 带 wrapper 的完整 LINK。LINK 是 master 侧 -c 的唯一入参，服务端每次
// 重启都会重新生成，所以必须现场提取而不是持久化复用。
func startTargetRelay(client *ssh.Client, relayHost, remPath string, relayPort int, key string) (link string, err error) {
	pidFile := fmt.Sprintf("/var/run/rem-relay-%d.pid", relayPort)
	logFile := fmt.Sprintf("/var/log/rem-relay-%d.log", relayPort)

	startCmd := "mkdir -p /var/log /var/run" +
		"; if [ -f " + shellQuote(pidFile) + " ] && kill -0 \"$(cat " + shellQuote(pidFile) + ")\" 2>/dev/null; then exit 0; fi" +
		"; nohup " + shellQuote(remPath) + " -s " + shellQuote("tcp://0.0.0.0:"+strconv.Itoa(relayPort)) +
		" -k " + shellQuote(key) + " > " + shellQuote(logFile) + " 2>&1 < /dev/null & echo $! > " + shellQuote(pidFile)
	if _, serr := runSSHCommand(client, startCmd, nil, 20*time.Second); serr != nil {
		return "", fmt.Errorf("启动目标机 rem 失败: %w", serr)
	}

	addr := net.JoinHostPort(relayHost, strconv.Itoa(relayPort))
	for i := 0; i < 10; i++ {
		time.Sleep(time.Second)
		// 服务端日志里抓 LINK（wrapper 参数就绪即代表监听可用）
		out, _ := runSSHCommand(client, "cat "+shellQuote(logFile)+" 2>/dev/null", nil, 10*time.Second)
		if m := remLinkRe.FindString(out); m != "" {
			if conn, derr := net.DialTimeout("tcp", addr, 2*time.Second); derr == nil {
				_ = conn.Close()
				return m, nil
			}
		}
		if conn, derr := net.DialTimeout("tcp", addr, 2*time.Second); derr == nil {
			_ = conn.Close()
			// 端口已开但 LINK 未出现：再给一轮日志落盘时间
			continue
		}
	}
	tailOut, _ := runSSHCommand(client, "tail -n 30 "+shellQuote(logFile), nil, 10*time.Second)
	return "", fmt.Errorf("目标机 rem relay 未就绪（检查云安全组/端口占用 %s）:\n%s", addr, trimOutput(tailOut, 3000))
}

func stopTargetRelay(client *ssh.Client, relayPort int) {
	pidFile := fmt.Sprintf("/var/run/rem-relay-%d.pid", relayPort)
	_, _ = runSSHCommand(client, "if [ -f "+shellQuote(pidFile)+" ]; then kill \"$(cat "+shellQuote(pidFile)+")\" 2>/dev/null; rm -f "+shellQuote(pidFile)+"; fi", nil, 15*time.Second)
}

// verifyTargetTunnel 从目标机本机访问 https://127.0.0.1:<tunnelPort>/health，确认反向隧道真的通到节点网关。
func verifyTargetTunnel(client *ssh.Client, tunnelPort int) error {
	probe := fmt.Sprintf("https://127.0.0.1:%d/health", tunnelPort)
	cmd := "if command -v curl >/dev/null 2>&1; then curl -sk -m 5 " + shellQuote(probe) +
		"; elif command -v wget >/dev/null 2>&1; then wget --no-check-certificate -qO- -T 5 " + shellQuote(probe) +
		"; else ss -ltn | grep -q " + shellQuote(":"+strconv.Itoa(tunnelPort)+" ") + " && echo '{\"status\":\"ok\"}'; fi"

	var last string
	for i := 0; i < 5; i++ {
		out, _ := runSSHCommand(client, cmd, nil, 20*time.Second)
		last = out
		if strings.Contains(out, `"status":"ok"`) {
			return nil
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("隧道未打通，目标机访问 https://127.0.0.1:%d/health 失败:\n%s", tunnelPort, trimOutput(last, 2000))
}

// startLocalRemTunnel 在平台侧启动 rem 客户端：
// 目标机监听 127.0.0.1:tunnelPort，通过 relay 反连到平台 127.0.0.1:platformPort。
func startLocalRemTunnel(nodeID string, platformPort, tunnelPort, relayPort int, relayHost, key, link string) error {
	remPath, err := findRemBinary()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(tunnelDir(), 0o700); err != nil {
		return fmt.Errorf("创建隧道目录失败: %w", err)
	}
	logPath := filepath.Join(tunnelDir(), nodeID+".log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("打开隧道日志失败: %w", err)
	}

	cmd := exec.Command(remPath,
		"-c", link,
		"-r", fmt.Sprintf("port://127.0.0.1:%d/127.0.0.1:%d", tunnelPort, platformPort),
	)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	detachCmd(cmd)
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return fmt.Errorf("启动本地 rem 失败: %w", err)
	}
	pid := cmd.Process.Pid
	// 子进程在独立会话里运行；用 Wait 回收，避免停止后留下 zombie。
	go func() { _ = cmd.Wait() }()
	_ = logFile.Close()

	info := remTunnelInfo{
		PID: pid, NodeID: nodeID, PlatformPort: platformPort, TunnelPort: tunnelPort,
		RelayPort: relayPort, RelayHost: relayHost, Key: key, Link: link,
		LogPath: logPath, CreatedAt: time.Now(),
	}
	data, _ := json.Marshal(info)
	if err := os.WriteFile(tunnelFilePath(nodeID), data, 0o600); err != nil {
		_ = terminateProcess(pid)
		return fmt.Errorf("写入隧道记录失败: %w", err)
	}

	time.Sleep(2 * time.Second)
	if !processAlive(pid) {
		logTail := readFileTail(logPath, 3000)
		_ = os.Remove(tunnelFilePath(nodeID))
		return fmt.Errorf("本地 rem 已退出:\n%s", logTail)
	}
	return nil
}

// stopLocalRemTunnel 在节点删除/吊销时停止平台侧隧道客户端。
func stopLocalRemTunnel(nodeID string) {
	path := tunnelFilePath(nodeID)
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var info remTunnelInfo
	_ = json.Unmarshal(data, &info)
	if info.PID > 0 && processAlive(info.PID) {
		_ = terminateProcess(info.PID)
		for i := 0; i < 30; i++ {
			if !processAlive(info.PID) {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	_ = os.Remove(path)
	if info.LogPath != "" {
		_ = os.Remove(info.LogPath)
	}
}

func readFileTail(path string, max int) string {
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

// RestoreRemTunnels 在平台启动时恢复已有的 rem 反连隧道：
//   - 进程还活着且 cmdline 匹配：跳过；
//   - 进程已死：用记录里的 LINK 重新拉起（目标机服务端没重启过才有效）；
//   - 节点已删除/吊销：停掉进程并清掉记录。
//
// 记录目录默认 /tmp/4zreark-tunnels，可用 node.tunnel_dir 指到持久目录以跨主机重启恢复。
func RestoreRemTunnels() {
	dir := tunnelDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	nodes := service.NewNodeService()
	restored := 0

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var info remTunnelInfo
		if err := json.Unmarshal(data, &info); err != nil {
			continue
		}
		nodeID := info.NodeID
		if nodeID == "" {
			nodeID = strings.TrimSuffix(e.Name(), ".json")
		}

		node, err := nodes.GetNodeByID(nodeID)
		if err != nil || node.TokenHash == "" || node.RevokedAt != nil {
			stopLocalRemTunnel(nodeID)
			continue
		}

		marker := fmt.Sprintf("port://127.0.0.1:%d", info.TunnelPort)
		if info.PID > 0 && processAlive(info.PID) && processMatches(info.PID, marker) {
			continue
		}

		if err := startLocalRemTunnel(nodeID, info.PlatformPort, info.TunnelPort, info.RelayPort, info.RelayHost, info.Key, info.Link); err != nil {
			log.Printf("[rem] 恢复节点 %s 的隧道失败（目标机 rem 服务端可能已重启，需重新部署）: %v", nodeID, err)
			continue
		}
		restored++
		log.Printf("[rem] 已恢复节点 %s 的隧道（127.0.0.1:%d -> %s:%d）",
			nodeID, info.TunnelPort, info.RelayHost, info.RelayPort)
	}
	if restored > 0 {
		log.Printf("[rem] 启动恢复完成，共恢复 %d 条隧道", restored)
	}
}
