package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/service"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// gostTunnelInfo 记录平台侧 rtcp 客户端进程，节点删除/吊销时据此停止隧道。
// 文件权限 0600，里面含自动生成的 relay 密码。
type gostTunnelInfo struct {
	PID          int       `json:"pid"`
	NodeID       string    `json:"node_id"`
	PlatformPort int       `json:"platform_port"`
	TunnelPort   int       `json:"tunnel_port"`
	RelayPort    int       `json:"relay_port"`
	RelayHost    string    `json:"relay_host"`
	User         string    `json:"user"`
	Pass         string    `json:"pass"`
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

func findGostBinary() (string, error) {
	if cfg := config.Loaded(); cfg != nil && strings.TrimSpace(cfg.Node.GostBinary) != "" {
		p := cfg.Node.GostBinary
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
		return "", fmt.Errorf("node.gost_binary 指向的文件不存在: %s", p)
	}
	if p, err := exec.LookPath("gost"); err == nil {
		return p, nil
	}
	exe, _ := os.Executable()
	candidates := []string{
		"/tmp/gost",
		"gost",
		filepath.Join(filepath.Dir(exe), "gost"),
		filepath.Join(filepath.Dir(exe), "..", "gost"),
	}
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return "", fmt.Errorf("找不到 gost 二进制：请把 gost 放到 server 同目录、/tmp/gost，或配置 node.gost_binary")
}

// ensureTargetGost 确认目标机有 gost；没有就上传平台侧 gost。
// 用 SFTP stat 判断，避免 SSH exec 输出在某些 sshd 上偶发为空。
func ensureTargetGost(client *ssh.Client) (string, error) {
	candidates := []string{"/usr/local/bin/gost", "/usr/bin/gost", "/opt/gost/gost", "/root/gost"}
	if sc, err := sftp.NewClient(client); err == nil {
		for _, p := range candidates {
			if _, err := sc.Stat(p); err == nil {
				_ = sc.Close()
				return p, nil
			}
		}
		_ = sc.Close()
	}

	local, err := findGostBinary()
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(local)
	if err != nil {
		return "", fmt.Errorf("读取本地 gost 失败: %w", err)
	}
	sc, err := sftp.NewClient(client)
	if err != nil {
		return "", fmt.Errorf("建立 SFTP 失败: %w", err)
	}
	defer sc.Close()
	if err := sc.MkdirAll("/usr/local/bin"); err != nil {
		return "", fmt.Errorf("创建 /usr/local/bin 失败: %w", err)
	}
	if err := writeSFTPFile(sc, "/usr/local/bin/gost", data, 0o755, true); err != nil {
		return "", fmt.Errorf("上传 gost 失败: %w", err)
	}
	if _, err := sc.Stat("/usr/local/bin/gost"); err != nil {
		return "", fmt.Errorf("目标机 gost 安装后仍不可用: %w", err)
	}
	return "/usr/local/bin/gost", nil
}

func gostRelayURL(host string, port int, user, pass string) string {
	userinfo := ""
	if user != "" {
		userinfo = url.UserPassword(user, pass).String() + "@"
	}
	return fmt.Sprintf("relay://%s%s:%d?bind=true", userinfo, host, port)
}

// startTargetRelay 在目标机启动（或复用）gost relay。
// 启动后从平台直接 dial relay 端口确认可达，不依赖 SSH 命令输出。
func startTargetRelay(client *ssh.Client, relayHost, gostPath string, relayPort int, user, pass string) (bool, error) {
	urlStr := gostRelayURL("", relayPort, user, pass)
	pidFile := fmt.Sprintf("/var/run/gost-relay-%d.pid", relayPort)
	logFile := fmt.Sprintf("/var/log/gost-relay-%d.log", relayPort)

	startCmd := "mkdir -p /var/log /var/run" +
		"; if [ -f " + shellQuote(pidFile) + " ] && kill -0 \"$(cat " + shellQuote(pidFile) + ")\" 2>/dev/null; then exit 0; fi" +
		"; nohup " + shellQuote(gostPath) + " -L " + shellQuote(urlStr) + " > " + shellQuote(logFile) + " 2>&1 < /dev/null & echo $! > " + shellQuote(pidFile)
	_, _ = runSSHCommand(client, startCmd, nil, 20*time.Second)

	addr := net.JoinHostPort(relayHost, strconv.Itoa(relayPort))
	for i := 0; i < 8; i++ {
		time.Sleep(time.Second)
		conn, derr := net.DialTimeout("tcp", addr, 2*time.Second)
		if derr == nil {
			_ = conn.Close()
			return true, nil
		}
	}
	logTail, _ := runSSHCommand(client, "tail -n 30 "+shellQuote(logFile), nil, 10*time.Second)
	return false, fmt.Errorf("relay 未在 %s 监听（检查云安全组/端口占用）:\n%s", addr, trimOutput(logTail, 3000))
}

func stopTargetRelay(client *ssh.Client, relayPort int) {
	pidFile := fmt.Sprintf("/var/run/gost-relay-%d.pid", relayPort)
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
		out, err := runSSHCommand(client, cmd, nil, 20*time.Second)
		last = out
		if err == nil && strings.Contains(out, `"status":"ok"`) {
			return nil
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("隧道未打通，目标机访问 https://127.0.0.1:%d/health 失败:\n%s", tunnelPort, trimOutput(last, 2000))
}

// startLocalGostTunnel 在平台侧启动 gost rtcp 客户端：
// 目标机监听 127.0.0.1:tunnelPort，通过 relay 反连到平台 127.0.0.1:platformPort。
func startLocalGostTunnel(nodeID string, platformPort, tunnelPort, relayPort int, relayHost, user, pass string) error {
	gostPath, err := findGostBinary()
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

	cmd := exec.Command(gostPath,
		"-L", fmt.Sprintf("rtcp://127.0.0.1:%d/127.0.0.1:%d", tunnelPort, platformPort),
		"-F", gostRelayURL(relayHost, relayPort, user, pass),
	)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	detachCmd(cmd)
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return fmt.Errorf("启动本地 gost 失败: %w", err)
	}
	pid := cmd.Process.Pid
	// 子进程在独立会话里运行；用 Wait 回收，避免停止后留下 zombie。
	go func() { _ = cmd.Wait() }()
	_ = logFile.Close()

	info := gostTunnelInfo{
		PID: pid, NodeID: nodeID, PlatformPort: platformPort, TunnelPort: tunnelPort,
		RelayPort: relayPort, RelayHost: relayHost, User: user, Pass: pass,
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
		return fmt.Errorf("本地 gost 已退出:\n%s", logTail)
	}
	return nil
}

// stopLocalGostTunnel 在节点删除/吊销时停止平台侧 rtcp 客户端。
func stopLocalGostTunnel(nodeID string) {
	path := tunnelFilePath(nodeID)
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var info gostTunnelInfo
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

// RestoreGostTunnels 在平台启动时恢复已有的 gost 反连隧道：
//   - 进程还活着且 cmdline 匹配：跳过；
//   - 进程已死：用记录里的参数重新拉起；
//   - 节点已删除/吊销：停掉进程并清掉记录。
//
// 记录目录默认 /tmp/4zreark-tunnels，可用 node.tunnel_dir 指到持久目录以跨主机重启恢复。
func RestoreGostTunnels() {
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
		var info gostTunnelInfo
		if err := json.Unmarshal(data, &info); err != nil {
			continue
		}
		nodeID := info.NodeID
		if nodeID == "" {
			nodeID = strings.TrimSuffix(e.Name(), ".json")
		}

		node, err := nodes.GetNodeByID(nodeID)
		if err != nil || node.TokenHash == "" || node.RevokedAt != nil {
			stopLocalGostTunnel(nodeID)
			continue
		}

		marker := fmt.Sprintf("rtcp://127.0.0.1:%d", info.TunnelPort)
		if info.PID > 0 && processAlive(info.PID) && processMatches(info.PID, marker) {
			continue
		}

		if err := startLocalGostTunnel(nodeID, info.PlatformPort, info.TunnelPort, info.RelayPort, info.RelayHost, info.User, info.Pass); err != nil {
			log.Printf("[gost] 恢复节点 %s 的隧道失败: %v", nodeID, err)
			continue
		}
		restored++
		log.Printf("[gost] 已恢复节点 %s 的隧道（127.0.0.1:%d -> %s:%d）",
			nodeID, info.TunnelPort, info.RelayHost, info.RelayPort)
	}
	if restored > 0 {
		log.Printf("[gost] 启动恢复完成，共恢复 %d 条隧道", restored)
	}
}
