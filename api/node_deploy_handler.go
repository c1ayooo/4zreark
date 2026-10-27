package api

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/internal/creds"
	"github.com/c1ayooo/4zreark/internal/toolruntime"
	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

// DeployNode 通过 SSH 把 worker 二进制和一份只含节点密钥的配置推到目标机并启动。
// 支持密码/私钥认证、Linux/Windows 目标机、可选 SOCKS5/HTTP 代理。
// SSH 凭据只在本请求内使用，不落库、不写日志。
// POST /api/nodes/deploy
func (h *NodeHandler) DeployNode(c *gin.Context) {
	var req struct {
		Host          string   `json:"host" binding:"required"`
		Port          int      `json:"port"`
		OS            string   `json:"os"`
		Username      string   `json:"username" binding:"required"`
		Password      string   `json:"password"`
		PrivateKey    string   `json:"private_key"`
		KeyPassphrase string   `json:"key_passphrase"`
		// OverwriteFingerprint 主机重装等合法换钥场景：显式替换 known-hosts 里
		// 的旧指纹（审计 H3）。不传时指纹不匹配的连接直接拒绝。
		OverwriteFingerprint bool `json:"overwrite_fingerprint"`
		Name          string   `json:"name"`
		MaxTasks      int      `json:"max_tasks"`
		Capabilities  []string `json:"capabilities"`
		Tags          []string `json:"tags"`
		PlatformURL   string   `json:"platform_url" binding:"required"`
		Proxy         string   `json:"proxy"`
		Dir           string   `json:"dir"`
		ReverseTunnel bool     `json:"reverse_tunnel"`
		RelayPort     int      `json:"relay_port"`
		TunnelPort    int      `json:"tunnel_port"`
		PlatformPort  int      `json:"platform_port"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}

	targetOS := strings.ToLower(strings.TrimSpace(req.OS))
	if targetOS == "" {
		targetOS = "linux"
	}
	if targetOS != "linux" && targetOS != "windows" {
		utils.BadRequest(c, "目标系统只支持 linux 或 windows")
		return
	}

	host, err := normalizeSSHHost(req.Host)
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	port := req.Port
	if port <= 0 {
		port = 22
	}
	if port > 65535 {
		utils.BadRequest(c, "SSH 端口不合法")
		return
	}

	dir := strings.TrimSpace(req.Dir)
	if targetOS == "windows" {
		if dir == "" {
			dir = `C:\4zreark-worker`
		}
		dir, err = normalizeWindowsDir(dir)
	} else {
		if dir == "" {
			dir = "/opt/4zreark-worker"
		}
		err = validateLinuxDir(dir)
	}
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}

	platformURL := strings.TrimRight(strings.TrimSpace(req.PlatformURL), "/")
	if !strings.HasPrefix(platformURL, "http://") && !strings.HasPrefix(platformURL, "https://") {
		utils.BadRequest(c, "平台地址必须以 http:// 或 https:// 开头")
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = host
	}
	maxTasks := req.MaxTasks
	if maxTasks <= 0 {
		maxTasks = 5
	}
	if maxTasks > service.MaxNodeWorkers {
		maxTasks = service.MaxNodeWorkers
	}
	caps := req.Capabilities
	if len(caps) == 0 {
		caps = append([]string(nil), config.DefaultNodeCapabilities...)
	}
	proxy := strings.TrimSpace(req.Proxy)
	if proxy != "" && !strings.Contains(proxy, "://") {
		utils.BadRequest(c, "代理地址需要带协议，例如 socks5://relay:1080")
		return
	}

	reverseTunnel := req.ReverseTunnel
	relayPort := req.RelayPort
	tunnelPort := req.TunnelPort
	platformPort := req.PlatformPort
	var remKey string
	if reverseTunnel {
		if targetOS != "linux" {
			utils.BadRequest(c, "rem 反连目前只支持 Linux 目标机")
			return
		}
		if runtime.GOOS != "linux" {
			utils.BadRequest(c, "rem 反连自动化要求 Master 运行在 Linux 上")
			return
		}
		if relayPort <= 0 {
			relayPort = 18421
		}
		if tunnelPort <= 0 {
			tunnelPort = 18080
		}
		if platformPort <= 0 {
			if cfg := config.Loaded(); cfg != nil && cfg.Server.Port > 0 {
				platformPort = cfg.Server.Port
			} else {
				platformPort = 8080
			}
		}
		if relayPort > 65535 || tunnelPort > 65535 || platformPort > 65535 {
			utils.BadRequest(c, "rem/平台端口不合法")
			return
		}
		if relayPort == tunnelPort {
			utils.BadRequest(c, "relay 端口和隧道端口不能相同")
			return
		}
		remKey = "rem-" + randomHex(16)
	}

	// 节点网关走独立 TLS 端口，不复用 Web 端口。
	serverCfg := config.Loaded()
	if serverCfg == nil {
		utils.Error(c, utils.ErrCodeInternalError, "配置未加载")
		return
	}
	gatewayPort := serverCfg.Node.GatewayPort
	if gatewayPort <= 0 {
		gatewayPort = 9443
	}
	gatewayTLS, terr := service.EnsureNodeGatewayTLS(&serverCfg.Node)
	if terr != nil {
		utils.Error(c, utils.ErrCodeInternalError, "准备节点网关 TLS 失败: "+terr.Error())
		return
	}
	if reverseTunnel {
		platformPort = gatewayPort
		platformURL = fmt.Sprintf("https://127.0.0.1:%d", tunnelPort)
	} else {
		gatewayHost := strings.TrimSpace(serverCfg.Node.GatewayHost)
		if u, perr := url.Parse(platformURL); perr == nil && gatewayHost == "" {
			gatewayHost = u.Hostname()
		}
		if gatewayHost == "" {
			gatewayHost = host
		}
		platformURL = fmt.Sprintf("https://%s:%d", gatewayHost, gatewayPort)
	}
	gatewayCAPath := strings.ReplaceAll(filepath.Join(dir, "config", "node-gateway.crt"), "\\", "/")

	// 选择要上传的二进制：Linux 直接用当前进程；Windows 需要预先构建的 worker.exe。
	var (
		binary   []byte
		fileName = "worker"
	)
	if targetOS == "windows" {
		fileName = "worker.exe"
		binPath, ferr := findWindowsWorkerBinary()
		if ferr != nil {
			utils.BadRequest(c, ferr.Error())
			return
		}
		binary, err = os.ReadFile(binPath)
	} else {
		if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
			utils.BadRequest(c, "Linux 一键部署要求 Master 运行在 linux/amd64 上")
			return
		}
		exe, eerr := os.Executable()
		if eerr != nil {
			utils.Error(c, utils.ErrCodeInternalError, "读取当前二进制路径失败: "+eerr.Error())
			return
		}
		binary, err = os.ReadFile(exe)
	}
	if err != nil {
		utils.Error(c, utils.ErrCodeInternalError, "读取 worker 二进制失败: "+err.Error())
		return
	}

	// 先创建节点和密钥；部署失败会把节点记录删掉，避免留下无效节点。
	node := &models.ScannerNode{
		Name:              name,
		Description:       "SSH 一键部署（" + targetOS + "）",
		Type:              models.NodeTypeWorker,
		IP:                host,
		MaxTasks:          maxTasks,
		Capabilities:      caps,
		Tags:              req.Tags,
		HeartbeatInterval: 30,
	}
	token, err := h.nodeService.CreateNodeWithToken(node)
	if err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}
	cleanup := func() {
		_ = h.nodeService.DeleteNode(node.ID.Hex())
		if h.hub != nil {
			h.hub.CloseNode(node.NodeID)
		}
	}

	cfgYAML, err := deployConfigYAML(name, platformURL, token, proxy, maxTasks, caps, req.Tags, gatewayCAPath)
	if err != nil {
		cleanup()
		utils.Error(c, utils.ErrCodeInternalError, "生成节点配置失败: "+err.Error())
		return
	}

	auth, err := sshAuthMethods(req.Password, req.PrivateKey, req.KeyPassphrase)
	if err != nil {
		cleanup()
		utils.BadRequest(c, err.Error())
		return
	}
	// 审计 H3：SSH 部署强制验证主机身份（TOFU known-hosts），不再忽略主机密钥。
	// 首次部署记录指纹，之后不匹配即拒绝——防中间人窃取 SSH 凭据与节点 token。
	hostKeyCB, _, hkErr := creds.SSHHostKeyCallback(host, port, req.OverwriteFingerprint)
	if hkErr != nil {
		cleanup()
		utils.BadRequest(c, hkErr.Error())
		return
	}
	sshCfg := &ssh.ClientConfig{
		User:            req.Username,
		Auth:            auth,
		HostKeyCallback: hostKeyCB,
		Timeout:         15 * time.Second,
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	client, err := ssh.Dial("tcp", addr, sshCfg)
	if err != nil {
		cleanup()
		utils.BadRequest(c, "SSH 连接失败: "+err.Error())
		return
	}
	defer client.Close()

	relayStarted := false
	cleanupTunnel := func() {}
	if reverseTunnel {
		remPath, gerr := ensureTargetRem(client)
		if gerr != nil {
			cleanup()
			utils.Error(c, utils.ErrCodeInternalError, "准备 rem 失败: "+gerr.Error())
			return
		}
		link, rerr := startTargetRelay(client, host, remPath, relayPort, remKey)
		if rerr != nil {
			cleanup()
			utils.Error(c, utils.ErrCodeInternalError, rerr.Error())
			return
		}
		relayStarted = true
		if terr := startLocalRemTunnel(node.NodeID, platformPort, tunnelPort, relayPort, host, remKey, link); terr != nil {
			if relayStarted {
				stopTargetRelay(client, relayPort)
			}
			cleanup()
			utils.Error(c, utils.ErrCodeInternalError, "启动 rem 反连失败: "+terr.Error())
			return
		}
		if verr := verifyTargetTunnel(client, tunnelPort); verr != nil {
			stopLocalRemTunnel(node.NodeID)
			if relayStarted {
				stopTargetRelay(client, relayPort)
			}
			cleanup()
			utils.Error(c, utils.ErrCodeInternalError, verr.Error())
			return
		}
		cleanupTunnel = func() {
			stopLocalRemTunnel(node.NodeID)
			if relayStarted {
				stopTargetRelay(client, relayPort)
			}
		}
	}

	if err := uploadNodeFiles(client, dir, fileName, binary, []byte(cfgYAML), targetOS, gatewayTLS.CAPEM); err != nil {
		cleanupTunnel()
		cleanup()
		utils.Error(c, utils.ErrCodeInternalError, "上传节点文件失败: "+err.Error())
		return
	}

	var startCmd string
	if targetOS == "windows" {
		startCmd = windowsStartCommand(dir)
	} else {
		startCmd = linuxStartCommand(dir)
	}
	output, startErr := runSSHCommand(client, startCmd, nil, 60*time.Second)
	if startErr != nil {
		cleanupTunnel()
		cleanup()
		utils.Error(c, utils.ErrCodeInternalError,
			fmt.Sprintf("启动 worker 失败: %v\n%s", startErr, trimOutput(output, 4000)))
		return
	}

	data := gin.H{
		"node_id":     node.NodeID,
		"name":        name,
		"host":        host,
		"os":          targetOS,
		"install_dir": dir,
		"output":      trimOutput(output, 8000),
	}
	if reverseTunnel {
		data["tunnel"] = gin.H{
			"backend":      "rem",
			"relay_host":   host,
			"relay_port":   relayPort,
			"tunnel_port":  tunnelPort,
			"platform_via": platformURL,
		}
	}
	utils.SuccessWithMessage(c, "节点已部署，等待连接平台", data)
}

func sshAuthMethods(password, privateKey, passphrase string) ([]ssh.AuthMethod, error) {
	if strings.TrimSpace(privateKey) != "" {
		var (
			signer ssh.Signer
			err    error
		)
		if passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(privateKey), []byte(passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey([]byte(privateKey))
		}
		if err != nil {
			return nil, fmt.Errorf("SSH 私钥解析失败: %w", err)
		}
		return []ssh.AuthMethod{ssh.PublicKeys(signer)}, nil
	}
	if password == "" {
		return nil, fmt.Errorf("请填写 SSH 密码或私钥")
	}
	// 部分 Debian/Ubuntu 的 OpenSSH 只开放 keyboard-interactive，不开放 password。
	keyboard := ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
		answers := make([]string, len(questions))
		for i := range answers {
			answers[i] = password
		}
		return answers, nil
	})
	return []ssh.AuthMethod{ssh.Password(password), keyboard}, nil
}

func findWindowsWorkerBinary() (string, error) {
	if cfg := config.Loaded(); cfg != nil && strings.TrimSpace(cfg.Node.WindowsBinary) != "" {
		p := cfg.Node.WindowsBinary
		if _, err := os.Stat(p); err != nil {
			return "", fmt.Errorf("node.windows_binary 指向的文件不存在: %s", p)
		}
		return p, nil
	}
	exe, _ := os.Executable()
	execDir := filepath.Dir(exe)
	candidates := []string{
		filepath.Join(execDir, "worker-windows-amd64.exe"),
		filepath.Join(execDir, "..", "worker-windows-amd64.exe"),
		"worker-windows-amd64.exe",
		"bin/worker-windows-amd64.exe",
	}
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return "", fmt.Errorf("找不到 Windows worker 二进制：请先执行 GOOS=windows GOARCH=amd64 go build -o worker-windows-amd64.exe .，放到 server 同目录，或配置 node.windows_binary")
}

func uploadNodeFiles(client *ssh.Client, dir, fileName string, binary, configYAML []byte, targetOS string, caPEM []byte) error {
	sc, err := sftp.NewClient(client)
	if err != nil {
		return fmt.Errorf("建立 SFTP 失败: %w", err)
	}
	defer sc.Close()

	dir = strings.ReplaceAll(dir, "\\", "/")
	if err := sc.MkdirAll(dir + "/config"); err != nil {
		return fmt.Errorf("创建安装目录失败: %w", err)
	}
	if err := writeSFTPFile(sc, dir+"/"+fileName, binary, 0o755, targetOS == "linux"); err != nil {
		return fmt.Errorf("上传二进制失败: %w", err)
	}
	if err := writeSFTPFile(sc, dir+"/config/config.yaml", configYAML, 0o600, targetOS == "linux"); err != nil {
		return fmt.Errorf("上传配置失败: %w", err)
	}
	if len(caPEM) > 0 {
		if err := writeSFTPFile(sc, dir+"/config/node-gateway.crt", caPEM, 0o644, targetOS == "linux"); err != nil {
			return fmt.Errorf("上传节点网关证书失败: %w", err)
		}
	}
	// 字典不是启动必需，但子域/目录爆破依赖它；失败只记日志，不阻断部署。
	if err := uploadLocalDicts(sc, dir); err != nil {
		log.Printf("[Deploy] 上传字典失败（扫描仍可运行）: %v", err)
	}
	// 托管工具（gogo/spray/katana/rem）一并推送，部署完即可跑全量模块；
	// 失败只记日志——worker 之后还能经节点网关按清单自行同步。
	if err := uploadManagedTools(sc, dir, targetOS); err != nil {
		log.Printf("[Deploy] 上传扫描工具失败（worker 将按清单自行同步）: %v", err)
	}
	return nil
}

// uploadManagedTools 把 master 托管目录里的工具二进制推到 worker 的
// tools/<os>/ 下。平台上没装的工具跳过（worker 会回退 vendored/PATH，
// 或等清单同步）。
func uploadManagedTools(sc *sftp.Client, remoteDir, targetOS string) error {
	osDir := "linux"
	if targetOS == "windows" {
		osDir = "win"
	}
	remoteRoot := strings.ReplaceAll(remoteDir, "\\", "/") + "/tools/" + osDir
	if err := sc.MkdirAll(remoteRoot); err != nil {
		return err
	}
	mgr := toolruntime.Default()
	for _, name := range toolruntime.SpecNames() {
		path := mgr.BinaryPath(name)
		if path == "" {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		bin := name
		if osDir == "win" {
			bin += ".exe"
		}
		if err := writeSFTPFile(sc, remoteRoot+"/"+bin, data, 0o755, osDir == "linux"); err != nil {
			return fmt.Errorf("上传 %s 失败: %w", name, err)
		}
		log.Printf("[Deploy] 已推送工具 %s（%d 字节）", name, len(data))
	}
	return nil
}

// uploadLocalDicts 把 Master 的 config/dicts 一并推到 worker，避免子域/目录爆破被跳过。
// 磁盘目录不存在时使用二进制内置字典，因此单文件部署也能带全词表。
func uploadLocalDicts(sc *sftp.Client, remoteDir string) error {
	remoteRoot := strings.ReplaceAll(remoteDir, "\\", "/") + "/config/dicts"
	if err := sc.MkdirAll(remoteRoot); err != nil {
		return err
	}
	local := findLocalDictsDir()
	if local == "" {
		return uploadEmbeddedDicts(sc, remoteRoot)
	}
	return filepath.WalkDir(local, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(local, p)
		if err != nil || rel == "." {
			return err
		}
		remote := remoteRoot + "/" + strings.ReplaceAll(rel, "\\", "/")
		if d.IsDir() {
			return sc.MkdirAll(remote)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if dir := path.Dir(remote); dir != "." {
			if err := sc.MkdirAll(dir); err != nil {
				return err
			}
		}
		return writeSFTPFile(sc, remote, data, 0o644, false)
	})
}

// uploadEmbeddedDicts 从 go:embed 字典树直接推到 worker。
func uploadEmbeddedDicts(sc *sftp.Client, remoteRoot string) error {
	embedded := config.EmbeddedDicts()
	return fs.WalkDir(embedded, "dicts", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel := strings.TrimPrefix(strings.TrimPrefix(p, "dicts"), "/")
		if rel == "" {
			return nil
		}
		remote := remoteRoot + "/" + rel
		if d.IsDir() {
			return sc.MkdirAll(remote)
		}
		data, err := fs.ReadFile(embedded, p)
		if err != nil {
			return err
		}
		if dir := path.Dir(remote); dir != "." {
			if err := sc.MkdirAll(dir); err != nil {
				return err
			}
		}
		return writeSFTPFile(sc, remote, data, 0o644, false)
	})
}

func findLocalDictsDir() string {
	candidates := []string{config.GetDictBasePath(), "config/dicts", "../config/dicts"}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "..", "config", "dicts"))
	}
	for _, p := range candidates {
		if p == "" {
			continue
		}
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			return p
		}
	}
	return ""
}

func writeSFTPFile(sc *sftp.Client, path string, data []byte, mode os.FileMode, chmod bool) error {
	f, err := sc.Create(path)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if chmod {
		if err := sc.Chmod(path, mode); err != nil {
			return err
		}
	}
	return nil
}

func linuxStartCommand(dir string) string {
	q := shellQuote(dir)
	return "cd " + q + " && chmod 755 worker" +
		" && rm -f worker.pid" +
		" && (nohup ./worker >> worker.log 2>&1 & echo $! > worker.pid)" +
		" && sleep 2 && if kill -0 $(cat worker.pid) 2>/dev/null; then echo WORKER_STARTED; else echo WORKER_FAILED; tail -n 40 worker.log; fi"
}

func windowsStartCommand(dir string) string {
	d := strings.ReplaceAll(dir, "\\", "/")
	script := "Set-Location '" + d + "'; " +
		"Remove-Item -Force -ErrorAction SilentlyContinue worker.log,worker.err.log; " +
		"$p = Start-Process -FilePath '.\\worker.exe' -WorkingDirectory '" + d + "' -WindowStyle Hidden -PassThru " +
		"-RedirectStandardOutput '" + d + "/worker.log' -RedirectStandardError '" + d + "/worker.err.log'; " +
		"Start-Sleep -Seconds 2; " +
		"if (Get-Process -Id $p.Id -ErrorAction SilentlyContinue) { 'WORKER_STARTED' } else { 'WORKER_FAILED'; Get-Content '" + d + "/worker.err.log' -Tail 40 }"
	return `powershell -NoProfile -Command "` + script + `"`
}

func normalizeSSHHost(raw string) (string, error) {
	host := strings.TrimSpace(raw)
	host = strings.TrimPrefix(host, "ssh://")
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimPrefix(host, "https://")
	if i := strings.IndexAny(host, "/?#"); i >= 0 {
		host = host[:i]
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if host == "" {
		return "", fmt.Errorf("SSH 主机不能为空")
	}
	if strings.ContainsAny(host, " \t\r\n'\"`$;|&<>") {
		return "", fmt.Errorf("SSH 主机包含非法字符")
	}
	if net.ParseIP(host) == nil {
		if !regexp.MustCompile(`^[A-Za-z0-9.-]+$`).MatchString(host) {
			return "", fmt.Errorf("SSH 主机格式不合法")
		}
	}
	return host, nil
}

func validateLinuxDir(dir string) error {
	if !strings.HasPrefix(dir, "/") {
		return fmt.Errorf("安装目录必须是绝对路径")
	}
	if strings.Contains(dir, "..") {
		return fmt.Errorf("安装目录不能包含 ..")
	}
	if !regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`).MatchString(dir) {
		return fmt.Errorf("安装目录只能包含字母、数字、点、下划线、斜杠")
	}
	return nil
}

func normalizeWindowsDir(dir string) (string, error) {
	p := strings.ReplaceAll(strings.TrimSpace(dir), "\\", "/")
	p = strings.TrimRight(p, "/")
	if strings.Contains(p, "..") {
		return "", fmt.Errorf("安装目录不能包含 ..")
	}
	if !regexp.MustCompile(`^[A-Za-z]:/[A-Za-z0-9._/-]+$`).MatchString(p) {
		return "", fmt.Errorf(`Windows 安装目录格式应为 C:\4zreark-worker`)
	}
	return p, nil
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func deployConfigYAML(name, platformURL, token, proxy string, maxTasks int, caps, tags []string, platformCA string) (string, error) {
	nodeCfg := map[string]interface{}{
		"role":               config.NodeRoleWorker,
		"platform_url":       platformURL,
		"token":              token,
		"name":               name,
		"max_tasks":          maxTasks,
		"heartbeat_interval": 30,
		"capabilities":       caps,
		"tags":               tags,
	}
	if proxy != "" {
		nodeCfg["proxy"] = proxy
	}
	if platformCA != "" {
		nodeCfg["platform_ca"] = platformCA
	}
	data, err := yaml.Marshal(map[string]interface{}{"node": nodeCfg})
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func runSSHCommand(client *ssh.Client, cmd string, stdin []byte, timeout time.Duration) (string, error) {
	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()

	var buf bytes.Buffer
	sess.Stdout = &buf
	sess.Stderr = &buf
	if stdin != nil {
		sess.Stdin = bytes.NewReader(stdin)
	}

	done := make(chan error, 1)
	go func() {
		done <- sess.Run(cmd)
	}()
	select {
	case err := <-done:
		return buf.String(), err
	case <-time.After(timeout):
		_ = sess.Close()
		return buf.String(), fmt.Errorf("命令超时（%s）", timeout)
	}
}

func trimOutput(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[len(s)-max:]
}

func randomHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(buf)
}
