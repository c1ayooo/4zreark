package creds

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

// SSH 主机身份验证（审计 H3）：两处 SSH 出站拨号（节点部署 / 凭据探测）
// 统一走 TOFU（Trust On First Use）known-hosts：
//   - 首次连接：记录 SHA256 指纹并在响应/日志中回显，供操作者核对；
//   - 后续连接：指纹必须匹配，不匹配即拒绝（防中间人窃取凭据与节点 token）；
//   - 主机重装等合法换钥场景：overwrite 显式替换旧指纹。
// 记录存 data/ssh_known_hosts.json，随数据目录走，不入仓库。

type knownHosts struct {
	Entries map[string]string `json:"entries"`
}

func sshKnownHostsPath() string {
	root := os.Getenv("ZRE_DATA_DIR")
	if strings.TrimSpace(root) == "" {
		root = "data"
	}
	return filepath.Join(root, "ssh_known_hosts.json")
}

func loadKnownHosts() (*knownHosts, error) {
	kh := &knownHosts{Entries: map[string]string{}}
	raw, err := os.ReadFile(sshKnownHostsPath())
	if err == nil {
		_ = json.Unmarshal(raw, kh)
	}
	if kh.Entries == nil {
		kh.Entries = map[string]string{}
	}
	return kh, nil
}

func saveKnownHosts(kh *knownHosts) error {
	path := sshKnownHostsPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(kh, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

var knownHostsMu sync.Mutex

// SSHHostKeyCallback 返回 TOFU 语义的 HostKeyCallback 与（首次记录时的）指纹。
// overwrite=true 时以本次握手指纹替换已存记录（主机重装后管理员显式确认）。
func SSHHostKeyCallback(host string, port int, overwrite bool) (ssh.HostKeyCallback, string, error) {
	hostPort := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		fp := ssh.FingerprintSHA256(key)
		knownHostsMu.Lock()
		defer knownHostsMu.Unlock()
		kh, err := loadKnownHosts()
		if err != nil {
			return fmt.Errorf("读取 known-hosts 失败: %w", err)
		}
		old, ok := kh.Entries[hostPort]
		if ok && old != fp && !overwrite {
			return fmt.Errorf("SSH 主机指纹不匹配（%s）：已记录 %s，本次 %s。"+
				"主机重装确认后用 overwrite 选项替换指纹", hostPort, old, fp)
		}
		if !ok || overwrite {
			kh.Entries[hostPort] = fp
			if err := saveKnownHosts(kh); err != nil {
				return fmt.Errorf("写入 known-hosts 失败: %w", err)
			}
		}
		return nil
	}, "", nil
}

// GenerateTestHostKey 仅供测试：生成一次性 ed25519 主机密钥。
func GenerateTestHostKey() (ssh.PublicKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return ssh.NewPublicKey(priv.Public())
}
