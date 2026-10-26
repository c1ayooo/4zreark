// sshprobe.go SSH 凭据实连探测(只读验证):x/crypto/ssh 建连认证,成功后执行
// id 与 sudo -n true 摸权限面(可登录/用户组/能否免密 sudo),不做任何写操作。
package creds

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHProbeInput 一次 SSH 凭据验证的入参。
type SSHProbeInput struct {
	Host       string
	Port       int // 0 = 22
	Username   string
	Password   string // 与 Key 二选一
	PrivateKey string // PEM 私钥(可选)
	Timeout    time.Duration
}

// SSHProbeResult 实连结论:存活性 + 认证结果 + 权限面。
type SSHProbeResult struct {
	Alive    bool   `json:"alive"`     // TCP/SSH banner 可达
	Authed   bool   `json:"authed"`    // 凭据通过
	User     string `json:"user"`      // 登录后 id -un
	Groups   string `json:"groups"`    // id 输出摘要
	SudoNOPW bool   `json:"sudo_nopw"` // sudo -n true 通过(高危)
	Banner   string `json:"banner,omitempty"`
	Detail   string `json:"detail"`
}

// VerifySSH 实连验证。凭据无效/网络不通都返回明确 Detail。
func VerifySSH(ctx context.Context, in SSHProbeInput) (*SSHProbeResult, error) {
	if strings.TrimSpace(in.Host) == "" || strings.TrimSpace(in.Username) == "" {
		return nil, fmt.Errorf("host 与 username 必填")
	}
	if in.Port <= 0 {
		in.Port = 22
	}
	timeout := in.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	addr := net.JoinHostPort(in.Host, strconv.Itoa(in.Port))

	var authMethods []ssh.AuthMethod
	if strings.TrimSpace(in.PrivateKey) != "" {
		key, err := ssh.ParsePrivateKey([]byte(in.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("私钥解析失败: %v", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(key))
	}
	if in.Password != "" {
		authMethods = append(authMethods, ssh.Password(in.Password))
	}
	if len(authMethods) == 0 {
		return nil, fmt.Errorf("password 与 private_key 至少提供一项")
	}

	cfg := &ssh.ClientConfig{
		User:            in.Username,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // 凭据验证场景:不校验主机指纹(测试目标)
		Timeout:         timeout,
		BannerCallback:  func(b string) error { return nil },
	}
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return &SSHProbeResult{Alive: false, Detail: fmt.Sprintf("端口不通: %v", err)}, nil
	}
	defer conn.Close()
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		// 区分「可达但认证失败」与「不是 SSH 服务」。
		detail := fmt.Sprintf("认证失败或握手异常: %v", err)
		alive := true
		if strings.Contains(err.Error(), "unable to read") || strings.Contains(err.Error(), "connection reset") {
			alive = false
			detail = "握手失败(可能不是 SSH 服务): " + err.Error()
		}
		return &SSHProbeResult{Alive: alive, Detail: detail}, nil
	}
	client := ssh.NewClient(sshConn, chans, reqs)
	defer client.Close()

	res := &SSHProbeResult{Alive: true, Authed: true, Banner: strings.TrimSpace(string(sshConn.ServerVersion()))}
	// 权限面:id + sudo -n true(只读探测,全部 5s 超时)。
	if out, err := runSSHCommand(ctx, client, "id", 5*time.Second); err == nil {
		idLine := strings.TrimSpace(out)
		res.Groups = truncate(idLine, 300)
		if parts := strings.Fields(idLine); len(parts) > 0 {
			res.User = strings.TrimPrefix(parts[0], "uid=")
		}
	}
	if out, err := runSSHCommand(ctx, client, "sudo -n true 2>/dev/null && echo SUDO_OK", 5*time.Second); err == nil && strings.Contains(out, "SUDO_OK") {
		res.SudoNOPW = true
	}
	res.Detail = fmt.Sprintf("登录成功:%s@%s", in.Username, addr)
	if res.SudoNOPW {
		res.Detail += ",免密 sudo(高危)"
	}
	return res, nil
}

func runSSHCommand(ctx context.Context, client *ssh.Client, cmd string, timeout time.Duration) (string, error) {
	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	done := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		out, err := sess.Output(cmd)
		if err != nil {
			errCh <- err
			return
		}
		done <- string(out)
	}()
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case out := <-done:
		return out, nil
	case err := <-errCh:
		return "", err
	case <-time.After(timeout):
		return "", fmt.Errorf("命令超时: %s", cmd)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
