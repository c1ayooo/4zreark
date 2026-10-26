package service

import (
	"compress/gzip"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	configSourceMu sync.RWMutex
	configSource   []byte
	updatingFlag   int32
)

// SetConfigSource 留存启动时读到的配置原文。
// 节点是零配置启动（CONFIG_PATH=/dev/stdin），自更新 exec 前必须把同一份内容
// 重新灌回 fd 0，否则新进程读 stdin 直接 EOF 起不来。
func SetConfigSource(raw []byte) {
	configSourceMu.Lock()
	configSource = append([]byte(nil), raw...)
	configSourceMu.Unlock()
}

func configSourceBytes() []byte {
	configSourceMu.RLock()
	defer configSourceMu.RUnlock()
	return configSource
}

// configUsesStdin 见 self_update_unix.go / self_update_windows.go 的平台实现。

// BinaryVersion 用文件内容的 SHA-256 前 12 位当版本号。
// 平台侧对 worker 二进制算的是同一个值，两边可以直接比对。
func BinaryVersion(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))[:12]
}

// SelfVersion 返回当前运行中二进制自己的版本号。
func SelfVersion() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	real, err := filepath.EvalSymlinks(exe)
	if err == nil {
		exe = real
	}
	return BinaryVersion(exe)
}

// newUpdateClient 构造信任平台自签 CA 的下载客户端。
// worker 连平台走的是自签证书链，用系统根证书池会直接握手失败。
func newUpdateClient(caPath string) (*http.Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caPath != "" {
		pem, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("读取平台 CA 失败: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("平台 CA 无法解析: %s", caPath)
		}
		tlsCfg.RootCAs = pool
	}
	return &http.Client{
		Timeout:   10 * time.Minute,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}, nil
}

// TrySelfUpdate 从平台拉取新版 worker，校验后原地替换并 exec 重启。
// 任何一步失败都只返回错误，当前进程继续按旧版干活，不会把节点搞丢。
func TrySelfUpdate(platformURL, token, binaryURL, wantVersion, caPath string) error {
	if !atomic.CompareAndSwapInt32(&updatingFlag, 0, 1) {
		return nil
	}
	defer atomic.StoreInt32(&updatingFlag, 0)

	if wantVersion == "" {
		return fmt.Errorf("平台未给出版本号")
	}
	if wantVersion == SelfVersion() {
		return nil
	}
	if platformURL == "" || token == "" {
		return fmt.Errorf("缺少平台地址或节点密钥，无法自更新")
	}
	if binaryURL == "" {
		binaryURL = "/api/node/binary"
	}

	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if real, rerr := filepath.EvalSymlinks(exe); rerr == nil {
		exe = real
	}
	dir := filepath.Dir(exe)

	tmpGz := filepath.Join(dir, ".worker.new.gz")
	tmpBin := filepath.Join(dir, ".worker.new")

	cleanup := func() {
		_ = os.Remove(tmpGz)
		_ = os.Remove(tmpBin)
	}

	// 1. 下载（节点只做出站，平台地址与 ws 用的是同一个）
	url := strings.TrimRight(platformURL, "/") + binaryURL
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	// 下载客户端必须信任平台自签 CA，否则会报 x509: certificate signed by unknown authority
	client, err := newUpdateClient(caPath)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("下载失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载返回 %d", resp.StatusCode)
	}

	f, err := os.OpenFile(tmpGz, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		cleanup()
		return fmt.Errorf("写临时文件失败: %w", err)
	}
	f.Close()

	// 2. 解压
	gz, err := os.Open(tmpGz)
	if err != nil {
		cleanup()
		return err
	}
	zr, err := gzip.NewReader(gz)
	if err != nil {
		gz.Close()
		cleanup()
		return fmt.Errorf("解压失败: %w", err)
	}
	out, err := os.OpenFile(tmpBin, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		zr.Close()
		gz.Close()
		cleanup()
		return err
	}
	if _, err := io.Copy(out, zr); err != nil {
		out.Close()
		zr.Close()
		gz.Close()
		cleanup()
		return fmt.Errorf("写新二进制失败: %w", err)
	}
	out.Close()
	zr.Close()
	gz.Close()

	// 3. 校验：版本号就是二进制的 sha256 前 12 位
	got := BinaryVersion(tmpBin)
	if got != wantVersion {
		cleanup()
		return fmt.Errorf("校验失败: want=%s got=%s", wantVersion, got)
	}

	// 4. 安装并重启：Unix 原子替换 + exec，Windows 起新进程再退出
	_ = os.Remove(tmpGz)
	if err := installAndRestart(exe, tmpBin, wantVersion); err != nil {
		cleanup()
		return err
	}
	return nil
}
