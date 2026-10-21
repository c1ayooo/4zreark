package nucleiruntime

import (
	"archive/zip"
	"context"
	"fmt"
	"github.com/c1ayooo/4zreark/internal/useragent"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// downloadURL 是 GitHub release 的固定形态，抽出来便于测试。
func downloadURL(version, goos, goarch string) (string, error) {
	asset, _, err := assetName(version, goos, goarch)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("https://github.com/projectdiscovery/nuclei/releases/download/v%s/%s", version, asset), nil
}

// assetName 返回 release 压缩包名和压缩包内的可执行文件名。
func assetName(version, goos, goarch string) (asset, binary string, err error) {
	version = strings.TrimPrefix(strings.TrimSpace(version), "v")
	if version == "" {
		return "", "", fmt.Errorf("nuclei 版本为空")
	}
	switch goos {
	case "linux", "darwin", "windows":
	default:
		return "", "", fmt.Errorf("nuclei 不支持当前操作系统: %s", goos)
	}
	switch goarch {
	case "amd64", "arm64", "386", "arm":
	default:
		return "", "", fmt.Errorf("nuclei 不支持当前架构: %s", goarch)
	}
	if goos == "darwin" && (goarch == "386" || goarch == "arm") {
		return "", "", fmt.Errorf("nuclei 没有 darwin/%s 的官方构建", goarch)
	}
	if goos == "windows" && goarch == "arm" {
		return "", "", fmt.Errorf("nuclei 没有 windows/arm 的官方构建")
	}
	binary = "nuclei"
	if goos == "windows" {
		binary = "nuclei.exe"
	}
	return fmt.Sprintf("nuclei_%s_%s_%s.zip", version, goos, goarch), binary, nil
}

// installBinary 下载并安装固定版本的 nuclei 到 m.BinaryPath()。
// 先写临时文件、校验可执行、再原子替换，避免半截二进制被当成可用。
func (m *Manager) installBinary(ctx context.Context, version string, progress func(Progress)) error {
	dest := m.BinaryPath()
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return fmt.Errorf("创建二进制目录失败: %w", err)
	}
	if err := os.MkdirAll(m.tmpDir(), 0o700); err != nil {
		return fmt.Errorf("创建临时目录失败: %w", err)
	}
	u, err := downloadURL(version, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(m.tmpDir(), "nuclei-download-*.zip")
	if err != nil {
		return fmt.Errorf("创建下载临时文件失败: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	reportProgress(progress, "下载 nuclei 二进制", 10, "连接 GitHub release…")
	if err := m.download(ctx, u, tmp, func(done, total int64) {
		pct := 20
		msg := fmt.Sprintf("已下载 %.1f MB", float64(done)/(1<<20))
		if total > 0 {
			pct = 10 + int(35*done/total)
			msg = fmt.Sprintf("%.1f / %.1f MB", float64(done)/(1<<20), float64(total)/(1<<20))
		}
		reportProgress(progress, "下载 nuclei 二进制", pct, msg)
	}); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("写入下载文件失败: %w", err)
	}

	_, binaryName, err := assetName(version, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return err
	}
	extracted, err := os.CreateTemp(filepath.Dir(dest), ".nuclei-install-*")
	if err != nil {
		return fmt.Errorf("创建安装临时文件失败: %w", err)
	}
	extractedName := extracted.Name()
	extracted.Close()
	defer os.Remove(extractedName)
	if err := extractZipBinary(tmpName, binaryName, extractedName); err != nil {
		return err
	}
	if err := os.Chmod(extractedName, 0o755); err != nil {
		return fmt.Errorf("设置二进制权限失败: %w", err)
	}
	// 先确认下载物真的可执行，再替换正式路径。
	if out, err := m.runCommand(ctx, extractedName, "-version"); err != nil {
		return fmt.Errorf("下载的 nuclei 无法执行: %w: %s", err, tail(out))
	}
	if runtime.GOOS == "windows" {
		_ = os.Remove(dest) // Windows 不允许 rename 覆盖正在使用的文件
	}
	if err := os.Rename(extractedName, dest); err != nil {
		return fmt.Errorf("安装 nuclei 到 %s 失败: %w", dest, err)
	}
	if err := os.Chmod(dest, 0o755); err != nil {
		return fmt.Errorf("设置二进制权限失败: %w", err)
	}
	return nil
}

func (m *Manager) download(ctx context.Context, url string, dst *os.File, progress func(done, total int64)) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("创建下载请求失败: %w", err)
	}
	req.Header.Set("User-Agent", useragent.Pick())
	resp, err := m.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("下载 nuclei 失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载 nuclei 失败: HTTP %d (%s)", resp.StatusCode, url)
	}
	sink := &progressWriter{dst: dst, total: resp.ContentLength, cb: progress}
	n, err := io.Copy(sink, io.LimitReader(resp.Body, downloadLimit+1))
	if err != nil {
		return fmt.Errorf("写入下载文件失败: %w", err)
	}
	if n > downloadLimit {
		return fmt.Errorf("nuclei release 超过 %d MB 上限", downloadLimit>>20)
	}
	if n == 0 {
		return fmt.Errorf("下载的 nuclei release 为空")
	}
	return nil
}

// progressWriter 每写入约 1MB 回调一次，避免进度回调过于频繁。
type progressWriter struct {
	dst   io.Writer
	total int64
	done  int64
	last  int64
	cb    func(done, total int64)
}

func (p *progressWriter) Write(b []byte) (int, error) {
	n, err := p.dst.Write(b)
	p.done += int64(n)
	if p.cb != nil && (p.done-p.last >= 1<<20 || err != nil) {
		p.last = p.done
		p.cb(p.done, p.total)
	}
	return n, err
}

// extractZipBinary 只取压缩包里 basename 匹配的单个可执行文件，不展开目录，
// 从根上避免 zip-slip。
func extractZipBinary(zipPath, binaryName, dest string) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return fmt.Errorf("创建目标目录失败: %w", err)
	}
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("打开 nuclei release 压缩包失败: %w", err)
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || filepath.Base(f.Name) != binaryName {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("读取 %s 失败: %w", f.Name, err)
		}
		out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			rc.Close()
			return fmt.Errorf("创建目标文件失败: %w", err)
		}
		_, copyErr := io.Copy(out, io.LimitReader(rc, downloadLimit))
		closeErr := out.Close()
		rc.Close()
		if copyErr != nil {
			return fmt.Errorf("解压 %s 失败: %w", f.Name, copyErr)
		}
		if closeErr != nil {
			return fmt.Errorf("写入 %s 失败: %w", binaryName, closeErr)
		}
		return nil
	}
	return fmt.Errorf("release 压缩包里没有找到 %s", binaryName)
}
