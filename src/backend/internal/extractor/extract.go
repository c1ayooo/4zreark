package extractor

// 提取器公共工具：response body 抽取、HTTP 下载、落盘归档（限长 + sha256）。

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// bodyFromResponse 从 nuclei JSONL response 字段剥掉 HTTP 头块取 body。
// nuclei -json 的 response 含完整报文（状态行+头+空行+body）；无头块时整段视为 body。
func bodyFromResponse(resp string) string {
	if idx := strings.Index(resp, "\r\n\r\n"); idx >= 0 {
		return resp[idx+4:]
	}
	if idx := strings.Index(resp, "\n\n"); idx >= 0 {
		return resp[idx+2:]
	}
	return resp
}

// fetchBody 下载 URL，按 limit 限长返回 body。HTTPClient 为 nil 时拒绝下载
// （仅解析已有报文，不做计划外出网——与 nuclei 链路 -ni 的约束一致）。
func fetchBody(ctx context.Context, client *http.Client, url string, limit int64) ([]byte, error) {
	if client == nil {
		return nil, fmt.Errorf("下载客户端未注入（nil HTTPClient）")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; 4zreco-extract/1.0)")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

// maxArchiveBytes 单发下载归档的上限（备份/仓库文件可能很大，超出即放弃归档只记结论）。
const maxArchiveBytes = 64 << 20 // 64MB

// downloadAndArchive 下载 URL 落盘到 dir（完整路径），返回 (相对 dir 的路径, 字节数, sha256)。
// 超长（>maxArchiveBytes）拒绝落盘并返回错误；内容按 URL 末尾文件名清洗命名。
func downloadAndArchive(ctx context.Context, client *http.Client, rawURL, dir string) (name string, size int64, sha string, err error) {
	if client == nil {
		return "", 0, "", fmt.Errorf("下载客户端未注入（nil HTTPClient）")
	}
	u, perr := url.Parse(rawURL)
	if perr != nil {
		return "", 0, "", perr
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", 0, "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; 4zreco-extract/1.0)")
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", 0, "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", 0, "", err
	}
	base := sanitizeFilename(filepath.Base(u.Path))
	if base == "" || base == "." || base == "/" {
		base = "download.bin"
	}
	dst := filepath.Join(dir, base)
	// 限长守卫：LimitReader 读 max+1 字节，超出即放弃（防止把巨型备份拖进归档目录）。
	f, err := os.Create(dst)
	if err != nil {
		return "", 0, "", err
	}
	h := sha256.New()
	n, cErr := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, maxArchiveBytes+1))
	closeErr := f.Close()
	if cErr != nil {
		_ = os.Remove(dst)
		return "", 0, "", cErr
	}
	if closeErr != nil {
		_ = os.Remove(dst)
		return "", 0, "", closeErr
	}
	if n > maxArchiveBytes {
		_ = os.Remove(dst)
		return "", 0, "", fmt.Errorf("超过归档上限 %dMB", maxArchiveBytes>>20)
	}
	return filepath.Join(dir, base), n, hex.EncodeToString(h.Sum(nil)), nil
}

// sanitizeFilename 只保留安全文件名字符，防路径穿越。
func sanitizeFilename(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	return b.String()
}
