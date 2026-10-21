package extractor

// backup 提取器：nuclei 命中 backups 类模板（zip-backup-files / mysql-dump /
// php-backup-files 等）后，把命中的备份文件 URL 下载归档，记录大小与 sha256。
// 目录列表类命中（backup-directory-listing）下载到的是 HTML 页而非文件，跳过。

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// backupExtractor 处理 backups/ 目录下的模板 id（见 data/nuclei-templates/http/exposures/backups/）。
type backupExtractor struct{}

var backupTemplateIDs = map[string]bool{
	"backup-directory-listing":    true,
	"batflat-sqlite-exposure":     true,
	"exposed-mysql-initial":       true,
	"sql-server-dump":             true,
	"wordpress-db-exposure":       true,
	"zip-backup-files":            true,
	"generic-php-files":           true,
	"sweetrice-backup-disclosure": true,
	"mysql-dump":                  true,
	"php-backup-files":            true,
	"froxlor-database-backup":     true,
}

func (backupExtractor) Supports(templateID string) bool { return backupTemplateIDs[templateID] }

// backupRecord 归档记录。
type backupRecord struct {
	URL     string `json:"url,omitempty"`
	Size    int64  `json:"size_bytes,omitempty"`
	SHA256  string `json:"sha256,omitempty"`
	Archive string `json:"archive_path,omitempty"` // 相对项目根归档路径
}

func (backupExtractor) Extract(ctx context.Context, c *Ctx) (*Finding, error) {
	url := firstNonEmpty(c.MatchURL, "")
	if url == "" || c.DownloadDir == "" || c.HTTPClient == nil {
		// 无归档能力（未注入客户端/目录）时不产出——检测本身已由 nuclei 完成。
		return nil, nil
	}
	rec := backupRecord{URL: url}
	dir := filepath.Join(c.DownloadDir, "backup")
	name, size, sha, err := downloadAndArchive(ctx, c.HTTPClient, url, dir)
	if err != nil {
		// 目录列表/404/超限：归档失败，不做产物（避免把 HTML 列表当备份落盘）。
		return nil, nil
	}
	rec.Size = size
	rec.SHA256 = sha
	rec.Archive = name
	if isHTMLContent(name) {
		_ = os.Remove(name) // 下载到的是 HTML 页（目录列表/错误页），清理误归档不产出
		return nil, nil
	}
	data, _ := json.Marshal(rec)
	return &Finding{
		ProjectID:   c.ProjectID,
		Domain:      c.Domain,
		Target:      url,
		Category:    "backup_file",
		Kind:        backupKind(url),
		Data:        string(data),
		RawEvidence: backupEvidence(rec),
		FilePath:    rec.Archive,
	}, nil
}

// isHTMLContent 读归档文件头部判断是否为 HTML 页（目录列表/错误页），
// 比扩展名判断可靠（目录 URL 落盘的文件名可能是目录名而非 .html）。
func isHTMLContent(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, 512)
	n, _ := f.Read(buf)
	head := strings.ToLower(strings.TrimSpace(string(buf[:n])))
	return strings.HasPrefix(head, "<html") || strings.HasPrefix(head, "<!doctype")
}

func backupKind(url string) string {
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(url), "."))
	switch ext {
	case "zip", "rar", "7z", "gz", "tar", "tgz", "tar.gz", "bak", "sql", "dump", "db", "sqlite":
		return ext
	default:
		return "backup"
	}
}

func backupEvidence(rec backupRecord) string {
	return "备份文件命中 → " + rec.URL + " size=" + itoa64(rec.Size) + " sha256=" + rec.SHA256
}

func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
