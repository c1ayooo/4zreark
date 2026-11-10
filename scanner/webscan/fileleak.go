package webscan

// FileLeak 备份/敏感文件专项探测（对齐 ARL fileLeak 思路的轻量版）。
//
// 判定三道闸，缺一不可，目标是把误报压到接近零：
//  1. 路径命中：探测一组固定路径（.git/.env/备份压缩包/actuator/swagger 等）；
//  2. 响应特征：每条规则带内容特征（魔数或关键字），纯 200 不算数——
//     这是与目录扫描的本质区别，spray 靠 valid 启发式，这里靠强特征；
//  3. 软 404 基线：每 origin 先用随机路径建基线，与基线同形（同状态码且
//     长度接近）的候选一律丢弃。
//
// 请求预算：每 origin 探测路径数固定（probes 内置，不接外部字典），
// 不会随任务规模放大对目标的压力。

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/internal/useragent"
)

// siteKeyOfURL 取 URL host 键（与 katana.go 的 siteKey 同口径）。
func siteKeyOfURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return u.Host
	}
	return raw
}

type FileLeakHit struct {
	Path       string // 命中路径
	Kind       string // git / svn / env / backup / docs / debug
	Name       string // 规则名
	Severity   string // high / medium / low
	Evidence   string // 命中证据摘要（截断）
	StatusCode int
	Length     int64
}

type fileLeakProbe struct {
	path     string
	kind     string
	name     string
	severity string
	// match 判定响应是否为真实命中。body 已截断到 fileLeakBodyCap。
	match func(status int, body []byte) (evidence string, ok bool)
}

const (
	fileLeakTimeout        = 8 * time.Second
	fileLeakBodyCap        = 64 * 1024
	fileLeakBaselineProbes = 2 // 每 origin 随机基线探测数
)

var envLineRe = regexp.MustCompile(`(?m)^[A-Z][A-Z0-9_]{2,}=`)

// fileLeakProbes 内置探测规则。顺序即探测顺序。
var fileLeakProbes = []fileLeakProbe{
	{path: "/.git/config", kind: "git", name: "Git 仓库配置泄露", severity: "high",
		match: func(_ int, b []byte) (string, bool) {
			if bytes.Contains(b, []byte("[core]")) {
				return "[core] ...", true
			}
			return "", false
		}},
	{path: "/.git/HEAD", kind: "git", name: "Git 仓库泄露", severity: "high",
		match: func(_ int, b []byte) (string, bool) {
			if bytes.HasPrefix(b, []byte("ref: refs/")) {
				return strings.TrimSpace(string(b[:40])), true
			}
			return "", false
		}},
	{path: "/.svn/entries", kind: "svn", name: "SVN 仓库泄露", severity: "high",
		match: func(_ int, b []byte) (string, bool) {
			if len(b) > 4 && (bytes.Contains(b, []byte("dir")) || b[0] == 12) {
				return "svn entries", true
			}
			return "", false
		}},
	{path: "/.svn/wc.db", kind: "svn", name: "SVN 工作副本数据库泄露", severity: "high",
		match: func(_ int, b []byte) (string, bool) {
			if bytes.HasPrefix(b, []byte("SQLite format 3")) {
				return "SQLite format 3", true
			}
			return "", false
		}},
	{path: "/.env", kind: "env", name: "环境变量文件泄露", severity: "critical",
		match: func(_ int, b []byte) (string, bool) {
			if len(envLineRe.FindAll(b, 3)) >= 2 {
				return firstLines(b, 120), true
			}
			return "", false
		}},
	{path: "/.env.local", kind: "env", name: "本地环境变量文件泄露", severity: "high",
		match: func(_ int, b []byte) (string, bool) {
			if len(envLineRe.FindAll(b, 2)) >= 2 {
				return firstLines(b, 120), true
			}
			return "", false
		}},
	{path: "/.DS_Store", kind: "backup", name: "macOS 目录元数据泄露", severity: "low",
		match: func(_ int, b []byte) (string, bool) {
			if bytes.Contains(b[:min(len(b), 16)], []byte("Bud1")) {
				return "Bud1 magic", true
			}
			return "", false
		}},
	{path: "/.idea/workspace.xml", kind: "backup", name: "IDE 工作区文件泄露", severity: "medium",
		match: func(_ int, b []byte) (string, bool) {
			if bytes.Contains(b, []byte("<project version")) {
				return "<project ...", true
			}
			return "", false
		}},
	{path: "/backup.zip", kind: "backup", name: "备份压缩包泄露", severity: "high",
		match: func(_ int, b []byte) (string, bool) {
			return archiveMagic(b)
		}},
	{path: "/web.zip", kind: "backup", name: "备份压缩包泄露", severity: "high",
		match: func(_ int, b []byte) (string, bool) {
			return archiveMagic(b)
		}},
	{path: "/www.zip", kind: "backup", name: "备份压缩包泄露", severity: "high",
		match: func(_ int, b []byte) (string, bool) {
			return archiveMagic(b)
		}},
	{path: "/site.zip", kind: "backup", name: "备份压缩包泄露", severity: "high",
		match: func(_ int, b []byte) (string, bool) {
			return archiveMagic(b)
		}},
	{path: "/backup.tar.gz", kind: "backup", name: "备份压缩包泄露", severity: "high",
		match: func(_ int, b []byte) (string, bool) {
			return archiveMagic(b)
		}},
	{path: "/dump.sql", kind: "backup", name: "数据库导出泄露", severity: "critical",
		match: func(_ int, b []byte) (string, bool) {
			return sqlDumpMagic(b)
		}},
	{path: "/database.sql", kind: "backup", name: "数据库导出泄露", severity: "critical",
		match: func(_ int, b []byte) (string, bool) {
			return sqlDumpMagic(b)
		}},
	{path: "/db.sql", kind: "backup", name: "数据库导出泄露", severity: "critical",
		match: func(_ int, b []byte) (string, bool) {
			return sqlDumpMagic(b)
		}},
	{path: "/swagger.json", kind: "docs", name: "API 文档暴露", severity: "medium",
		match: func(_ int, b []byte) (string, bool) {
			return openapiMagic(b)
		}},
	{path: "/openapi.json", kind: "docs", name: "API 文档暴露", severity: "medium",
		match: func(_ int, b []byte) (string, bool) {
			return openapiMagic(b)
		}},
	{path: "/v2/api-docs", kind: "docs", name: "API 文档暴露", severity: "medium",
		match: func(_ int, b []byte) (string, bool) {
			return openapiMagic(b)
		}},
	{path: "/actuator", kind: "debug", name: "Spring Actuator 暴露", severity: "medium",
		match: func(_ int, b []byte) (string, bool) {
			if bytes.Contains(b, []byte(`"_links"`)) {
				return `{"_links": ...`, true
			}
			return "", false
		}},
	{path: "/actuator/env", kind: "debug", name: "Actuator 环境变量暴露", severity: "critical",
		match: func(_ int, b []byte) (string, bool) {
			if bytes.Contains(b, []byte(`"propertySources"`)) || bytes.Contains(b, []byte(`"activeProfiles"`)) {
				return `"propertySources" ...`, true
			}
			return "", false
		}},
	{path: "/actuator/heapdump", kind: "debug", name: "Actuator 堆转储暴露", severity: "critical",
		match: func(_ int, b []byte) (string, bool) {
			if bytes.HasPrefix(b, []byte("JAVA PROFILE")) || bytes.HasPrefix(b, []byte("\xac\xed\x00\x05")) {
				return "heapdump magic", true
			}
			return "", false
		}},
	{path: "/metrics", kind: "debug", name: "Prometheus 指标暴露", severity: "low",
		match: func(_ int, b []byte) (string, bool) {
			if bytes.Contains(b, []byte("# HELP")) || bytes.Contains(b, []byte("# TYPE")) {
				return "# HELP ...", true
			}
			return "", false
		}},
	{path: "/druid/index.html", kind: "debug", name: "Druid 监控台暴露", severity: "medium",
		match: func(_ int, b []byte) (string, bool) {
			if bytes.Contains(b, []byte("druid")) && bytes.Contains(b, []byte("StatViewServlet")) {
				return "druid console", true
			}
			return "", false
		}},
}

// archiveMagic 判定响应体是否为真实压缩包（zip/gzip/7z/rar 魔数）。
func archiveMagic(b []byte) (string, bool) {
	switch {
	case len(b) < 8:
		return "", false
	case bytes.HasPrefix(b, []byte("PK\x03\x04")):
		return "zip magic (PK)", true
	case bytes.HasPrefix(b, []byte("\x1f\x8b")):
		return "gzip magic", true
	case bytes.HasPrefix(b, []byte("7z\xbc\xaf")):
		return "7z magic", true
	case bytes.HasPrefix(b, []byte("Rar!")):
		return "rar magic", true
	}
	return "", false
}

// sqlDumpMagic 判定 SQL 导出文件特征。
func sqlDumpMagic(b []byte) (string, bool) {
	if len(b) < 32 {
		return "", false
	}
	for _, kw := range []string{"-- MySQL dump", "-- PostgreSQL database dump", "CREATE TABLE", "INSERT INTO"} {
		if bytes.Contains(b, []byte(kw)) {
			return kw, true
		}
	}
	return "", false
}

// openapiMagic 判定 OpenAPI/Swagger JSON。
func openapiMagic(b []byte) (string, bool) {
	if len(b) < 32 {
		return "", false
	}
	for _, kw := range []string{`"swagger"`, `"openapi"`, `"paths"`} {
		if bytes.Contains(b, []byte(kw)) {
			return kw + " in JSON", true
		}
	}
	return "", false
}

// FileLeakScanner 对单个 origin 做备份/敏感文件探测。
type FileLeakScanner struct {
	client *http.Client
}

func NewFileLeakScanner() *FileLeakScanner {
	return &FileLeakScanner{
		client: &http.Client{
			Timeout: fileLeakTimeout,
			// 不跟随重定向：302 到登录页/首页是这类探测最常见的假象。
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

type fileLeakBaseline struct {
	status  int
	length  int64
	created bool
}

// ScanOrigin 探测一个 origin（如 https://example.com）。
// 返回通过三道闸的命中列表。
func (s *FileLeakScanner) ScanOrigin(ctx context.Context, origin string) []FileLeakHit {
	if origin == "" || !strings.HasPrefix(origin, "http") {
		return nil
	}
	base := s.baseline(ctx, origin)
	if base.created && base.status == http.StatusOK {
		// 基线是 200：这个 origin 对任意路径返回统一页（WAF 挑战/SPA fallback），
		// 特征判定仍有意义，但需要更严的长度差。
	}
	hits := make([]FileLeakHit, 0, 2)
	for _, p := range fileLeakProbes {
		select {
		case <-ctx.Done():
			return hits
		default:
		}
		status, length, body, ok := s.get(ctx, origin+p.path)
		if !ok {
			continue
		}
		evidence, hit := p.match(status, body)
		if !hit {
			continue
		}
		// 软 404 基线闸：与基线同形（同状态码且长度接近）视为误报。
		if base.created && status == base.status && abs64(length-base.length) <= 32 {
			continue
		}
		hits = append(hits, FileLeakHit{
			Path:       p.path,
			Kind:       p.kind,
			Name:       p.name,
			Severity:   p.severity,
			Evidence:   evidence,
			StatusCode: status,
			Length:     length,
		})
	}
	return hits
}

// baseline 用随机路径建立该 origin 的统一响应基线。
func (s *FileLeakScanner) baseline(ctx context.Context, origin string) fileLeakBaseline {
	for i := 0; i < fileLeakBaselineProbes; i++ {
		probe := fmt.Sprintf("/zl%dq%d.noexists", time.Now().UnixNano()%100000, i)
		status, length, _, ok := s.get(ctx, origin+probe)
		if !ok {
			continue
		}
		return fileLeakBaseline{status: status, length: length, created: true}
	}
	return fileLeakBaseline{}
}

func (s *FileLeakScanner) get(ctx context.Context, url string) (status int, length int64, body []byte, ok bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, 0, nil, false
	}
	req.Header.Set("User-Agent", useragent.ForSite("", siteKeyOfURL(url)).UserAgent)
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, 0, nil, false
	}
	defer resp.Body.Close()
	body, _ = io.ReadAll(io.LimitReader(resp.Body, fileLeakBodyCap))
	return resp.StatusCode, resp.ContentLength, body, true
}

func firstLines(b []byte, cap int) string {
	s := string(b)
	if len(s) > cap {
		s = s[:cap]
	}
	s = strings.ReplaceAll(s, "\r", "")
	lines := strings.SplitN(s, "\n", 3)
	return strings.Join(lines, "\\n")
}

func abs64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
