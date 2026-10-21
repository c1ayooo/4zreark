package extractor

// phpinfo 提取器：nuclei 命中 phpinfo 类模板（phpinfo-files / xampp-phpinfo-detect /
// ruijie-phpinfo）后，从响应 HTML 解析 phpinfo() 表格，提取内网 IP（SERVER_ADDR）、
// 站点根目录、软件版本等关键配置字段。

import (
	"context"
	"encoding/json"
	"net"
	"regexp"
	"strings"
)

// phpinfoExtractor 处理模板 id 含 "phpinfo" 的命中。
type phpinfoExtractor struct{}

var (
	// phpinfoRowRe 匹配 <tr><td class="e">KEY</td><td class="v">VALUE</td></tr> 双列行。
	phpinfoRowRe = regexp.MustCompile(`<td class="e">([^<]+)</td>\s*<td class="v">(.*?)</td>`)
	// phpinfoVersionRe 匹配页面标题里的 PHP 版本（老式 phpinfo 输出 <h1>PHP Version 7.4.3</h1>）。
	phpinfoVersionRe = regexp.MustCompile(`PHP Version\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)

	// phpinfoWant 关注的配置字段（phpinfo 表格 key → 结构化输出 key）。
	phpinfoWant = map[string]string{
		"SERVER_ADDR":     "server_addr",
		"SERVER_NAME":     "server_name",
		"SERVER_SOFTWARE": "server_software",
		"DOCUMENT_ROOT":   "document_root",
		"PHP_SAPI":        "php_sapi",
		"System":          "system",
	}
)

func (phpinfoExtractor) Supports(templateID string) bool {
	return strings.Contains(templateID, "phpinfo")
}

// phpinfoFields 提取出的关键配置。ServerAddrInternal 标记内网 IP。
type phpinfoFields struct {
	ServerAddr         string `json:"server_addr,omitempty"`
	ServerAddrInternal bool   `json:"server_addr_internal"`
	ServerName         string `json:"server_name,omitempty"`
	ServerSoftware     string `json:"server_software,omitempty"`
	DocumentRoot       string `json:"document_root,omitempty"`
	PHPSAPI            string `json:"php_sapi,omitempty"`
	System             string `json:"system,omitempty"`
	PHPVersion         string `json:"php_version,omitempty"`
}

func (phpinfoExtractor) Extract(ctx context.Context, c *Ctx) (*Finding, error) {
	body := bodyFromResponse(c.Response)
	if strings.TrimSpace(body) == "" {
		return nil, nil // 无响应报文可解析
	}
	out := phpinfoFields{}
	for _, m := range phpinfoRowRe.FindAllStringSubmatch(body, -1) {
		key := strings.TrimSpace(stripTags(m[1]))
		val := strings.TrimSpace(stripTags(m[2]))
		outKey, ok := phpinfoWant[key]
		if !ok || val == "" {
			continue
		}
		switch outKey {
		case "server_addr":
			out.ServerAddr = val
			out.ServerAddrInternal = isPrivateIP(val)
		case "system":
			out.System = val
		case "php_sapi":
			out.PHPSAPI = val
		case "server_name":
			out.ServerName = val
		case "server_software":
			out.ServerSoftware = val
		case "document_root":
			out.DocumentRoot = val
		}
	}
	if m := phpinfoVersionRe.FindStringSubmatch(body); len(m) > 1 {
		out.PHPVersion = m[1]
	}
	if out.ServerAddr == "" && out.ServerName == "" && out.PHPVersion == "" {
		// 命中页面不是 phpinfo 输出（matcher 误报或模板宽匹配），不产出。
		return nil, nil
	}
	data, _ := json.Marshal(out)
	return &Finding{
		ProjectID:   c.ProjectID,
		Domain:      c.Domain,
		Target:      firstNonEmpty(c.MatchURL, c.Target),
		Category:    "phpinfo_field",
		Kind:        "phpinfo",
		Data:        string(data),
		RawEvidence: phpinfoEvidence(body, out),
	}, nil
}

// stripTags 去除 HTML 标签（phpinfo 值里常含 <a href> 等）。
func stripTags(s string) string {
	var b strings.Builder
	inTag := false
	for _, r := range s {
		switch {
		case r == '<':
			inTag = true
		case r == '>':
			inTag = false
		case !inTag:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func isPrivateIP(s string) bool {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}

// phpinfoEvidence 证据文本：结构化结论 + 原始表格关键行（截前 8KB）。
func phpinfoEvidence(body string, out phpinfoFields) string {
	var b strings.Builder
	b.WriteString("phpinfo 命中")
	if out.ServerAddr != "" {
		b.WriteString(" → SERVER_ADDR=" + out.ServerAddr)
		if out.ServerAddrInternal {
			b.WriteString(" (内网)")
		}
	}
	if out.ServerName != "" {
		b.WriteString(" SERVER_NAME=" + out.ServerName)
	}
	if out.ServerSoftware != "" {
		b.WriteString(" SERVER_SOFTWARE=" + out.ServerSoftware)
	}
	if out.DocumentRoot != "" {
		b.WriteString(" DOCUMENT_ROOT=" + out.DocumentRoot)
	}
	if out.PHPVersion != "" {
		b.WriteString(" PHP_VERSION=" + out.PHPVersion)
	}
	if body != "" {
		if len(body) > 8<<10 {
			body = body[:8<<10] + "…"
		}
		b.WriteString("\n")
		b.WriteString(body)
	}
	return b.String()
}
