// Package vulnharvest 把「已确认」的漏洞沉淀成可复用的 POC 文档。
//
// 来源：4zreco internal/vulnharvest（只搬纯组装逻辑，不搬文件落盘/数据库）。
// 4zreark 的 POC 库在 PG（pocs 表），由调用方把 Build 的产物 upsert 进去。
package vulnharvest

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/models"
)

var (
	cveIDPattern    = regexp.MustCompile(`CVE-\d{4}-\d{4,}`)
	ipv4Pattern     = regexp.MustCompile(`(?:\d{1,3}\.){3}\d{1,3}`)
	pocNameUnsafeRe = regexp.MustCompile(`[\\/:*?"<>|\r\n\t]+`)
)

// Build 由一条已确认漏洞组装 POC 文档。ok=false 表示缺少目标，不具备沉淀条件。
func Build(v *models.Vulnerability) (title, content string, ok bool) {
	if v == nil || strings.TrimSpace(v.Target) == "" {
		return "", "", false
	}
	masked := *v
	masked.Name = maskIPv4(v.Name)
	masked.Description = maskIPv4(v.Description)
	masked.Target = maskIPv4(v.Target)
	masked.Evidence = maskIPv4(v.Evidence)
	masked.Solution = maskIPv4(v.Solution)

	title = strings.TrimSpace(masked.Name)
	if title == "" {
		title = "未命名漏洞"
	}
	if cve := cveIDPattern.FindString(masked.Name + " " + masked.Description); cve != "" {
		title = cve + " " + title
	}

	today := time.Now().Format("2006-01-02")
	var b strings.Builder
	b.WriteString("---\n")
	b.WriteString("category: poc\n")
	b.WriteString("source: auto-harvest\n")
	b.WriteString("date: " + today + "\n")
	b.WriteString("vulnerability_id: " + masked.ID.Hex() + "\n")
	if cve := cveIDPattern.FindString(masked.Name + " " + masked.Description); cve != "" {
		b.WriteString("cve: " + cve + "\n")
	}
	b.WriteString("---\n\n")
	b.WriteString("# " + title + "\n\n")
	b.WriteString("## 漏洞概述\n\n" + orNone(masked.Description) + "\n\n")
	b.WriteString("## 利用前提\n\n" + orNone(preconditionsText(&masked)) + "\n\n")
	b.WriteString("## 复现步骤（逐字保真）\n\n" + orNone(reproText(&masked)) + "\n")
	if e := strings.TrimSpace(masked.Evidence); e != "" {
		b.WriteString("\n## 证据要点\n\n" + e + "\n")
	}
	if r := strings.TrimSpace(masked.Request); r != "" {
		b.WriteString("\n## 请求报文\n\n```http\n" + r + "\n```\n")
	}
	if r := strings.TrimSpace(masked.Response); r != "" {
		b.WriteString("\n## 响应报文\n\n```http\n" + r + "\n```\n")
	}
	b.WriteString("\n## 处置建议\n\n" + orNone(masked.Solution) + "\n\n")
	b.WriteString("> 本文件由平台在漏洞确认后自动沉淀。复用前先核对组件版本与利用前提；")
	b.WriteString("目标在变，打法可复用，禁止无核对直接打。\n")
	return title, b.String(), true
}

// SafeName 生成可读的文件名（仅用于前端展示/导出）。
func SafeName(title string) string {
	base := pocNameUnsafeRe.ReplaceAllString(strings.TrimSpace(title), "")
	if r := []rune(base); len(r) > 60 {
		base = string(r[:60])
	}
	if base == "" {
		base = "untitled"
	}
	return base
}

func orNone(s string) string {
	if strings.TrimSpace(s) == "" {
		return "（未填写）"
	}
	return strings.TrimSpace(s)
}

// maskIPv4 把点分十进制 IPv4 脱敏为保留前两段（10.0.0.1 → 10.0.x.x）。
func maskIPv4(s string) string {
	if !strings.Contains(s, ".") {
		return s
	}
	locs := ipv4Pattern.FindAllStringIndex(s, -1)
	if len(locs) == 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	last := 0
	for _, loc := range locs {
		start, end := loc[0], loc[1]
		if start > 0 && isASCIIDigit(s[start-1]) {
			continue
		}
		if end < len(s) && (isASCIIDigit(s[end]) || (s[end] == '.' && end+1 < len(s) && isASCIIDigit(s[end+1]))) {
			continue
		}
		ip := s[start:end]
		if !plausibleIPv4(ip) {
			continue
		}
		parts := strings.SplitN(ip, ".", 4)
		b.WriteString(s[last:start])
		b.WriteString(parts[0] + "." + parts[1] + ".x.x")
		last = end
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

func isASCIIDigit(c byte) bool { return c >= '0' && c <= '9' }

func plausibleIPv4(s string) bool {
	for _, part := range strings.Split(s, ".") {
		n := 0
		for i := 0; i < len(part); i++ {
			if part[i] < '0' || part[i] > '9' {
				return false
			}
			n = n*10 + int(part[i]-'0')
		}
		if n > 255 {
			return false
		}
	}
	return true
}

// 以下两个辅助函数把 4zreark 没有的独立字段映射到已有字段，保持文档结构完整。
func preconditionsText(v *models.Vulnerability) string { return "" }

func reproText(v *models.Vulnerability) string {
	var parts []string
	if strings.TrimSpace(v.Method) != "" || strings.TrimSpace(v.Target) != "" {
		parts = append(parts, fmt.Sprintf("%s %s", v.Method, v.Target))
	}
	if strings.TrimSpace(v.Payload) != "" {
		parts = append(parts, "Payload: "+v.Payload)
	}
	if strings.TrimSpace(v.Evidence) != "" {
		parts = append(parts, "证据: "+v.Evidence)
	}
	return strings.Join(parts, "\n")
}
