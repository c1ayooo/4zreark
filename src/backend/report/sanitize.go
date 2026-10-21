package report

// Export sanitization: the finding detail page is an internal view (finding id,
// status, work/node traces, traffic ids). A client-facing Word/PDF export must
// not leak that bookkeeping. SanitizeForExport strips platform identifiers while
// keeping the vulnerability description, reproduction, evidence and fix.

import (
	"regexp"
	"strings"
)

var (
	rePrevFinding = regexp.MustCompile(`此前\s*finding\s*#?\s*\d+`)
	rePrevFact    = regexp.MustCompile(`此前\s*fact\s*\d+`)
	reFindingRef  = regexp.MustCompile(`(?i)finding\s*#?\s*\d+`)
	reToolName    = regexp.MustCompile(`(?i)http_probe|traffic_search|traffic_get|get_finding_traffic|bind_finding_traffic`)
	reBulletID    = regexp.MustCompile("(?m)^-\\s*`?完整报文已留存`?：")
	reNodeRef     = regexp.MustCompile(`探索节点\s*\d+`)
	reWorkRef     = regexp.MustCompile(`work#\d+(?:\s*（[^）]*）)?`)
	reIntentRef   = regexp.MustCompile(`intent_id\s*=\s*\d+`)
	reStepRef     = regexp.MustCompile(`(?i)step\s*\d+`)
	reFactRef     = regexp.MustCompile(`(?i)fact\s*\d+`)
	reEvidenceVer = regexp.MustCompile(`(?i)evidence_version|report_evidence_version|证据版本`)
	reTrafficID   = regexp.MustCompile(`traffic_id\s*=\s*` + "`?" + `ev-\d+-\d+` + "`?")
	reEvID        = regexp.MustCompile(`ev-\d+-\d+`)
	reBlanks      = regexp.MustCompile(`\n{3,}`)
)

// SanitizeForExport removes platform-only metadata and ids from a finding report
// before Word/PDF rendering. The stored report (detail page) is left untouched.
func SanitizeForExport(md string) string {
	lines := strings.Split(strings.ReplaceAll(md, "\r\n", "\n"), "\n")
	var out []string
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trim := strings.TrimSpace(line)

		// Internal header blockquote: finding id/status/template note.
		if strings.HasPrefix(trim, "> 漏洞编号：") || strings.HasPrefix(trim, "> 本文按 SRC") {
			continue
		}
		// Traffic table (platform traffic ids): drop the whole table block.
		if strings.HasPrefix(trim, "|") && strings.Contains(trim, "traffic_id") {
			for i+1 < len(lines) && strings.TrimSpace(lines[i+1]) != "" {
				i++
			}
			continue
		}
		// Internal bookkeeping lines.
		if reEvidenceVer.MatchString(line) ||
			strings.Contains(line, "traffic_id") ||
			strings.Contains(line, "完整报文已绑定") ||
			strings.Contains(line, "报文已绑定为流量证据") ||
			strings.Contains(line, "get_finding_traffic") ||
			strings.Contains(line, "bind_finding_traffic") ||
			strings.Contains(line, "自动绑定") ||
			strings.Contains(line, "流量证据库") ||
			strings.Contains(line, "未绑定 HTTP 流量") ||
			strings.Contains(line, "截图仅用于人眼复核") ||
			strings.Contains(line, "截图只用于人眼快速确认") ||
			strings.Contains(line, "截图只用于证明") ||
			strings.Contains(line, "不替代原始报文") ||
			strings.Contains(line, "原始 200/206 请求与响应见 2.2") ||
			strings.Contains(line, "关键请求与响应见正文") {
			continue
		}

		line = reTrafficID.ReplaceAllString(line, "完整报文已留存")
		line = rePrevFinding.ReplaceAllString(line, "此前记录")
		line = rePrevFact.ReplaceAllString(line, "此前记录")
		line = reFindingRef.ReplaceAllString(line, "历史记录")
		line = reToolName.ReplaceAllString(line, "HTTP 请求")
		line = reNodeRef.ReplaceAllString(line, "")
		line = reWorkRef.ReplaceAllString(line, "原始执行")
		line = reIntentRef.ReplaceAllString(line, "")
		line = reStepRef.ReplaceAllString(line, "")
		line = reFactRef.ReplaceAllString(line, "历史记录")
		line = strings.ReplaceAll(line, "授权渗透测试", "SRC 漏洞挖掘")
		line = strings.ReplaceAll(line, "渗透测试", "SRC 漏洞挖掘")
		line = strings.ReplaceAll(line, "授权资产", "SRC 收录资产")
		line = strings.ReplaceAll(line, "授权面", "SRC 范围")
		line = strings.ReplaceAll(line, "授权范围", "SRC 范围")
		line = strings.ReplaceAll(line, "这把 历史记录 的", "这把此前的")
		line = strings.ReplaceAll(line, "历史记录 的", "此前的")
		line = reEvID.ReplaceAllString(line, "")
		line = strings.ReplaceAll(line, "完整报文已留存：", "")
		line = strings.ReplaceAll(line, "完整报文已留存", "")
		out = append(out, line)
	}
	res := strings.TrimSpace(reBlanks.ReplaceAllString(strings.Join(out, "\n"), "\n\n"))
	res = reBulletID.ReplaceAllString(res, "- ")
	// Drop bullets/lines left empty by removing platform evidence ids.
	var kept []string
	for _, l := range strings.Split(res, "\n") {
		t := strings.TrimSpace(l)
		if t == "-" || t == "- " || t == "" {
			kept = append(kept, "")
			continue
		}
		kept = append(kept, l)
	}
	res = reBlanks.ReplaceAllString(strings.Join(kept, "\n"), "\n\n")
	// A section emptied by removing the traffic table: drop its heading too.
	res = strings.ReplaceAll(res, "### 2.4 完整报文复验\n\n## ", "## ")
	res = strings.ReplaceAll(res, "### 2.4 完整报文复验\n\n### ", "### ")
	if strings.HasSuffix(res, "### 2.4 完整报文复验") {
		res = strings.TrimSpace(strings.TrimSuffix(res, "### 2.4 完整报文复验"))
	}
	return res
}
