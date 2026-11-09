package service

// 提交预评分（watchlist 种子 v1.0：commit_keywords + path_whitelist）。
//
// 定位：只影响判定优先级，不做跳过——提交标题经常骗人
// （Text4Shell 修复标题无任何 CVE 字样），diff 才是真相。
// high_signal 命中排前、path 白名单加权、downgrade 词降权（下限 0）。

import "strings"

// highSignalKeywords 是种子文件的 high_signal 词表（小写）。
var highSignalKeywords = []string{
	"auth bypass", "privilege escalation", "ssrf", "rce", "deserializ", "ssti",
	"prototype pollution", "path traversal", "arbitrary file", "jwt", "alg:none",
	"signature", "csrf", "idor", "acl", "rbac", "sanitiz", "escape", "xss",
	"sqli", "command injection", "eval(", "unserialize", "pickle", "yaml.load",
	"os.exec", "shell=true", "header spoof", "x-forwarded", "trust proxy",
	"open redirect", "cve", "ghsa", "vulnerab", "secur",
}

// downgradeKeywords 是降权词表（refactor/typo/ci 等常规提交）。
var downgradeKeywords = []string{
	"refactor", "typo", "lint", "doc", "ci", "chore", "i18n", "translation",
	"bump", "upgrade", "update dependency", "release",
}

// sensitivePathPatterns 是 path_whitelist 的目录片段（小写），
// diff 改动路径命中任一片段即视为高价值变更。
var sensitivePathPatterns = []string{
	"/auth/", "/middleware/", "/security/", "/rbac/", "/acl/", "/permission",
	"/parser/", "/deserialize", "/serialize", "/render/", "/template", "/view/",
	"/upload", "/storage/", "/file", "/proxy/", "/router/", "/handler/",
	"/oauth", "/jwt", "/crypto", "/sanitiz", "/escape", "/validate",
	"/ssrf", "/cors", "/csrf", "token", "session", "password",
}

// ScoreCommit 给提交打预评分（非负）：
//   - 标题命中 high_signal：每个 +3
//   - 标题命中 downgrade：每个 -1（下限 0）
//   - diff 变更路径命中敏感片段：+5（一次）
func ScoreCommit(subject string, files []FileChange) int {
	s := strings.ToLower(subject)
	score := 0
	for _, kw := range highSignalKeywords {
		if strings.Contains(s, kw) {
			score += 3
		}
	}
	for _, kw := range downgradeKeywords {
		if strings.Contains(s, kw) {
			score--
		}
	}
	for _, f := range files {
		p := strings.ToLower(f.Path)
		for _, pat := range sensitivePathPatterns {
			if strings.Contains(p, pat) {
				score += 5
				return score
			}
		}
	}
	if score < 0 {
		score = 0
	}
	return score
}

// gradeForVerdict 把判定结论映射为种子文件的 S/A/B/C 分级：
//   - S：critical + 注入类/反序列化/SSRF（未公开可达 RCE 形态）
//   - A：high 或 权限绕过/反序列化/路径穿越类
//   - B：medium/low 或 XSS/信息泄露类
//   - C：非安全修复
func gradeForVerdict(isSecurityFix bool, vulnClass, severity string) string {
	if !isSecurityFix {
		return "C"
	}
	rc := map[string]bool{
		"INJECTION": true, "SSRF": true, "DESERIALIZATION": true,
		"OOB_WRITE": true, "AUTH_BYPASS": true, "PRIV_ESC": true,
	}
	if severity == "critical" {
		return "S"
	}
	if severity == "high" || rc[vulnClass] {
		return "A"
	}
	return "B"
}
