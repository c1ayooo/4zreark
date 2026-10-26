package componentprofile

import "strings"

// 规范化：把各种来源的产品名统一成「小写、连字符分隔、去版本」的键。
//
// 例：
//
//	"Apache-Tomcat"        → apache-tomcat
//	"nginx/1.24.0"         → nginx
//	"Apache Tomcat 9.0.65" → apache-tomcat
//	"H3C ER3108GW"         → h3c-er3108gw
//	"HZERO"                → hzero
//
// 规则：按非字母数字切分；丢弃纯数字 token（版本残留）；用 '-' 连接。
func Normalize(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" {
		return ""
	}
	// 版本斜杠形式：nginx/1.24 → 取斜杠前主体
	if i := strings.IndexByte(s, '/'); i > 0 {
		head := s[:i]
		tail := s[i+1:]
		if looksLikeVersion(tail) {
			s = head
		}
	}
	fields := splitAlnum(s)
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if isNumeric(f) || isVersionOnly(f) {
			continue
		}
		out = append(out, f)
	}
	return strings.Join(out, "-")
}

// isVersionOnly 判断 token 是否只是版本号（v2 / v10），避免"v2"被当成产品名。
func isVersionOnly(tok string) bool {
	if len(tok) < 2 || tok[0] != 'v' {
		return false
	}
	for i := 1; i < len(tok); i++ {
		if tok[i] < '0' || tok[i] > '9' {
			return false
		}
	}
	return true
}

// lowerTrim 原始名的小写去空白形式（别名比对用）。
func lowerTrim(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// splitAlnum 按非 [a-z0-9] 切分，丢弃空段。
func splitAlnum(s string) []string {
	var out []string
	var b strings.Builder
	flush := func() {
		if b.Len() > 0 {
			out = append(out, b.String())
			b.Reset()
		}
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			continue
		}
		flush()
	}
	flush()
	return out
}

// looksLikeVersion 判断字符串是否像版本号（1.24 / 9.0.65 / v2 / 1.2.3-beta）。
func looksLikeVersion(s string) bool {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	if s == "" {
		return false
	}
	if s[0] < '0' || s[0] > '9' {
		return false
	}
	dotCount, digitCount := 0, 0
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			digitCount++
		case r == '.':
			dotCount++
		case r == '-' || r == '_' || (r >= 'a' && r <= 'z'):
			// 允许版本后缀（-beta/rc1），但要求整体以数字开头
		default:
			return false
		}
	}
	return digitCount > 0 && (dotCount > 0 || digitCount == len(s))
}

func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// Tokens 拆分规范化键为 token 集合。
func Tokens(norm string) []string {
	if norm == "" {
		return nil
	}
	parts := strings.Split(norm, "-")
	out := make([]string, 0, len(parts))
	seen := make(map[string]bool, len(parts))
	for _, p := range parts {
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// genericTokens 不承载组件语义的通用词：技能名拆解与产品名匹配时忽略。
var genericTokens = map[string]bool{
	// 动作/类型
	"exploitation": true, "exploit": true, "exploits": true, "testing": true, "test": true,
	"attack": true, "attacks": true, "abuse": true, "injection": true, "hunting": true,
	"vulnerability": true, "vulnerabilities": true, "vuln": true, "vulns": true,
	"security": true, "scan": true, "scanner": true, "scanning": true, "detection": true,
	"bypass": true, "techniques": true, "technique": true, "methods": true, "method": true,
	"checklist": true, "playbook": true, "playbooks": true, "guide": true, "guidebook": true,
	// 名词/范围
	"common": true, "web": true, "api": true, "app": true, "application": true, "apps": true,
	"server": true, "servers": true, "service": true, "services": true, "system": true,
	"systems": true, "platform": true, "platforms": true, "framework": true, "frameworks": true,
	"component": true, "components": true, "module": true, "modules": true, "plugin": true,
	"plugins": true, "intel": true, "intelligence": true, "corpus": true, "local": true,
	"and": true, "the": true, "for": true, "with": true, "from": true, "into": true,
	"deep": true, "advanced": true, "basic": true, "full": true, "all": true, "top": true,
	"hidden": true, "misc": true, "other": true, "others": true, "general": true,
	"discovery": true, "enumeration": true, "exploration": true, "research": true,
	"token": true, "tokens": true, "credential": true, "credentials": true, "auth": true,
	"authentication": true, "authorization": true, "session": true, "sessions": true,
	"misconfiguration": true, "misconfig": true, "hardening": true, "audit": true,
	"assessment": true, "response": true, "incident": true, "awareness": true,
	"training": true, "discipline": true, "scope": true, "standards": true, "output": true,
	"blackboard": true, "agent": true, "agents": true, "os": true, "automation": true,
	// 形态/范围词：不指向具体组件
	"cloud": true, "container": true, "containers": true, "mobile": true, "binary": true,
	"wireless": true, "hardware": true, "network": true, "networks": true, "intranet": true,
	"penetration": true, "pentest": true, "redteam": true, "victim": true, "target": true,
	"targets": true, "type": true, "types": true, "juggling": true, "race": true,
	"condition": true, "conditions": true, "request": true, "requests": true,
	"parameter": true, "parameters": true, "path": true, "paths": true, "open": true,
	"redirect": true, "cache": true, "deception": true, "cross": true, "origin": true,
	"origins": true, "sql": true, "sqli": true, "side": true,
}

// IsGenericToken 判断 token 是否不承载组件语义。
func IsGenericToken(tok string) bool {
	return genericTokens[strings.ToLower(strings.TrimSpace(tok))]
}

// vendorTokens 厂商名：单独出现时不足以定位组件（"apache" 命中全部 Apache 系产品）。
var vendorTokens = map[string]bool{
	"apache": true, "oracle": true, "microsoft": true, "google": true, "amazon": true,
	"aws": true, "azure": true, "ibm": true, "cisco": true, "huawei": true, "h3c": true,
	"dell": true, "hp": true, "f5": true, "citrix": true, "vmware": true, "atlassian": true,
	"jetbrains": true, "adobe": true, "sap": true, "zoho": true, "salesforce": true,
	"alibaba": true, "tencent": true, "baidu": true, "jd": true, "netease": true, "sina": true,
	"nginx": false, // nginx 本身是产品，不是厂商（显式排除，勿删）
}

// IsVendorToken 判断 token 是否只是厂商名。
func IsVendorToken(tok string) bool {
	return vendorTokens[strings.ToLower(strings.TrimSpace(tok))]
}

// MatchTokens 返回用于档案兜底查询的「有区分度」token：
// 过滤通用词与厂商词；全被过滤时返回 nil（宁可不匹配，也不乱匹配）。
func MatchTokens(norm string) []string {
	var out []string
	for _, t := range Tokens(norm) {
		if IsGenericToken(t) || IsVendorToken(t) {
			continue
		}
		if len([]rune(t)) < 2 {
			continue
		}
		out = append(out, t)
	}
	return out
}

// SkillComponentTokens 从技能名/描述提取「组件 token」：
//   - 名称 token（按 '-'/'_' 切分）——高置信，派生 auto 边；
//   - 描述中的 ASCII 词（长度 ≥4）——低置信，派生 unreviewed 边，仅落库待审。
//
// 返回 (nameTokens, descTokens)，均已去通用词、去纯数字、小写去重。
func SkillComponentTokens(name, description string) (nameTokens, descTokens []string) {
	nameTokens = distinctiveTokens(strings.Split(strings.ToLower(name), "-"), 3)
	descTokens = distinctiveTokens(asciiWords(strings.ToLower(description), 4), 4)
	// 描述 token 里剔除已在名称中出现过的，避免重复边
	nameSet := make(map[string]bool, len(nameTokens))
	for _, t := range nameTokens {
		nameSet[t] = true
	}
	filtered := descTokens[:0]
	for _, t := range descTokens {
		if !nameSet[t] {
			filtered = append(filtered, t)
		}
	}
	return nameTokens, filtered
}

func distinctiveTokens(in []string, minLen int) []string {
	seen := make(map[string]bool, len(in))
	var out []string
	for _, t := range in {
		t = strings.TrimSpace(t)
		if t == "" || seen[t] || IsGenericToken(t) {
			continue
		}
		if len([]rune(t)) < minLen {
			continue
		}
		if isNumeric(t) || isVersionOnly(t) {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	return out
}

// asciiWords 提取长度 ≥minLen 的纯 ASCII 字母/数字词（用于英文描述）。
func asciiWords(s string, minLen int) []string {
	var out []string
	var b strings.Builder
	flush := func() {
		if b.Len() >= minLen {
			out = append(out, b.String())
		}
		b.Reset()
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			continue
		}
		flush()
	}
	flush()
	return out
}
