package fingerprint

import (
	"net"
	"strings"
)

// multiLabelSuffixes 常见多段公共后缀（第二段为短代码时注册域取三段）。
// 覆盖 .com.cn 系即可；奇葩后缀误判最多归错链接桶，不产生安全问题。
var multiLabelSuffixes = map[string]bool{
	"com.cn": true, "net.cn": true, "org.cn": true, "gov.cn": true,
	"edu.cn": true, "ac.cn": true, "com.hk": true, "com.tw": true,
	"com.jp": true, "co.jp": true, "co.kr": true, "co.uk": true,
}

// RegistrableDomain 注册域近似（eTLD+1）：
//
//	survey.woniuxy.com        → woniuxy.com
//	beian.miit.gov.cn         → miit.gov.cn
//	mail.office.example.co.uk → example.co.uk
//	1.2.3.4                   → 1.2.3.4（IP 原样返回）
//
// 用于链接三桶分类（同主机/同主域/跨域）。不上 publicsuffix 库：纯规则覆盖
// 常见后缀，误判代价是归错桶而非漏授权校验（授权判定由 ScopeRule 独立承担）。
func RegistrableDomain(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if i := strings.LastIndexByte(host, ':'); i >= 0 && !strings.Contains(host, "]") {
		host = host[:i] // 剥端口（IPv6 含 ] 的场景不走此分支）
	}
	host = strings.Trim(host, "[].")
	if host == "" {
		return ""
	}
	if ip := net.ParseIP(host); ip != nil {
		return host
	}
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return host
	}
	last2 := strings.Join(parts[len(parts)-2:], ".")
	if len(parts) >= 3 && multiLabelSuffixes[last2] {
		return strings.Join(parts[len(parts)-3:], ".")
	}
	return last2
}
