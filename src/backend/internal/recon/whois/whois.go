// Package whois 域名注册信息查询：IANA :43 转介 + 权威 whois 服务器二次查询，
// 纯 Go 实现（net.Dial，无第三方依赖）。对应 OneForAll 的 whois 模块组。
//
// 用途：注册人/注册商/注册与到期时间/NS 是资产归属判定与到期监控的基础线索。
// 注意：明文 TCP 协议，不走出网代理（socks/http 代理不适用 raw TCP）；
// 查询频率请自我节制（各注册商对 :43 有速率限制）。
//
// 「反查」（按注册人/邮箱找域名）绝大多数 whois 服务器不支持，需要付费 API，
// 本包只做正向查询；反查留待接入专门数据源。
package whois

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

// Record 解析后的域名注册信息。字段缺失 = 上游未返回（解析留空，不猜）。
type Record struct {
	Domain        string   `json:"domain"`
	Registrar     string   `json:"registrar,omitempty"`
	RegistrarURL  string   `json:"registrar_url,omitempty"`
	RegistrantOrg string   `json:"registrant_org,omitempty"`
	RegistrantPun string   `json:"registrant_pun,omitempty"` // 注册人/联系人（个人名）
	RegistrantEml string   `json:"registrant_email,omitempty"`
	CreationDate  string   `json:"creation_date,omitempty"`
	UpdatedDate   string   `json:"updated_date,omitempty"`
	ExpiryDate    string   `json:"expiry_date,omitempty"`
	Status        []string `json:"status,omitempty"`
	NameServers   []string `json:"name_servers,omitempty"`
	DNSSEC        string   `json:"dnssec,omitempty"`
	// Server 实际应答的权威 whois 服务器（排查数据口径用）。
	Server string `json:"server,omitempty"`
	// RawText 权威服务器原始应答（截断后），供前端展开核查。
	RawText string `json:"raw_text,omitempty"`
}

// ianaWhoisServer IANA 根 whois。包级变量：测试注入 mock 服务器用。
var ianaWhoisServer = "whois.iana.org"

const (
	queryTimeout  = 10 * time.Second
	rawTextLimit  = 8 * 1024
	maxRespSize   = 64 * 1024
	redactedToken = "redacted" // GDPR 脱敏占位（REDACTED FOR PRIVACY 等）
)

// Query 查询域名注册信息：先问 IANA 拿权威服务器，再查权威（必要时按
// Registrar WHOIS Server 转介一次）。
func Query(ctx context.Context, domain string) (*Record, error) {
	domain = normalizeDomain(domain)
	if domain == "" {
		return nil, fmt.Errorf("域名无效")
	}

	raw, err := askServer(ctx, ianaWhoisServer, domain)
	if err != nil {
		return nil, fmt.Errorf("IANA 转介查询失败: %w", err)
	}
	server := parseReferServer(raw)
	if server == "" || strings.EqualFold(server, ianaWhoisServer) {
		// IANA 自己就是权威（小众 TLD / 保留域）：直接用 IANA 的应答解析，
		// 不对 IANA 重复发一次查询。
		rec := parse(domain, raw, ianaWhoisServer)
		if rec.Registrar == "" && rec.CreationDate == "" && len(rec.NameServers) == 0 {
			return nil, fmt.Errorf("IANA 无 %s 的注册数据（TLD 未开放 whois）", domain)
		}
		return rec, nil
	}

	raw, err = askServer(ctx, server, domain)
	if err != nil {
		return nil, fmt.Errorf("查询 %s 失败: %w", server, err)
	}
	rec := parse(domain, raw, server)

	// 注册商级 whois 字段更全：有转介就再问一层。
	if next := parseRegistrarServer(raw); next != "" && !strings.EqualFold(next, server) {
		if raw2, err := askServer(ctx, next, domain); err == nil {
			rec2 := parse(domain, raw2, next)
			mergeRecord(rec, rec2)
		}
	}
	return rec, nil
}

// askServer 对 whois 服务器发一次查询并读完应答。
func askServer(ctx context.Context, server, query string) (string, error) {
	host, port := splitServerAddr(server)
	d := net.Dialer{Timeout: queryTimeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return "", err
	}
	defer conn.Close()

	deadline := time.Now().Add(queryTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)

	if _, err := conn.Write([]byte(query + "\r\n")); err != nil {
		return "", err
	}
	buf := make([]byte, maxRespSize)
	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		return "", err
	}
	return strings.TrimSpace(string(buf[:n])), nil
}

func splitServerAddr(server string) (string, string) {
	if host, port, err := net.SplitHostPort(server); err == nil && port != "" {
		return host, port
	}
	return server, "43"
}

func normalizeDomain(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.TrimPrefix(v, "https://")
	v = strings.TrimPrefix(v, "http://")
	if i := strings.IndexAny(v, "/:?"); i >= 0 {
		v = v[:i]
	}
	v = strings.TrimSuffix(v, ".")
	if v == "" || !strings.Contains(v, ".") || strings.ContainsAny(v, " \t") {
		return ""
	}
	return v
}

var (
	reReferServer = regexp.MustCompile(`(?im)^\s*(?:whois|refer|registrar whois server):\s*(\S+)`)
	// registrarRefRe 注册商转介（权威 whois 应答内）。
	registrarRefRe = regexp.MustCompile(`(?im)^\s*registrar whois server:\s*(\S+)`)
)

func parseReferServer(raw string) string {
	if m := reReferServer.FindStringSubmatch(raw); m != nil {
		return strings.TrimSpace(m[1])
	}
	return ""
}

func parseRegistrarServer(raw string) string {
	if m := registrarRefRe.FindStringSubmatch(raw); m != nil {
		return strings.TrimSpace(m[1])
	}
	return ""
}

// 字段抽取：同一字段在不同注册商响应里的标签变体，按序取第一个命中。
var fieldPatterns = map[string]*regexp.Regexp{
	"Registrar":     compileFields(`registrar:`),
	"RegistrarURL":  compileFields(`registrar (?:url|website):`, `registration service url:`),
	"RegistrantOrg": compileFields(`registrant organization:`, `registrant organization\b.*:`, `organi[sz]ation:`, `单位名称：`),
	"RegistrantPun": compileFields(`registrant name:`, `registrant:\s`, `registrant contact name:`, ` registrant：`),
	"RegistrantEml": compileFields(`registrant email:`, `registrant contact email:`, `e-?mail：`),
	"CreationDate":  compileFields(`creation date:`, `created(?: on)?:`, `registration time:`, `注册时间：`),
	"UpdatedDate":   compileFields(`updated date:`, `last updated on:`, `changed:`, `域名更新日期：`),
	"ExpiryDate":    compileFields(`registrar registration expiration date:`, `registry expiry date:`, `expiration(?: date| time)?:`, `expiry date:`, `过期时间：`),
	"DNSSEC":        compileFields(`dnssec:`),
}

func compileFields(alts ...string) *regexp.Regexp {
	return regexp.MustCompile(`(?im)^\s*(?:` + strings.Join(alts, `|`) + `)\s*:?\s*(.+)$`)
}

var nameServerRe = regexp.MustCompile(`(?im)^\s*(?:name server|nserver|ns[1-4]|dns server)\s*:?\s*(\S+)`)
var statusRe = regexp.MustCompile(`(?im)^\s*(?:domain status|status|state)\s*:?\s*(\S.+)$`)

// parse 从 whois 应答文本提取结构化字段。解析不到的字段留空。
func parse(domain, raw, server string) *Record {
	rec := &Record{Domain: domain, Server: server}
	get := func(re *regexp.Regexp) string {
		if m := re.FindStringSubmatch(raw); m != nil {
			return cleanValue(m[1])
		}
		return ""
	}
	rec.Registrar = get(fieldPatterns["Registrar"])
	rec.RegistrarURL = get(fieldPatterns["RegistrarURL"])
	rec.RegistrantOrg = get(fieldPatterns["RegistrantOrg"])
	rec.RegistrantPun = get(fieldPatterns["RegistrantPun"])
	rec.RegistrantEml = get(fieldPatterns["RegistrantEml"])
	rec.CreationDate = get(fieldPatterns["CreationDate"])
	rec.UpdatedDate = get(fieldPatterns["UpdatedDate"])
	rec.ExpiryDate = get(fieldPatterns["ExpiryDate"])
	rec.DNSSEC = get(fieldPatterns["DNSSEC"])

	for _, m := range statusRe.FindAllStringSubmatch(raw, -1) {
		v := cleanValue(m[1])
		if v != "" {
			rec.Status = append(rec.Status, v)
		}
	}
	seenNS := map[string]bool{}
	for _, m := range nameServerRe.FindAllStringSubmatch(raw, -1) {
		ns := strings.TrimSuffix(strings.ToLower(cleanValue(m[1])), ".")
		if ns != "" && !seenNS[ns] {
			seenNS[ns] = true
			rec.NameServers = append(rec.NameServers, ns)
		}
	}

	if len(raw) > rawTextLimit {
		raw = raw[:rawTextLimit] + "\n…（截断）"
	}
	rec.RawText = raw
	return rec
}

// cleanValue 去掉值里的 GDPR 脱敏占位与注释噪音。
func cleanValue(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	// "data protected" / "REDACTED FOR PRIVACY" 等占位视同未提供
	if strings.Contains(strings.ToLower(v), redactedToken) ||
		strings.Contains(strings.ToLower(v), "data protected") ||
		strings.Contains(v, "Please query the whois service") {
		return ""
	}
	if i := strings.Index(v, " //"); i > 0 { // 去掉行内注释（部分注册商带提示）
		v = v[:i]
	}
	return strings.TrimSpace(v)
}

// mergeRecord 注册商级应答补全注册局级缺失的字段（不反向覆盖）。
func mergeRecord(base, extra *Record) {
	if extra == nil {
		return
	}
	if base.Registrar == "" {
		base.Registrar = extra.Registrar
	}
	if base.RegistrarURL == "" {
		base.RegistrarURL = extra.RegistrarURL
	}
	if base.RegistrantOrg == "" {
		base.RegistrantOrg = extra.RegistrantOrg
	}
	if base.RegistrantPun == "" {
		base.RegistrantPun = extra.RegistrantPun
	}
	if base.RegistrantEml == "" {
		base.RegistrantEml = extra.RegistrantEml
	}
	if base.CreationDate == "" {
		base.CreationDate = extra.CreationDate
	}
	if base.UpdatedDate == "" {
		base.UpdatedDate = extra.UpdatedDate
	}
	if base.ExpiryDate == "" {
		base.ExpiryDate = extra.ExpiryDate
	}
	if base.DNSSEC == "" {
		base.DNSSEC = extra.DNSSEC
	}
	if len(base.NameServers) == 0 {
		base.NameServers = extra.NameServers
	}
	if len(base.Status) == 0 {
		base.Status = extra.Status
	}
	base.RawText = extra.RawText
	base.Server = extra.Server
}
