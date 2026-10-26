package subdomain

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"github.com/c1ayooo/4zreark/internal/useragent"
	"io"
	"math/big"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/internal/recon/brute"
	"github.com/c1ayooo/4zreark/internal/recon/cdnmatch"
	"github.com/c1ayooo/4zreark/internal/recon/dnsres"
	"github.com/c1ayooo/4zreark/scanner/core"
)

// SubdomainResult represents a discovered subdomain
type SubdomainResult struct {
	Subdomain   string   `json:"subdomain"`
	Domain      string   `json:"domain"`
	FullDomain  string   `json:"full_domain"`
	// Source 是发现来源（passive:crtsh / spacemap:fofa / brute / artifact:cert-san），
	// 同一子域名被多路发现时保留首个命中的来源。
	Source      string   `json:"source,omitempty"`
	IPs         []string `json:"ips,omitempty"`
	CNAMEs      []string `json:"cnames,omitempty"`
	Alive       bool     `json:"alive"`
	HTTPStatus  int      `json:"http_status,omitempty"`
	HTTPSStatus int      `json:"https_status,omitempty"`
	Title       string   `json:"title,omitempty"`
	Server      string   `json:"server,omitempty"`
	CDN         bool     `json:"cdn"`
	CDNProvider string   `json:"cdn_provider,omitempty"`
	Fingerprint []string `json:"fingerprint,omitempty"`
	ContentLen  int64    `json:"content_length,omitempty"`
}

// DomainScanResult represents the result of domain scanning
type DomainScanResult struct {
	Domain       string            `json:"domain"`
	TotalChecked int               `json:"total_checked"`
	Found        int               `json:"found"`
	StartTime    time.Time         `json:"start_time"`
	EndTime      time.Time         `json:"end_time"`
	Duration     string            `json:"duration"`
	Subdomains   []SubdomainResult `json:"subdomains"`
	NSRecords    []string          `json:"ns_records,omitempty"`
	MXRecords    []string          `json:"mx_records,omitempty"`
	TXTRecords   []string          `json:"txt_records,omitempty"`
}

// DomainInfo represents basic domain information
type DomainInfo struct {
	Domain     string   `json:"domain"`
	IPs        []string `json:"ips"`
	CNAMEs     []string `json:"cnames"`
	NSRecords  []string `json:"ns_records"`
	MXRecords  []string `json:"mx_records"`
	TXTRecords []string `json:"txt_records"`
	SOARecord  string   `json:"soa_record,omitempty"`
}

// DomainScanner handles domain scanning and subdomain enumeration
type DomainScanner struct {
	Timeout     time.Duration
	Concurrency int
	Resolvers   []string
	EnableHTTP  bool            // 是否启用HTTP探测（会变慢但获取更多信息）
	WildcardIPs map[string]bool // 泛解析IP记录
}

// NewDomainScanner creates a new domain scanner
func NewDomainScanner(concurrency int) *DomainScanner {
	if concurrency == 0 {
		concurrency = 200 // 提高默认并发数，DNS查询很快
	}
	return &DomainScanner{
		Timeout:     2 * time.Second,
		Concurrency: concurrency,
		EnableHTTP:  false, // 默认不启用HTTP探测以提高速度
		Resolvers: []string{
			"8.8.8.8:53",
			"8.8.4.4:53",
			"1.1.1.1:53",
			"114.114.114.114:53",
			"223.5.5.5:53",
			"119.29.29.29:53", // DNSPod
			"180.76.76.76:53", // 百度DNS
		},
		WildcardIPs: make(map[string]bool),
	}
}

// NewDomainScannerWithHTTP creates a scanner with HTTP probing enabled
func NewDomainScannerWithHTTP(concurrency int) *DomainScanner {
	scanner := NewDomainScanner(concurrency)
	scanner.EnableHTTP = true
	scanner.Concurrency = 50 // HTTP探测需要降低并发
	return scanner
}

// GetSubdomainWordlist returns subdomain wordlist from config
func GetSubdomainWordlist() []string {
	wordlist := config.GetSubdomains()
	if len(wordlist) == 0 {
		// Fallback to minimal built-in list if config not loaded
		return []string{"www", "mail", "ftp", "admin", "api", "dev", "test", "blog", "shop", "m"}
	}
	return wordlist
}

// GetDomainInfo retrieves DNS information for a domain
func (s *DomainScanner) GetDomainInfo(ctx context.Context, domain string) *DomainInfo {
	info := &DomainInfo{
		Domain: domain,
	}

	// A records
	ips, err := net.LookupIP(domain)
	if err == nil {
		for _, ip := range ips {
			if ipv4 := ip.To4(); ipv4 != nil {
				info.IPs = append(info.IPs, ipv4.String())
			}
		}
	}

	// CNAME records
	cname, err := net.LookupCNAME(domain)
	if err == nil && cname != "" && cname != domain+"." {
		info.CNAMEs = append(info.CNAMEs, strings.TrimSuffix(cname, "."))
	}

	// NS records
	nsRecords, err := net.LookupNS(domain)
	if err == nil {
		for _, ns := range nsRecords {
			info.NSRecords = append(info.NSRecords, strings.TrimSuffix(ns.Host, "."))
		}
	}

	// MX records
	mxRecords, err := net.LookupMX(domain)
	if err == nil {
		for _, mx := range mxRecords {
			info.MXRecords = append(info.MXRecords, fmt.Sprintf("%s (priority: %d)", strings.TrimSuffix(mx.Host, "."), mx.Pref))
		}
	}

	// TXT records
	txtRecords, err := net.LookupTXT(domain)
	if err == nil {
		info.TXTRecords = txtRecords
	}

	return info
}

// CheckSubdomain checks if a subdomain exists (DNS only for speed)
func (s *DomainScanner) CheckSubdomain(ctx context.Context, subdomain, domain string) *SubdomainResult {
	return s.CheckFullDomain(ctx, subdomain+"."+domain)
}

// CheckFullDomain checks if a full domain (e.g. "api.example.com") exists (DNS only for speed)
func (s *DomainScanner) CheckFullDomain(ctx context.Context, host string) *SubdomainResult {
	fullDomain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	subdomain, domain := splitSubdomain(fullDomain)
	result := &SubdomainResult{
		Subdomain:  subdomain,
		Domain:     domain,
		FullDomain: fullDomain,
		Alive:      false,
	}

	// DNS查询使用自定义resolver和超时
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: s.Timeout,
			}
			// 随机选择一个DNS服务器
			resolverAddr := s.Resolvers[time.Now().UnixNano()%int64(len(s.Resolvers))]
			return d.DialContext(ctx, "udp", resolverAddr)
		},
	}

	// 设置查询超时
	queryCtx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()

	// Try to resolve the domain
	ips, err := resolver.LookupIP(queryCtx, "ip4", fullDomain)
	if err != nil {
		return result
	}

	if len(ips) == 0 {
		return result
	}

	result.Alive = true
	for _, ip := range ips {
		ipStr := ip.String()
		result.IPs = append(result.IPs, ipStr)
	}

	// 检查是否命中泛解析IP
	if s.isWildcardIP(result.IPs) {
		result.Alive = false
		return result
	}

	// Try to get CNAME (使用新的resolver)
	cname, err := resolver.LookupCNAME(queryCtx, fullDomain)
	if err == nil && cname != "" && cname != fullDomain+"." {
		result.CNAMEs = append(result.CNAMEs, strings.TrimSuffix(cname, "."))
	}

	// Check for CDN based on CNAME and IP
	result.CDN, result.CDNProvider = s.detectCDN(result.CNAMEs, result.IPs)

	// HTTP probe only if enabled (for detailed info)
	if s.EnableHTTP {
		s.httpProbe(ctx, result)
	}

	return result
}

// isWildcardIP checks if IPs match wildcard DNS records
func (s *DomainScanner) isWildcardIP(ips []string) bool {
	if len(s.WildcardIPs) == 0 {
		return false
	}
	for _, ip := range ips {
		if s.WildcardIPs[ip] {
			return true
		}
	}
	return false
}

// detectWildcardDNS detects wildcard DNS for a domain
func (s *DomainScanner) detectWildcardDNS(ctx context.Context, domain string) {
	s.WildcardIPs = make(map[string]bool)

	// 生成随机子域名测试泛解析
	testSubdomains := []string{
		generateRandomString(8),
		generateRandomString(10),
		generateRandomString(12),
	}

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: s.Timeout}
			resolverAddr := s.Resolvers[0]
			return d.DialContext(ctx, "udp", resolverAddr)
		},
	}

	wildcardCount := 0
	for _, sub := range testSubdomains {
		testDomain := sub + "." + domain
		queryCtx, cancel := context.WithTimeout(ctx, s.Timeout)
		ips, err := resolver.LookupIP(queryCtx, "ip4", testDomain)
		cancel()

		if err == nil && len(ips) > 0 {
			wildcardCount++
			for _, ip := range ips {
				s.WildcardIPs[ip.String()] = true
			}
		}
	}

	// 如果3个随机子域名都有解析，认为存在泛解析
	if wildcardCount < 2 {
		s.WildcardIPs = make(map[string]bool) // 清空，不是泛解析
	}
}

// splitSubdomain 把完整域名拆成（子域标签, 根域），仅供结果展示字段使用；
// 拆不开时子域标签为空、根域为原名。
func splitSubdomain(fullDomain string) (subdomain, domain string) {
	parts := strings.SplitN(fullDomain, ".", 2)
	if len(parts) != 2 {
		return "", fullDomain
	}
	return parts[0], parts[1]
}

// generateRandomString generates a random string for wildcard detection.
// 用 crypto/rand：此前取 UnixNano 取模 + 睡纳秒，8 位串大概率是同一字符
// 重复，泛解析判定被削弱。
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	total := big.NewInt(int64(len(charset)))
	for i := range b {
		n, err := rand.Int(rand.Reader, total)
		if err != nil {
			// 系统熵源不可用是严重异常；退化为固定模式至少可预测地失败
			b[i] = charset[i%len(charset)]
			continue
		}
		b[i] = charset[n.Int64()]
	}
	return string(b)
}

// httpProbe performs HTTP/HTTPS probing to get title, status code, etc.
func (s *DomainScanner) httpProbe(ctx context.Context, result *SubdomainResult) {
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext: (&net.Dialer{
				Timeout: 3 * time.Second,
			}).DialContext,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	// Try HTTPS first
	httpsURL := "https://" + result.FullDomain
	if resp, err := s.doHTTPRequest(ctx, client, httpsURL); err == nil {
		result.HTTPSStatus = resp.StatusCode
		if result.HTTPStatus == 0 {
			result.HTTPStatus = resp.StatusCode
		}
		s.parseHTTPResponse(resp, result)
		resp.Body.Close()
	}

	// Try HTTP
	httpURL := "http://" + result.FullDomain
	if resp, err := s.doHTTPRequest(ctx, client, httpURL); err == nil {
		result.HTTPStatus = resp.StatusCode
		if result.Title == "" {
			s.parseHTTPResponse(resp, result)
		}
		resp.Body.Close()
	}
}

// doHTTPRequest makes an HTTP request with context
func (s *DomainScanner) doHTTPRequest(ctx context.Context, client *http.Client, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", useragent.Pick())
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	return client.Do(req)
}

// parseHTTPResponse extracts information from HTTP response
func (s *DomainScanner) parseHTTPResponse(resp *http.Response, result *SubdomainResult) {
	// Get Server header
	if server := resp.Header.Get("Server"); server != "" {
		result.Server = server
		// Add to fingerprint
		result.Fingerprint = append(result.Fingerprint, server)
	}

	// Get X-Powered-By
	if poweredBy := resp.Header.Get("X-Powered-By"); poweredBy != "" {
		result.Fingerprint = append(result.Fingerprint, poweredBy)
	}

	// Read body for title (limit to 64KB)
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err == nil {
		result.ContentLen = int64(len(body))

		// Extract title
		if title := core.ExtractTitle(string(body)); title != "" {
			result.Title = title
		}

		// Simple fingerprint detection from body
		bodyStr := strings.ToLower(string(body))
		fingerprints := detectFingerprints(bodyStr, resp.Header)
		result.Fingerprint = append(result.Fingerprint, fingerprints...)
	}

	// Remove duplicates from fingerprint
	result.Fingerprint = uniqueStrings(result.Fingerprint)
}

// detectFingerprints detects web technologies from response
func detectFingerprints(body string, headers http.Header) []string {
	var fps []string

	// Common frameworks/technologies
	patterns := map[string][]string{
		"WordPress":  {"wp-content", "wp-includes", "wordpress"},
		"Drupal":     {"drupal", "sites/all", "sites/default"},
		"Joomla":     {"joomla", "/components/com_"},
		"ThinkPHP":   {"thinkphp", "think\\"},
		"Laravel":    {"laravel", "laravel_session"},
		"Spring":     {"spring", "j_spring_security"},
		"React":      {"react", "_react", "reactroot"},
		"Vue.js":     {"vue.js", "vue.min.js", "__vue__"},
		"Angular":    {"angular", "ng-version"},
		"jQuery":     {"jquery"},
		"Bootstrap":  {"bootstrap"},
		"Nginx":      {"nginx"},
		"Apache":     {"apache"},
		"IIS":        {"iis", "asp.net"},
		"Tomcat":     {"tomcat", "catalina"},
		"WebLogic":   {"weblogic"},
		"phpMyAdmin": {"phpmyadmin"},
		"Confluence": {"confluence"},
		"JIRA":       {"jira"},
		"GitLab":     {"gitlab"},
		"Jenkins":    {"jenkins"},
	}

	for tech, keywords := range patterns {
		for _, kw := range keywords {
			if strings.Contains(body, kw) {
				fps = append(fps, tech)
				break
			}
		}
	}

	// Check headers for tech
	if setCookie := headers.Get("Set-Cookie"); setCookie != "" {
		setCookieLower := strings.ToLower(setCookie)
		if strings.Contains(setCookieLower, "phpsessid") {
			fps = append(fps, "PHP")
		}
		if strings.Contains(setCookieLower, "jsessionid") {
			fps = append(fps, "Java")
		}
		if strings.Contains(setCookieLower, "asp.net") {
			fps = append(fps, "ASP.NET")
		}
	}

	return fps
}

// detectCDN detects if the domain is using a CDN.
// T12：CNAME/IP 判定统一交给 reconkit cdnmatch（一份分类器 + 可覆盖 JSON），
// 不再维护第三张硬编码表。
func (s *DomainScanner) detectCDN(cnames []string, ips []string) (bool, string) {
	for _, cname := range cnames {
		if r := cdnmatch.Classify(cname, nil); r.EdgeType != "" {
			return true, r.EdgeName
		}
	}
	if r := cdnmatch.Classify("", ips); r.EdgeType != "" {
		return true, r.EdgeName
	}
	return false, ""
}

// checkCDNByIP checks if IP belongs to known CDN ranges.
func checkCDNByIP(ip string) string {
	if r := cdnmatch.Classify("", []string{ip}); r.EdgeType != "" {
		return r.EdgeName
	}
	return ""
}

// uniqueStrings removes duplicates from string slice
func uniqueStrings(input []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0)
	for _, s := range input {
		if s != "" && !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

// BruteSubdomains performs subdomain brute-force enumeration.
//
// T11：直接改用 reconkit 的纯 Go 爆破（dnsres 解析池 + 令牌桶限速 +
// 泛解析基线过滤），不再走 ksubdomain 库/子进程。HTTP 探测与指纹由调用方
// 后续的 httpx 阶段完成，这里只负责「名字是否解析」。
func (s *DomainScanner) BruteSubdomains(ctx context.Context, domain string, wordlist []string) *DomainScanResult {
	start := time.Now()
	result := &DomainScanResult{
		Domain:       domain,
		TotalChecked: len(wordlist),
		StartTime:    start,
		Subdomains:   make([]SubdomainResult, 0),
	}

	// 域名基础信息（NS/MX/TXT）与爆破并行没有依赖，先取。
	domainInfo := s.GetDomainInfo(ctx, domain)
	result.NSRecords = domainInfo.NSRecords
	result.MXRecords = domainInfo.MXRecords
	result.TXTRecords = domainInfo.TXTRecords

	pool := dnsres.NewPool(s.Resolvers, s.Concurrency, s.Timeout, 2)
	hits, stats, err := brute.Brute(ctx, domain, brute.Options{
		Words: wordlist,
		Pool:  pool,
		QPS:   300,
	})
	if err != nil {
		fmt.Printf("[*] 子域爆破失败 %s: %v\n", domain, err)
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(result.StartTime).String()
		return result
	}
	if stats.Wildcard {
		fmt.Printf("[*] 检测到泛解析域名 %s，已过滤 %d 条泛解析命中\n", domain, stats.WildcardFiltered)
	}

	for _, h := range hits {
		item := SubdomainResult{
			Subdomain:  h.Name,
			Domain:     domain,
			FullDomain: h.Name,
			IPs:        h.IPs,
			Alive:      true,
		}
		if h.CNAME != "" {
			item.CNAMEs = []string{h.CNAME}
		}
		result.Subdomains = append(result.Subdomains, item)
	}

	sort.Slice(result.Subdomains, func(i, j int) bool {
		return result.Subdomains[i].Subdomain < result.Subdomains[j].Subdomain
	})

	result.TotalChecked = stats.Probed
	result.Found = len(result.Subdomains)
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime).String()
	return result
}

// QuickSubdomainScan performs a quick subdomain scan with common subdomains
func (s *DomainScanner) QuickSubdomainScan(ctx context.Context, domain string) *DomainScanResult {
	wordlist := GetSubdomainWordlist()
	// Use first 200 for quick scan
	if len(wordlist) > 200 {
		wordlist = wordlist[:200]
	}
	return s.BruteSubdomains(ctx, domain, wordlist)
}

// FullSubdomainScan performs a full subdomain scan with extended wordlist
func (s *DomainScanner) FullSubdomainScan(ctx context.Context, domain string) *DomainScanResult {
	return s.BruteSubdomains(ctx, domain, GetSubdomainWordlist())
}

// CustomSubdomainScan performs subdomain scan with custom wordlist
func (s *DomainScanner) CustomSubdomainScan(ctx context.Context, domain string, wordlist []string) *DomainScanResult {
	return s.BruteSubdomains(ctx, domain, wordlist)
}

// ParseWordlist parses a wordlist string (newline or comma separated)
func ParseWordlist(input string) []string {
	var wordlist []string
	seen := make(map[string]bool)

	// Try newline separated first
	scanner := bufio.NewScanner(strings.NewReader(input))
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" && !seen[word] {
			seen[word] = true
			wordlist = append(wordlist, word)
		}
	}

	// If no newlines, try comma separated
	if len(wordlist) <= 1 && strings.Contains(input, ",") {
		wordlist = nil
		seen = make(map[string]bool)
		parts := strings.Split(input, ",")
		for _, part := range parts {
			word := strings.TrimSpace(part)
			if word != "" && !seen[word] {
				seen[word] = true
				wordlist = append(wordlist, word)
			}
		}
	}

	return wordlist
}
