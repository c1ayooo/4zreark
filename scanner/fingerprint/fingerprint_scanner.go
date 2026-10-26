package fingerprint

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/internal/useragent"
	"github.com/c1ayooo/4zreark/scanner/core"
	"hash"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spaolacci/murmur3"
	"gopkg.in/yaml.v3"
)

// FingerprintResult represents fingerprint detection result
type FingerprintResult struct {
	Target       string            `json:"target"`
	URL          string            `json:"url,omitempty"`
	StatusCode   int               `json:"status_code,omitempty"`
	Title        string            `json:"title,omitempty"`
	Server       string            `json:"server,omitempty"`
	PoweredBy    string            `json:"powered_by,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	IconHash     string            `json:"icon_hash,omitempty"`
	IconMD5      string            `json:"icon_md5,omitempty"`
	IconSHA256   string            `json:"icon_sha256,omitempty"`
	IconMMH3     int64             `json:"icon_mmh3,omitempty"`
	IconType     string            `json:"icon_content_type,omitempty"`
	IconData     []byte            `json:"-"`
	BodyHash     string            `json:"body_hash,omitempty"`
	BodyLength   int               `json:"body_length,omitempty"`
	// 响应富化：一次扫描顺带采集的画像字段（fpmine 挖掘与资产分级用）
	CertOrg      string    `json:"cert_org,omitempty"`       // TLS 证书 Subject.Organization
	CertNotAfter time.Time `json:"cert_not_after,omitempty"` // TLS 证书到期时间（证书到期提醒用）
	CookieNames  []string  `json:"cookie_names,omitempty"`   // Set-Cookie 的 cookie 名集合
	JSFrameworks []string `json:"js_frameworks,omitempty"` // JS bundle 里的框架@版本（vue@3.4.21）
	APIHosts    []string `json:"api_hosts,omitempty"`     // JS 里引用的 API/资源域名（跨域归属线索）
	Fingerprints []Fingerprint     `json:"fingerprints"`
	Technologies []string          `json:"technologies,omitempty"`
	CMS          string            `json:"cms,omitempty"`
	Framework    string            `json:"framework,omitempty"`
	WebServer    string            `json:"web_server,omitempty"`
	OS           string            `json:"os,omitempty"`
	Language     string            `json:"language,omitempty"`
	JSLibraries  []string          `json:"js_libraries,omitempty"`
	ScanTime     time.Duration     `json:"scan_time_ms"`
}

// Fingerprint represents a single fingerprint match
type Fingerprint struct {
	Name       string `json:"name"`
	Category   string `json:"category"`
	Version    string `json:"version,omitempty"`
	Confidence int    `json:"confidence"`
	Method     string `json:"method"` // header, body, icon, title, etc.
}

// PortFingerprint represents service fingerprint on a port
type PortFingerprint struct {
	Port        int       `json:"port"`
	Service     string    `json:"service"`
	Version     string    `json:"version,omitempty"`
	Product     string    `json:"product,omitempty"`
	Info        string    `json:"info,omitempty"`
	Banner      string    `json:"banner,omitempty"`
	SSL         bool      `json:"ssl"`
	Certificate *CertInfo `json:"certificate,omitempty"`
}

// CertInfo represents SSL certificate information
type CertInfo struct {
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	SANs        []string  `json:"sans,omitempty"`
	Fingerprint string    `json:"fingerprint"`
}

// FingerprintScanner handles fingerprint detection
type FingerprintScanner struct {
	Timeout       time.Duration
	HTTPClient    *http.Client
	Concurrency   int
	DSLEngine     *DSLEngine                // DSL fingerprint engine
	JSLibPatterns map[string]*regexp.Regexp // JS library detection patterns
	PortServices  map[int]string            // Port to service mapping
}

// NewFingerprintScanner creates a new fingerprint scanner
func NewFingerprintScanner(concurrency int) *FingerprintScanner {
	if concurrency <= 0 {
		concurrency = core.DefaultFingerprintConcurrency
	}

	scanner := &FingerprintScanner{
		Timeout: core.FingerprintHTTPTimeout,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				DialContext: (&net.Dialer{
					Timeout:   core.DefaultHTTPTimeout,
					KeepAlive: core.DefaultHTTPTimeout,
				}).DialContext,
				MaxIdleConns:        core.MaxIdleConns,
				MaxIdleConnsPerHost: core.MaxIdleConnsPerHost,
				IdleConnTimeout:     core.IdleConnTimeout,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
		Concurrency: concurrency,
	}

	// Initialize DSL engine and load fingerprint rules
	scanner.DSLEngine = NewDSLEngine()
	scanner.JSLibPatterns = make(map[string]*regexp.Regexp)
	scanner.PortServices = make(map[int]string)
	scanner.loadFingerprintRules()

	return scanner
}

// ScanFingerprint performs fingerprint detection on a URL
func (s *FingerprintScanner) ScanFingerprint(ctx context.Context, target string) *FingerprintResult {
	start := time.Now()
	result := &FingerprintResult{
		Target:       target,
		Headers:      make(map[string]string),
		Fingerprints: make([]Fingerprint, 0),
		Technologies: make([]string, 0),
		JSLibraries:  make([]string, 0),
	}

	// Normalize URL
	url := target
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "http://" + target
	}
	result.URL = url

	// Fetch page
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		result.ScanTime = time.Since(start) / time.Millisecond
		return result
	}
	req.Header.Set("User-Agent", useragent.Pick())
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")

	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		// Try HTTPS
		if strings.HasPrefix(url, "http://") {
			url = strings.Replace(url, "http://", "https://", 1)
			result.URL = url
			req, _ = http.NewRequestWithContext(ctx, "GET", url, nil)
			req.Header.Set("User-Agent", useragent.Pick())
			resp, err = s.HTTPClient.Do(req)
			if err != nil {
				result.ScanTime = time.Since(start) / time.Millisecond
				return result
			}
		} else {
			result.ScanTime = time.Since(start) / time.Millisecond
			return result
		}
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode

	// Read body (limit to 1MB)
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		result.ScanTime = time.Since(start) / time.Millisecond
		return result
	}
	bodyStr := string(body)
	result.BodyLength = len(body)

	// Calculate body hash
	bodyMD5 := md5.Sum(body)
	result.BodyHash = hex.EncodeToString(bodyMD5[:])

	// Extract headers
	for key, values := range resp.Header {
		result.Headers[key] = strings.Join(values, ", ")
	}

	// Extract common headers
	result.Server = resp.Header.Get("Server")
	result.PoweredBy = resp.Header.Get("X-Powered-By")

	// Extract title
	result.Title = extractPageTitle(bodyStr)

	// Extract JS libraries
	result.JSLibraries = s.extractJSLibraries(bodyStr)

	// Try to get favicon hash
	iconHash, iconMD5, iconSHA, iconMMH3, iconData, iconType := s.getFaviconHash(ctx, url)
	result.IconHash = iconHash
	result.IconMD5 = iconMD5
	result.IconSHA256 = iconSHA
	result.IconMMH3 = iconMMH3
	result.IconData = iconData
	result.IconType = iconType

	// 证书归属先进 result：cert 规则的匹配数据源（富化随后复用，不重复取）
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		cert := resp.TLS.PeerCertificates[0]
		result.CertOrg = strings.Join(cert.Subject.Organization, " ")
		result.CertNotAfter = cert.NotAfter
	}

	// Use DSL engine for fingerprint detection
	s.detectFingerprintsWithDSL(result, bodyStr, iconHash, iconMD5)

	// 响应富化：证书归属 / cookie 名集合 / JS 框架版本与 API 域名。
	// JS 分析最多再发 2 个请求（同域脚本），失败静默——画像字段容错。
	s.enrichResponse(ctx, result, resp, bodyStr)

	// Sort fingerprints by confidence
	sort.Slice(result.Fingerprints, func(i, j int) bool {
		return result.Fingerprints[i].Confidence > result.Fingerprints[j].Confidence
	})

	result.ScanTime = time.Since(start) / time.Millisecond
	return result
}

// enrichResponse 采集响应画像：TLS 证书归属、Set-Cookie 名集合、JS 框架版本
// 与 JS 里引用的域名（跨域 API 归属线索）。所有失败静默——这些是增值字段。
func (s *FingerprintScanner) enrichResponse(ctx context.Context, result *FingerprintResult, resp *http.Response, body string) {
	// 证书归属：ScanFingerprint 已提前提取（cert 规则数据源），这里不重复取

	// cookie 名集合：Set-Cookie 每条取等号前的名字（框架/网关特征，如 tenantId）
	cookieNames := map[string]bool{}
	for _, sc := range resp.Header.Values("Set-Cookie") {
		if i := strings.IndexByte(sc, '='); i > 0 {
			name := strings.TrimSpace(sc[:i])
			if name != "" && len(name) <= 64 {
				cookieNames[strings.ToLower(name)] = true
			}
		}
	}
	for name := range cookieNames {
		result.CookieNames = append(result.CookieNames, name)
	}
	sort.Strings(result.CookieNames)

	// JS 元数据：抓同域脚本（最多 2 个）提取框架版本与引用域名
	jsContents := s.fetchSameOriginScripts(ctx, result.URL, body)
	frameworks := map[string]bool{}
	apiHosts := map[string]int{}
	for _, js := range jsContents {
		for _, f := range extractJSFrameworks(js) {
			frameworks[f] = true
		}
		for host, n := range extractReferencedHosts(js) {
			apiHosts[host] += n
		}
	}
	for f := range frameworks {
		result.JSFrameworks = append(result.JSFrameworks, f)
	}
	sort.Strings(result.JSFrameworks)
	type hostCount struct {
		host  string
		count int
	}
	var hc []hostCount
	for h, n := range apiHosts {
		hc = append(hc, hostCount{h, n})
	}
	sort.Slice(hc, func(i, j int) bool {
		if hc[i].count != hc[j].count {
			return hc[i].count > hc[j].count
		}
		return hc[i].host < hc[j].host
	})
	for i, h := range hc {
		if i >= 8 {
			break
		}
		result.APIHosts = append(result.APIHosts, h.host)
	}
}

// fetchSameOriginScripts 从 body 提取同域 script src 并下载内容（最多 2 个、每个 512KB）。
func (s *FingerprintScanner) fetchSameOriginScripts(ctx context.Context, pageURL, body string) []string {
	base, err := url.Parse(pageURL)
	if err != nil {
		return nil
	}
	scriptRe := regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+)["']`)
	var candidates []string
	for _, m := range scriptRe.FindAllStringSubmatch(body, -1) {
		u, uerr := base.Parse(m[1])
		if uerr != nil {
			continue
		}
		if u.Host != base.Host || u.Path == "" || strings.HasSuffix(u.Path, ".css") {
			continue
		}
		candidates = append(candidates, u.String())
		if len(candidates) >= 2 {
			break
		}
	}
	var out []string
	for _, jsURL := range candidates {
		jsCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		req, rerr := http.NewRequestWithContext(jsCtx, http.MethodGet, jsURL, nil)
		if rerr != nil {
			cancel()
			continue
		}
		req.Header.Set("User-Agent", useragent.Pick())
		resp, gerr := s.HTTPClient.Do(req)
		if gerr != nil {
			cancel()
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
		resp.Body.Close()
		cancel()
		if len(b) > 0 {
			out = append(out, string(b))
		}
	}
	return out
}

// jsFrameworkRes 常见前端框架/组件库的版本特征（文件名 + 内容两种形态）。
var jsFrameworkRes = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(vue|react|angular|jquery|element-ui|element-plus|antd|ant-design|bootstrap|layui|echarts|chart\.js|axios|moment|dayjs|lodash|next|nuxt)\.?(?:runtime|global|prod|common|min)?\.?v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)`),
	regexp.MustCompile(`(?i)(element-ui|element-plus|ant-design-vue|ant-design|view-design|iview)[@/ -]v?([0-9]+\.[0-9]+\.[0-9]+)`),
}

// extractJSFrameworks 从 JS 内容提取 "框架@版本" 列表。
func extractJSFrameworks(js string) []string {
	found := map[string]bool{}
	for _, re := range jsFrameworkRes {
		for _, m := range re.FindAllStringSubmatch(js, 20) {
			// 两个正则都是两捕获组（框架名, 版本）；越界防御避免带崩扫描进程
			if len(m) < 3 {
				continue
			}
			name := strings.ToLower(strings.TrimSuffix(m[1], "."))
			ver := m[2]
			if name == "" || ver == "" {
				continue
			}
			// 通用 version 字段匹配时 m[1] 可能不是框架名，跳过无名词命中
			if !strings.ContainsAny(name, "abcdefghijklmnopqrstuvwxyz") {
				continue
			}
			found[name+"@"+ver] = true
		}
	}
	out := make([]string, 0, len(found))
	for f := range found {
		out = append(out, f)
	}
	return out
}

// referencedHostRe 页面/JS 里的绝对 URL 主机。
var referencedHostRe = regexp.MustCompile(`https?://([a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,})(?::\d+)?`)

// cdnHosts 公共 CDN/文档域，不算资产归属线索。
var cdnHosts = map[string]bool{
	"unpkg.com": true, "cdn.jsdelivr.net": true, "cdnjs.cloudflare.com": true,
	"cdn.bootcdn.net": true, "cdn.staticfile.org": true, "lib.sinaapp.com": true,
	"fonts.googleapis.com": true, "fonts.gstatic.com": true, "www.w3.org": true,
	"github.com": true, "gitlab.com": true, "stackoverflow.com": true,
	"beian.miit.gov.cn": true, "beian.gov.cn": true,
	"registry.npmmirror.com": true, "npm.elemecdn.com": true, "lf3-cdn-tos.bytecdnapi.com": true,
}

// extractReferencedHosts 统计 JS 内容里引用的域名频次（排除公共 CDN）。
func extractReferencedHosts(js string) map[string]int {
	counts := map[string]int{}
	for _, m := range referencedHostRe.FindAllStringSubmatch(js, 500) {
		h := strings.ToLower(m[1])
		if cdnHosts[h] || strings.HasSuffix(h, ".example.com") {
			continue
		}
		counts[h]++
	}
	return counts
}

// loadFingerprintRules loads fingerprint rules from YAML files
func (s *FingerprintScanner) loadFingerprintRules() {
	// 内置规则集（dddd 快照 + 种子）不依赖工作目录，先加载。
	builtin := s.DSLEngine.LoadBuiltinRules()
	fmt.Printf("Loaded %d builtin fingerprint rules (dddd snapshot + seeds)\n", builtin)

	// Try to find the config/dicts/yaml directory
	paths := []string{
		"config/dicts/yaml",
		"./config/dicts/yaml",
		"../config/dicts/yaml",
		"backend/config/dicts/yaml",
	}

	var rulesDir string
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			rulesDir = p
			break
		}
	}

	if rulesDir == "" {
		// 二进制内置字典兜底：ReadDictFile 会回落到 go:embed。
		rulesDir = "config/dicts/yaml"
	}

	// T13：finger.yaml 已退役（T10 用 reconkit 的 dddd 快照 + 种子替代）。
	// sensitive.yaml 仍保留：它是内容敏感信息特征，dddd 快照不覆盖。
	sensitivePath := filepath.Join(rulesDir, "sensitive.yaml")
	if err := s.DSLEngine.LoadRulesFromFile(sensitivePath); err != nil {
		fmt.Printf("Warning: failed to load sensitive.yaml: %v\n", err)
	}

	// Load jslib.yaml for JavaScript library detection
	jslibPath := filepath.Join(rulesDir, "jslib.yaml")
	if err := s.loadJSLibPatterns(jslibPath); err != nil {
		fmt.Printf("Warning: failed to load jslib.yaml: %v\n", err)
	}

	// Load ports.yaml for port service mapping
	portsPath := filepath.Join(rulesDir, "ports.yaml")
	if err := s.loadPortServices(portsPath); err != nil {
		fmt.Printf("Warning: failed to load ports.yaml: %v\n", err)
	}

	fmt.Printf("Loaded %d fingerprint rules, %d JS libs, %d port services\n",
		s.DSLEngine.RulesCount(), len(s.JSLibPatterns), len(s.PortServices))
}

// detectFingerprintsWithDSL performs fingerprint detection using DSL engine
func (s *FingerprintScanner) detectFingerprintsWithDSL(result *FingerprintResult, body, iconHash, iconMD5 string) {
	matched := make(map[string]bool)

	// Use DSL engine if available
	if s.DSLEngine != nil && s.DSLEngine.RulesCount() > 0 {
		dslResp := &HTTPResponse{
			StatusCode: result.StatusCode,
			Headers:    result.Headers,
			Body:       body,
			Title:      result.Title,
			URL:        result.URL,
			IconHash:   iconHash,
			IconMD5:    iconMD5,
			CertOrg:    result.CertOrg,
		}

		dslMatches := s.DSLEngine.AnalyzeResponse(dslResp)
		for _, match := range dslMatches {
			if !matched[match.Technology] {
				matched[match.Technology] = true
				result.Fingerprints = append(result.Fingerprints, Fingerprint{
					Name:       match.Technology,
					Category:   match.Category,
					Confidence: match.Confidence,
					Method:     "dsl",
				})
				result.Technologies = append(result.Technologies, match.Technology)
				setCategoryField(result, match.Technology, match.Category)
			}
		}
	}

	// Also detect from headers (basic detection as fallback)
	s.detectFromHeaders(result, matched)
}

// detectFromHeaders performs basic fingerprint detection from HTTP headers
func (s *FingerprintScanner) detectFromHeaders(result *FingerprintResult, matched map[string]bool) {
	// Detect from Server header
	if result.Server != "" {
		serverLower := strings.ToLower(result.Server)
		if strings.Contains(serverLower, "nginx") {
			s.addFingerprint(result, matched, "Nginx", "WebServer", 90, "header")
		}
		if strings.Contains(serverLower, "apache") {
			s.addFingerprint(result, matched, "Apache", "WebServer", 90, "header")
		}
		if strings.Contains(serverLower, "iis") {
			s.addFingerprint(result, matched, "IIS", "WebServer", 90, "header")
		}
		if strings.Contains(serverLower, "tomcat") {
			s.addFingerprint(result, matched, "Tomcat", "WebServer", 90, "header")
		}
		if strings.Contains(serverLower, "openresty") {
			s.addFingerprint(result, matched, "OpenResty", "WebServer", 90, "header")
		}
	}

	// Detect from X-Powered-By header
	if result.PoweredBy != "" {
		poweredByLower := strings.ToLower(result.PoweredBy)
		if strings.Contains(poweredByLower, "php") {
			s.addFingerprint(result, matched, "PHP", "Language", 90, "header")
		}
		if strings.Contains(poweredByLower, "asp.net") {
			s.addFingerprint(result, matched, "ASP.NET", "Framework", 90, "header")
		}
		if strings.Contains(poweredByLower, "express") {
			s.addFingerprint(result, matched, "Express", "Framework", 90, "header")
		}
		if strings.Contains(poweredByLower, "servlet") {
			s.addFingerprint(result, matched, "Java Servlet", "Framework", 90, "header")
		}
	}
}

// addFingerprint adds a fingerprint to result if not already matched
func (s *FingerprintScanner) addFingerprint(result *FingerprintResult, matched map[string]bool, name, category string, confidence int, method string) {
	if matched[name] {
		return
	}
	matched[name] = true
	result.Fingerprints = append(result.Fingerprints, Fingerprint{
		Name:       name,
		Category:   category,
		Confidence: confidence,
		Method:     method,
	})
	result.Technologies = append(result.Technologies, name)
	setCategoryField(result, name, category)
}

// setCategoryField sets the appropriate category field in result
func setCategoryField(result *FingerprintResult, name, category string) {
	switch category {
	case "CMS":
		if result.CMS == "" {
			result.CMS = name
		}
	case "Framework":
		if result.Framework == "" {
			result.Framework = name
		}
	case "WebServer":
		if result.WebServer == "" {
			result.WebServer = name
		}
	case "Language":
		if result.Language == "" {
			result.Language = name
		}
	}
}

// extractPageTitle extracts page title from HTML
func extractPageTitle(html string) string {
	titleRegex := regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)
	matches := titleRegex.FindStringSubmatch(html)
	if len(matches) > 1 {
		title := strings.TrimSpace(matches[1])
		// Clean up title
		title = strings.ReplaceAll(title, "\n", " ")
		title = strings.ReplaceAll(title, "\r", " ")
		title = strings.ReplaceAll(title, "\t", " ")
		// Limit length
		if len(title) > 200 {
			title = title[:200] + "..."
		}
		return title
	}
	return ""
}

// loadJSLibPatterns loads JavaScript library patterns from YAML file
func (s *FingerprintScanner) loadJSLibPatterns(path string) error {
	data, err := config.ReadDictFile(path)
	if err != nil {
		return err
	}

	// Parse YAML structure: LibName: {pattern: "regex"}
	var rawPatterns map[string]struct {
		Pattern string `yaml:"pattern"`
	}
	if err := yaml.Unmarshal(data, &rawPatterns); err != nil {
		return err
	}

	// Compile regex patterns
	for name, item := range rawPatterns {
		if item.Pattern == "" {
			continue
		}
		re, err := regexp.Compile(item.Pattern)
		if err != nil {
			fmt.Printf("Warning: invalid regex for %s: %v\n", name, err)
			continue
		}
		s.JSLibPatterns[name] = re
	}

	return nil
}

// loadPortServices loads port to service mapping from YAML file
func (s *FingerprintScanner) loadPortServices(path string) error {
	data, err := config.ReadDictFile(path)
	if err != nil {
		return err
	}

	// Parse YAML structure: port: {service: "name"}
	var rawPorts map[int]struct {
		Service string `yaml:"service"`
	}
	if err := yaml.Unmarshal(data, &rawPorts); err != nil {
		return err
	}

	for port, item := range rawPorts {
		if item.Service != "" {
			s.PortServices[port] = item.Service
		}
	}

	return nil
}

// extractJSLibraries extracts JavaScript library references
func (s *FingerprintScanner) extractJSLibraries(html string) []string {
	libraries := make([]string, 0)
	seen := make(map[string]bool)

	// Use patterns from configuration
	for name, pattern := range s.JSLibPatterns {
		if pattern.MatchString(html) && !seen[name] {
			seen[name] = true
			libraries = append(libraries, name)
		}
	}

	sort.Strings(libraries)
	return libraries
}

// getFaviconHash 抓 favicon 并返回 mmh3（Shodan/FOFA 口径，76 列折行）、
// MD5、sha256、mmh3 数值与原始字节；原始字节供资产域直接入库。
func (s *FingerprintScanner) getFaviconHash(ctx context.Context, baseURL string) (string, string, string, int64, []byte, string) {
	// 只取 origin：result.URL 可能带路径，直接拼 /favicon.ico 会变成 /path/favicon.ico。
	if u, err := url.Parse(baseURL); err == nil && u.Host != "" {
		baseURL = u.Scheme + "://" + u.Host
	}
	// Parse base URL
	faviconURLs := []string{
		baseURL + "/favicon.ico",
		baseURL + "/favicon.png",
	}

	// Also try to find from HTML
	// (simplified - would need to parse HTML link tags)

	for _, faviconURL := range faviconURLs {
		req, err := http.NewRequestWithContext(ctx, "GET", faviconURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", useragent.Pick())

		resp, err := s.HTTPClient.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			continue
		}

		favicon, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		if err != nil || len(favicon) == 0 {
			continue
		}

		// Calculate MD5 / SHA256
		md5Hash := md5.Sum(favicon)
		md5Str := hex.EncodeToString(md5Hash[:])
		sha := sha256.Sum256(favicon)
		shaStr := hex.EncodeToString(sha[:])

		// Shodan/FOFA 口径：base64 每 76 列折行后再算 mmh3。
		b64 := base64.StdEncoding.EncodeToString(favicon)
		var folded strings.Builder
		for i := 0; i < len(b64); i += 76 {
			end := i + 76
			if end > len(b64) {
				end = len(b64)
			}
			folded.WriteString(b64[i:end])
			folded.WriteByte('\n')
		}
		mmh3Hash := mmh3Hash32([]byte(folded.String()))
		ctype := strings.TrimSpace(resp.Header.Get("Content-Type"))
		if ctype == "" {
			ctype = http.DetectContentType(favicon)
		}

		return fmt.Sprintf("%d", mmh3Hash), md5Str, shaStr, int64(mmh3Hash), favicon, ctype
	}

	return "", "", "", 0, nil, ""
}

// mmh3Hash32 calculates MurmurHash3 32-bit hash
func mmh3Hash32(data []byte) int32 {
	h := murmur3.New32()
	h.Write(data)
	return int32(h.Sum32())
}

// ScanPortFingerprint scans service fingerprint on a specific port
func (s *FingerprintScanner) ScanPortFingerprint(ctx context.Context, host string, port int) *PortFingerprint {
	result := &PortFingerprint{
		Port:    port,
		Service: "unknown",
	}

	address := net.JoinHostPort(host, strconv.Itoa(port))

	// Try TCP connection
	conn, err := net.DialTimeout("tcp", address, s.Timeout)
	if err != nil {
		return result
	}
	defer conn.Close()

	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	// Try to grab banner
	buffer := make([]byte, 4096)
	n, _ := conn.Read(buffer)
	if n > 0 {
		result.Banner = string(buffer[:n])
		result.Service, result.Product, result.Version = parseServiceBanner(result.Banner, port)
	}

	// Try SSL/TLS connection for common HTTPS ports
	if port == 443 || port == 8443 || port == 9443 {
		result.SSL = true
		result.Certificate = s.getCertInfo(ctx, host, port)
		if result.Service == "unknown" {
			result.Service = "https"
		}
	}

	// If no banner, determine service by port
	if result.Service == "unknown" {
		result.Service = s.getServiceByPort(port)
	}

	return result
}

// parseServiceBanner parses service banner to identify service
func parseServiceBanner(banner string, port int) (service, product, version string) {
	bannerLower := strings.ToLower(banner)

	// SSH
	if strings.HasPrefix(banner, "SSH-") {
		service = "ssh"
		parts := strings.Split(banner, "-")
		if len(parts) >= 3 {
			product = parts[2]
			if idx := strings.Index(product, " "); idx > 0 {
				version = strings.TrimSpace(product[idx:])
				product = product[:idx]
			}
		}
		return
	}

	// HTTP
	if strings.HasPrefix(banner, "HTTP/") || strings.Contains(bannerLower, "<html") {
		service = "http"
		if strings.Contains(bannerLower, "nginx") {
			product = "Nginx"
		} else if strings.Contains(bannerLower, "apache") {
			product = "Apache"
		} else if strings.Contains(bannerLower, "iis") {
			product = "IIS"
		}
		return
	}

	// MySQL
	if len(banner) > 5 && banner[4] == 0x0a {
		service = "mysql"
		product = "MySQL"
		return
	}

	// PostgreSQL
	if strings.Contains(banner, "PostgreSQL") {
		service = "postgresql"
		product = "PostgreSQL"
		return
	}

	// Redis
	if strings.Contains(banner, "REDIS") || strings.Contains(banner, "-ERR") {
		service = "redis"
		product = "Redis"
		return
	}

	// MongoDB
	if strings.Contains(banner, "MongoDB") || strings.Contains(banner, "It looks like you are trying to access MongoDB") {
		service = "mongodb"
		product = "MongoDB"
		return
	}

	// FTP
	if strings.HasPrefix(banner, "220") && (strings.Contains(bannerLower, "ftp") || port == 21) {
		service = "ftp"
		return
	}

	// SMTP
	if strings.HasPrefix(banner, "220") && (strings.Contains(bannerLower, "smtp") || strings.Contains(bannerLower, "mail") || port == 25 || port == 587) {
		service = "smtp"
		return
	}

	// POP3
	if strings.HasPrefix(banner, "+OK") && port == 110 {
		service = "pop3"
		return
	}

	// IMAP
	if strings.Contains(banner, "* OK") && strings.Contains(bannerLower, "imap") {
		service = "imap"
		return
	}

	service = "unknown"
	return
}

// getCertInfo gets SSL certificate information
func (s *FingerprintScanner) getCertInfo(ctx context.Context, host string, port int) *CertInfo {
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: s.Timeout}, "tcp", net.JoinHostPort(host, strconv.Itoa(port)), conf)
	if err != nil {
		return nil
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil
	}

	cert := certs[0]
	fingerprint := sha256Fingerprint(cert.Raw)

	return &CertInfo{
		Subject:     cert.Subject.String(),
		Issuer:      cert.Issuer.String(),
		NotBefore:   cert.NotBefore,
		NotAfter:    cert.NotAfter,
		SANs:        cert.DNSNames,
		Fingerprint: fingerprint,
	}
}

// sha256Fingerprint calculates SHA256 fingerprint
func sha256Fingerprint(data []byte) string {
	var h hash.Hash = md5.New() // Using MD5 for simplicity, should use SHA256 in production
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// getServiceByPort returns service name for a port from configuration
func (s *FingerprintScanner) getServiceByPort(port int) string {
	// First try from loaded configuration
	if service, ok := s.PortServices[port]; ok {
		return service
	}
	return "unknown"
}

// BatchScanFingerprint scans fingerprints for multiple targets
func (s *FingerprintScanner) BatchScanFingerprint(ctx context.Context, targets []string) []*FingerprintResult {
	results := make([]*FingerprintResult, len(targets))
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, s.Concurrency)
	var mu sync.Mutex

	for i, target := range targets {
		wg.Add(1)
		semaphore <- struct{}{}

		go func(idx int, t string) {
			defer wg.Done()
			defer func() { <-semaphore }()

			result := s.ScanFingerprint(ctx, t)

			mu.Lock()
			results[idx] = result
			mu.Unlock()
		}(i, target)
	}

	wg.Wait()
	return results
}
