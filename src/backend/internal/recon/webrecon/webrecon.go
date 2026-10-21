// Package webrecon Web 侦察核心:未授权访问探测与 JS 侦察(接口/泄露提取)。
// 逻辑自 4zreco 的 unauth_probe_tools / js_recon_tools / nuclei_extract 直接抽取
// (探测字典、bypass 变体、正则族、webpack chunk 递归、云 AK 嗅探原样保留);
// 差异:directhttp → recon/directhttp,cloudkeys.LooksLikePlaceholder → creds 同源实现,
// 无 DB 依赖(结果由工具层回报,agent 决定是否登记 finding)。
package webrecon

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/c1ayooo/4zreark/internal/creds"
	"github.com/c1ayooo/4zreark/internal/recon/directhttp"
)

type Hit struct {
	Path    string
	Variant string
	Status  int
	Snippet string
}

// unauthBypassBudget 单次调用 bypass 变体请求总预算：全字典 403 时最坏请求数可控。
const unauthBypassBudget = 64

// UnauthSweep 共享探测核心：无凭据（或带 headers 凭据态）扫 paths，403/401 自动跑
// bypass 变体（预算封顶）。返回命中清单与 bypass 预算是否耗尽。
func UnauthSweep(ctx context.Context, base string, paths []string, headers map[string]string, bypass bool) ([]Hit, bool) {
	base = strings.TrimSuffix(strings.TrimSpace(base), "/")
	if base == "" || !strings.Contains(base, "://") {
		return nil, false
	}
	client := directhttp.Client(&http.Client{Timeout: 8 * time.Second})
	budget := unauthBypassBudget
	truncated := false
	var hits []Hit
	for _, p := range paths {
		st, ct, body := fetch(ctx, client, base+p, headers)
		if isHit(st, ct, body) {
			hits = append(hits, Hit{Path: p, Status: st, Snippet: truncRunes(strings.TrimSpace(body), 160)})
			continue
		}
		if !bypass || (st != http.StatusForbidden && st != http.StatusUnauthorized) {
			continue
		}
		if budget <= 0 {
			truncated = true
			continue
		}
		for _, v := range bypassVariants(base, p) {
			if budget <= 0 {
				truncated = true
				break
			}
			budget--
			vst, vct, vbody := fetch(ctx, client, v.url, mergeHeaders(headers, v.headers))
			if isHit(vst, vct, vbody) {
				hits = append(hits, Hit{Path: p, Variant: v.name, Status: vst, Snippet: truncRunes(strings.TrimSpace(vbody), 160)})
				break // 该路径已绕过，不再试其余变体
			}
		}
	}
	return hits, truncated
}

// bypassVariant 一个 bypass 变体（请求 URL + 附加头；主 headers 由调用方合并）。
type bypassVariant struct {
	name    string
	url     string
	headers map[string]string
}

// bypassVariants 403/401 惯用绕过变体：header 伪造来源 5 种 + 路径归一化 3 种（GET）。
func bypassVariants(base, p string) []bypassVariant {
	return []bypassVariant{
		{"x-original-url", base + "/", map[string]string{"X-Original-URL": p}},
		{"x-rewrite-url", base + "/", map[string]string{"X-Rewrite-URL": p}},
		{"xff-127.0.0.1", base + p, map[string]string{"X-Forwarded-For": "127.0.0.1"}},
		{"x-originating-ip", base + p, map[string]string{"X-Originating-IP": "127.0.0.1"}},
		{"x-custom-ip-auth", base + p, map[string]string{"X-Custom-IP-Authorization": "127.0.0.1"}},
		{"trailing-slash", base + p + "/", nil},
		{"double-slash", base + "//" + strings.TrimPrefix(p, "/"), nil},
		{"dot-segment", base + "/." + p, nil},
	}
}

func mergeHeaders(base map[string]string, extra map[string]string) map[string]string {
	if len(extra) == 0 {
		return base
	}
	out := make(map[string]string, len(base)+len(extra))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

// fetch 单发探测请求，返回 (status, content-type, body≤64KB)；错误全零。
func fetch(ctx context.Context, client *http.Client, rawURL string, headers map[string]string) (int, string, string) {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, "", ""
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode, resp.Header.Get("Content-Type"), string(body)
}

// isHit 命中判据：200 且 JSON/文本业务数据；SPA 壳（<!DOCTYPE html> 且含
// <div id=root/app）与空体排除。主探测与 bypass 变体共用同一判据。
func isHit(st int, ct, body string) bool {
	if st != 200 || len(body) < 8 {
		return false
	}
	if strings.Contains(ct, "text/html") && (strings.Contains(body, "<div id=\"root\"") || strings.Contains(body, "<div id=\"app\"")) {
		return false
	}
	return strings.Contains(ct, "json") || strings.Contains(body, "{") || strings.Contains(body, "[")
}

// unauthDict 标准敏感端点字典（渗透常规清单，通用非定制）。
var unauthDict = []string{
	"/api/debug/routes", "/api/debug/env", "/api/debug/pprof/", "/debug/pprof/",
	"/actuator", "/actuator/env", "/actuator/heapdump", "/actuator/mappings", "/actuator/health",
	"/.env", "/config.yaml", "/application.yml", "/swagger", "/swagger/index.html", "/api-docs", "/v2/api-docs", "/openapi.json",
	"/api/system/config", "/api/config", "/api/settings",
	"/api/file/all", "/api/files", "/api/file/list", "/uploads/",
	"/api/admin/", "/api/admin/announcement/list", "/api/admin/users",
	"/api/internal/", "/api/test/", "/api/test/admin-register",
	"/api/user/list", "/api/users", "/api/user/profile",
	"/api/announcement/list", "/api/announcement/",
	"/api/notification/list", "/api/logs", "/api/audit/",
	"/metrics", "/healthz", "/info", "/.git/config", "/.svn/entries", "/robots.txt", "/sitemap.xml",
	"/druid/", "/nacos/", "/eureka/", "/consul/", "/apollo/",
	"/api/auth/userinfo", "/api/me", "/api/profile",
	"/graphql", "/api/graphql", "/trace",
}

const jsTick = "\x60"

// 请求量/入库量上限：感知面要宽，但灌库有红线——全链路处处有 cap。
const (
	jsReconMaxBundles   = 40  // 递归 bundle 上限（入口 <script src> + 懒加载 chunk）
	jsReconMaxEndpoints = 200 // 全量端点清单上限
	jsReconMaxLeaks     = 40  // 硬编码敏感配置上限
	jsReconMaxDisplay   = 80  // 输出里全量清单展示条数（其余入板）
)

type Result struct {
	Host           string
	Bundles        []string
	EndpointGroups []string
	Endpoints      []string // 全量端点（去重、去 query、cap 200）
	Routes         []string
	Leaks          []Leak
}

type Leak struct {
	Key, Val, Src string
}

var (
	reScriptSrc = regexp.MustCompile(`src=["']([^"']+\.js[^"']*)["']`)
	// 端点：引号/反引号包裹、/字母 开头的 1~8 段路径；后续段允许 ${}:*@（模板字面量）；
	// 可选 query 尾（闭引号必须可达，query 在 addEndpoint 剥掉）。前缀白名单（api|v1|v2|…）
	// 已废——/upload、/file/download 类无前缀端点恰是漏授权重灾区。
	reAPIPath = regexp.MustCompile(`["'` + jsTick + `](/[A-Za-z][A-Za-z0-9_.\-]{0,60}(?:/[A-Za-z0-9_.\-@:*{}$]{1,60}){0,7})(?:\?[A-Za-z0-9_=&%$.:\-]{0,80})?["'` + jsTick + `]`)
	reRoute   = regexp.MustCompile(`Path:["']([^"']{2,60})["']`)
	reLeak    = regexp.MustCompile(`(?i)(JWT[_-]?SECRET|SECRET[_-]?KEY|INVITE[_-]?CODE|ADMIN[_-]?CODE|API[_-]?KEY|APP[_-]?CONFIG|INTERNAL[_-]?API|DEBUG[_-]?API)["'\s:=]{1,4}["']([^"']{4,120})["']`)
	// JS 内 .js 文件字面量（相对/站点绝对路径）：覆盖 Vite __vite__mapDeps 数组、原生动态
	// import、可读拼接路径。字符集不含冒号——CDN 绝对 URL 天然排除，跨域由 host 校验兜底。
	reJSFileLit = regexp.MustCompile(`["'` + jsTick + `]([A-Za-z0-9_./~${}\-]{2,200}?\.js(?:\?[A-Za-z0-9_=&\-]{0,80})?)["'` + jsTick + `]`)
	// webpack runtime chunk 文件名模板："<dir>" + <var> + "." + {id:"hash"}[<var>] + ".js"
	// （__webpack_require__.u 赋值形态），由 publicPath+dir+id+hash 合成真实 chunk URL。
	reWebpackChunk   = regexp.MustCompile(`"([^"]{0,80}?)"\s*\+\s*[A-Za-z_$][\w$]*\s*\+\s*"\."\s*\+\s*\{([^{}]{2,800}?)\}\s*\[[A-Za-z_$][\w$]*\]\s*\+\s*"\.js"`)
	reWebpackPair    = regexp.MustCompile(`"([^"]{1,40})"\s*:\s*"([0-9A-Fa-f]{4,32})"`)
	reWebpackPubPath = regexp.MustCompile(`__webpack_require__\.p\s*=\s*"([^"]*)"`)
	// 泄露族四扩：JWT 本体 / DB 连接串 / 私钥块 / 口令赋值（占位值过滤）。云 AK 走
	// SniffCloudAKs/SniffCloudSecrets（nuclei_extract.go 同包纯函数，只嗅探不外呼）。
	reJWT        = regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{4,}`)
	reDBConn     = regexp.MustCompile(`(?i)\b(jdbc:[a-z0-9]{2,20}:[^\s"'` + jsTick + `<>\\]{4,200}|(?:mongodb(?:\+srv)?|mysql|postgres(?:ql)?|redis|mssql|amqp|oracle|sqlite3?)://[^\s"'` + jsTick + `<>\\]{4,200})`)
	rePrivKey    = regexp.MustCompile(`-----BEGIN [A-Z ]{0,30}PRIVATE KEY-----`)
	rePassAssign = regexp.MustCompile(`(?i)["']?\b(password|passwd|pwd|db_?pass(?:word)?|admin_?pass(?:word)?|secret_?key|access_?key_?secret|client_?secret|secret|auth_?token)\b["']?\s*[:=]\s*["']([^"'\n]{6,120})["']`)
)

// jsStaticExtDeny 端点候选的静态资源扩展名黑名单（.json/.js 排除由末段扩展名判断）。
var jsStaticExtDeny = map[string]bool{
	".js": true, ".css": true, ".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
	".svg": true, ".ico": true, ".woff": true, ".woff2": true, ".ttf": true, ".eot": true,
	".map": true, ".mp4": true, ".webm": true, ".webp": true, ".avif": true, ".html": true,
	".htm": true, ".txt": true, ".md": true, ".xml": true, ".pdf": true, ".zip": true,
	".gz": true, ".wasm": true,
}

// jsPathNoiseSingle 单段路径的 HTML/SVG tag 噪音表（多段路径不受此表约束）。
var jsPathNoiseSingle = map[string]bool{
	"div": true, "span": true, "svg": true, "path": true, "g": true, "li": true, "ul": true,
	"ol": true, "table": true, "td": true, "tr": true, "th": true, "img": true, "image": true,
	"text": true, "input": true, "button": true, "form": true, "label": true, "select": true,
	"option": true, "video": true, "audio": true, "canvas": true, "circle": true, "rect": true,
	"line": true, "polyline": true, "polygon": true, "ellipse": true, "defs": true, "use": true,
	"symbol": true, "view": true, "br": true, "hr": true, "pre": true, "code": true,
	"head": true, "body": true, "html": true, "meta": true, "link": true, "style": true,
	"title": true,
}

// LooksLikeAPIPath 放宽后的端点候选噪音过滤：静态资源扩展名/构建噪音前缀/tag 单段。
func LooksLikeAPIPath(p string) bool {
	if p == "" || !strings.HasPrefix(p, "/") {
		return false
	}
	for _, noise := range []string{"node_modules", "__webpack__", "hot-update"} {
		if strings.Contains(p, noise) {
			return false
		}
	}
	segs := strings.Split(strings.Trim(p, "/"), "/")
	last := segs[len(segs)-1]
	if i := strings.IndexByte(last, '.'); i >= 0 && jsStaticExtDeny[strings.ToLower(last[i:])] {
		return false
	}
	if len(segs) == 1 && jsPathNoiseSingle[strings.ToLower(segs[0])] {
		return false
	}
	return true
}

// passPlaceholder 口令赋值噪音过滤：模板占位/环境变量引用/布尔词/纯字母单词不是凭据
// （真口令几乎必含数字或特殊字符）。
func passPlaceholder(v string) bool {
	t := strings.TrimSpace(v)
	if t == "" {
		return true
	}
	for _, p := range []string{"${", "{{", "<%", "%s", "<"} {
		if strings.HasPrefix(t, p) {
			return true
		}
	}
	switch strings.ToLower(t) {
	case "true", "false", "null", "undefined", "password", "username", "secret", "token":
		return true
	}
	if strings.Trim(t, "*") == "" {
		return true
	}
	for _, r := range t {
		if unicode.IsDigit(r) || !unicode.IsLetter(r) {
			return false
		}
	}
	return true
}

// CollectLeaks 全泄露族提取入 set（key+val 去重）。
func CollectLeaks(body string, into map[string]Leak) {
	add := func(key, val string) {
		key = strings.ToUpper(strings.TrimSpace(key))
		val = strings.TrimSpace(val)
		if key == "" || val == "" {
			return
		}
		k := key + "\x00" + val
		if _, ok := into[k]; !ok {
			into[k] = Leak{Key: key, Val: val, Src: "bundle"}
		}
	}
	for _, m := range reLeak.FindAllStringSubmatch(body, -1) {
		add(m[1], m[2])
	}
	for _, m := range reJWT.FindAllString(body, -1) {
		add("JWT_TOKEN", m)
	}
	for _, m := range reDBConn.FindAllStringSubmatch(body, -1) {
		add("DB_CONN", m[1])
	}
	if s := rePrivKey.FindString(body); s != "" {
		add("PRIVATE_KEY", s)
	}
	for _, m := range rePassAssign.FindAllStringSubmatch(body, -1) {
		if !passPlaceholder(m[2]) {
			add(m[1], m[2])
		}
	}
	for _, ak := range SniffCloudAKs(body) {
		add("CLOUD_ACCESSKEY("+ak.Provider+")", ak.AccessKey)
	}
	for _, sk := range SniffCloudSecrets(body) {
		add("CLOUD_SECRET_CANDIDATE", sk)
	}
}

func JSReconFetch(baseURL string, headers map[string]string) *Result {
	out := &Result{Host: hostOf(baseURL)}
	client := directhttp.Client(&http.Client{Timeout: 15 * time.Second})
	baseU, err := url.Parse(baseURL)
	if err != nil {
		return out
	}
	html := httpGet(client, baseURL, headers)

	endpointSet, grpSet, routeSet := map[string]bool{}, map[string]bool{}, map[string]bool{}
	leakSet := map[string]Leak{}
	var queue []string
	queued := map[string]bool{}
	enqueueChunk := func(ref, ctxURL string) {
		if ref == "" {
			return
		}
		// 解析基准：/ 开头=站点绝对；./ ../=相对 bundle 所在目录；裸路径（webpack .u
		// 模板省略 publicPath）按站点根解析。
		if !strings.HasPrefix(ref, "/") && !strings.HasPrefix(ref, "./") && !strings.HasPrefix(ref, "../") {
			ref = "/" + ref
		}
		ctxU, err := url.Parse(ctxURL)
		if err != nil {
			return
		}
		rel, err := url.Parse(ref)
		if err != nil {
			return
		}
		abs := ctxU.ResolveReference(rel)
		if abs.Host != baseU.Host {
			return // 跨域（CDN 公共库）不拉
		}
		if abs.String() == baseURL {
			return
		}
		if !queued[abs.String()] {
			queued[abs.String()] = true
			queue = append(queue, abs.String())
		}
	}
	addEndpoint := func(raw string) {
		p := "/" + strings.Trim(strings.SplitN(raw, "?", 2)[0], "/")
		if p == "/" || !LooksLikeAPIPath(p) || endpointSet[p] {
			return
		}
		endpointSet[p] = true
		segs := strings.Split(strings.Trim(p, "/"), "/")
		grp := strings.Join(segs[:minInt(3, len(segs))], "/")
		if grp != "" {
			grpSet[grp] = true
		}
	}
	process := func(body, ctxURL string) {
		for _, m := range reAPIPath.FindAllStringSubmatch(body, -1) {
			addEndpoint(m[1])
		}
		for _, m := range reRoute.FindAllStringSubmatch(body, -1) {
			r := strings.TrimSpace(m[1])
			if strings.HasPrefix(r, "/") {
				routeSet[r] = true
			}
		}
		CollectLeaks(body, leakSet)
		// 递归 chunk：webpack hash 模板重建（publicPath+dir+id.hash.js）+ .js 字面量（Vite/import）
		pubPath := ""
		if pp := reWebpackPubPath.FindStringSubmatch(body); pp != nil {
			pubPath = pp[1]
		}
		for _, m := range reWebpackChunk.FindAllStringSubmatch(body, -1) {
			for _, pair := range reWebpackPair.FindAllStringSubmatch(m[2], -1) {
				enqueueChunk(pubPath+m[1]+pair[1]+"."+pair[2]+".js", ctxURL)
			}
		}
		for _, m := range reJSFileLit.FindAllStringSubmatch(body, -1) {
			enqueueChunk(m[1], ctxURL)
		}
	}
	process(html, baseURL)
	for _, m := range reScriptSrc.FindAllStringSubmatch(html, -1) {
		enqueueChunk(m[1], baseURL)
	}
	for len(queue) > 0 && len(out.Bundles) < jsReconMaxBundles {
		u := queue[0]
		queue = queue[1:]
		body := httpGet(client, u, headers)
		if body == "" {
			continue
		}
		out.Bundles = append(out.Bundles, u)
		process(body, u)
	}
	out.Endpoints = sortedCap(endpointSet, jsReconMaxEndpoints)
	out.EndpointGroups = sortedCap(grpSet, 40)
	out.Routes = sortedCap(routeSet, 40)
	for _, l := range leakSet {
		out.Leaks = append(out.Leaks, l)
	}
	sort.Slice(out.Leaks, func(i, j int) bool {
		if out.Leaks[i].Key != out.Leaks[j].Key {
			return out.Leaks[i].Key < out.Leaks[j].Key
		}
		return out.Leaks[i].Val < out.Leaks[j].Val
	})
	if len(out.Leaks) > jsReconMaxLeaks {
		out.Leaks = out.Leaks[:jsReconMaxLeaks]
	}
	return out
}

func httpGet(client *http.Client, rawURL string, headers map[string]string) string {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return ""
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return ""
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return ""
	}
	return string(body)
}

func sortedCap(m map[string]bool, n int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	return sortedCap(m, 40)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func truncRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

var cloudAKPatterns = []struct {
	provider string
	re       *regexp.Regexp
}{
	{creds.ProviderAWS, regexp.MustCompile(`\b(AKIA[0-9A-Z]{16})\b`)},
	{creds.ProviderAliyun, regexp.MustCompile(`\b(LTAI[0-9A-Za-z]{12,24})\b`)},
	{creds.ProviderTencent, regexp.MustCompile(`\b(AKID[0-9A-Za-z]{13,20})\b`)},
	{creds.ProviderVolc, regexp.MustCompile(`\b(AKLT[0-9A-Za-z]{11,40})\b`)},
}

// cloudSecretRe 命中原文里的 Secret 候选（key=value / key: value / "key":"value"）。
var cloudSecretRe = regexp.MustCompile(`(?i)(?:secret(?:_?access)?_?key|access_?key_?secret)\s*[=:"]\s*["']?([A-Za-z0-9/+=_\-]{16,64})`)

const (
	maxCloudAKVerify = 5 // 单次命中最多验证对数（防轰炸 STS）
	maxCloudSecrets  = 3 // 原文里最多取 3 个 secret 候选参与配对
)

func SniffCloudAKs(src string) []CloudAK {
	seen := map[string]bool{}
	var out []CloudAK
	for _, p := range cloudAKPatterns {
		for _, m := range p.re.FindAllStringSubmatch(src, -1) {
			if len(m) < 2 || seen[m[1]] || creds.LooksLikePlaceholder(m[1]) {
				continue
			}
			seen[m[1]] = true
			out = append(out, CloudAK{AccessKey: m[1], Provider: p.provider})
			if len(out) >= maxCloudAKVerify {
				return out
			}
		}
	}
	return out
}

// SniffCloudSecrets 从命中原文嗅探 Secret 候选：去重 + 截断上限。纯函数。
func SniffCloudSecrets(src string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range cloudSecretRe.FindAllStringSubmatch(src, -1) {
		if len(m) < 2 || seen[m[1]] {
			continue
		}
		seen[m[1]] = true
		out = append(out, m[1])
		if len(out) >= maxCloudSecrets {
			break
		}
	}
	return out
}

// hostOf URL 主机名提取(小写;解析失败返回原串)。
func hostOf(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
		return strings.ToLower(u.Hostname())
	}
	return strings.ToLower(strings.TrimSpace(raw))
}

// CloudAK 嗅探到的云 AK 候选。
type CloudAK struct {
	AccessKey string
	Provider  string
}

// Dict 标准未授权端点字典(拷贝)。
func Dict() []string { return append([]string(nil), unauthDict...) }
