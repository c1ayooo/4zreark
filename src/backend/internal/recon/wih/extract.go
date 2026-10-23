// Package wih 实现「WIH 式 JS 接口候选提取 + 同源受控探测」。
//
// extract.go 只做词法级分析（不执行 JS）：从 HTML/JS 文本里按固定优先级
// 抽出 fetch / axios / $.ajax / url-action-href 属性 / 相对路径字面量中的
// 接口候选，归一化为同源绝对路径并去重。
// probe.go 在同源约束下对候选路径做受控探测（HEAD 优先、限速、预算、
// 脱敏记录），输出可验证性结论。
package wih

import (
	"net/url"
	"regexp"
	"strings"
)

// EndpointCandidate 从页面/JS 文本中提取出的接口候选。
type EndpointCandidate struct {
	// Path 归一化后的同源绝对路径（不含 query 与 fragment）。
	Path string `json:"path"`
	// Source 提取来源：fetch / axios / ajax / attr / literal。
	Source string `json:"source"`
	// Raw 页面里的原始字符串（不含引号）。
	Raw string `json:"raw"`
}

const (
	// maxRawLen 单条原始字符串长度上限，超长的基本是打包产物里的噪声。
	maxRawLen = 200
	// maxCandidatesPerInput 单次提取的候选上限，防止巨型 JS 撑爆下游。
	maxCandidatesPerInput = 100
)

// 接口候选提取规则，按优先级从高到低排列：
// 同一条路径被多条规则命中时，取优先级最高的来源。
// RE2 不支持反向引用，引号统一用字符类匹配（只认单双引号，不认模板字符串）。
var extractionRules = []struct {
	source string
	re     *regexp.Regexp
}{
	// fetch("/api/x") / fetch('/api/x')
	{"fetch", regexp.MustCompile(`\bfetch\s*\(\s*["']([^"']{1,300})["']`)},
	// axios.get/post/put/patch/delete/head/request("...")
	{"axios", regexp.MustCompile(`\baxios\s*\.\s*(?:get|post|put|patch|delete|head|request)\s*\(\s*["']([^"']{1,300})["']`)},
	// $.ajax({ url: "..." })（允许 url 前有其它配置项）
	{"ajax", regexp.MustCompile(`(?s)\$\s*\.\s*ajax\s*\(\s*\{[^}]{0,500}?\burl\s*:\s*["']([^"']{1,300})["']`)},
	// url: "..." / action="..." / href="..."
	{"attr", regexp.MustCompile(`\b(?:url|action|href)\s*[:=]\s*["']([^"']{1,300})["']`)},
	// 形如 "/api/xxx"、"./api/xxx"、".../api/xxx" 的相对路径字符串字面量
	{"literal", regexp.MustCompile(`["']((?:\.\.?/)[^"']{0,199}|/[^"']{0,199})["']`)},
}

// nonHTTPSchemes 明显不是 HTTP 接口的协议前缀，直接排除。
var nonHTTPSchemes = []string{
	"mailto:", "javascript:", "data:", "tel:", "about:", "blob:", "file:",
}

// staticExts 探测无意义的静态资源扩展名。
// 注意 .json 刻意不在列表里：/api/config.json 这类路径本身就是接口目标。
// .js 也在列表里：候选是拿来发请求探测的，对 JS 文件本身发 GET 没有信息量。
var staticExts = map[string]struct{}{
	"js": {}, "mjs": {}, "cjs": {}, "css": {}, "map": {}, "wasm": {},
	"png": {}, "jpg": {}, "jpeg": {}, "gif": {}, "svg": {}, "ico": {},
	"webp": {}, "avif": {}, "bmp": {}, "tiff": {},
	"woff": {}, "woff2": {}, "ttf": {}, "otf": {}, "eot": {},
	"mp4": {}, "mp3": {}, "wav": {}, "webm": {}, "ogg": {},
}

// ExtractEndpoints 从 body 文本中做词法级接口提取。
// baseURL 用于把相对路径解析成同源绝对路径（url.ResolveReference），
// 解析失败或 baseURL 缺少 host 时返回 nil。
// 归一化只保留 path：query 会让候选组合爆炸，fragment 对探测无意义。
func ExtractEndpoints(baseURL, body string) []EndpointCandidate {
	base, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || base.Host == "" || body == "" {
		return nil
	}

	seen := make(map[string]struct{})
	out := make([]EndpointCandidate, 0, 16)
	for _, rule := range extractionRules {
		for _, m := range rule.re.FindAllStringSubmatch(body, -1) {
			raw := strings.TrimSpace(m[1])
			if len(raw) > maxRawLen {
				continue
			}
			path, ok := normalizeCandidate(base, raw)
			if !ok {
				continue
			}
			// 按归一化 path 去重，先到先得（即优先级最高的来源）
			if _, dup := seen[path]; dup {
				continue
			}
			seen[path] = struct{}{}
			out = append(out, EndpointCandidate{Path: path, Source: rule.source, Raw: raw})
			if len(out) >= maxCandidatesPerInput {
				return out
			}
		}
	}
	return out
}

// normalizeCandidate 把一条原始字符串归一化为同源绝对路径。
// 第二个返回值为 false 表示该字符串不是有效的同源接口候选。
func normalizeCandidate(base *url.URL, raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > maxRawLen {
		return "", false
	}
	// 纯锚点
	if strings.HasPrefix(raw, "#") {
		return "", false
	}
	// 非 HTTP 协议
	lower := strings.ToLower(raw)
	for _, scheme := range nonHTTPSchemes {
		if strings.HasPrefix(lower, scheme) {
			return "", false
		}
	}
	// 明显不是路径的字符串：内部空白、HTML 标签、模板占位符、转义噪声
	if strings.ContainsAny(raw, " \t\r\n<>\"'\\{}") {
		return "", false
	}
	// 接口路径至少要有一个 /
	if !strings.Contains(raw, "/") {
		return "", false
	}

	target := raw
	// 协议相对 URL（//host/path）：补上基准协议后按绝对 URL 处理
	if strings.HasPrefix(target, "//") {
		scheme := base.Scheme
		if scheme == "" {
			scheme = "https"
		}
		target = scheme + ":" + target
	}

	ref, err := url.Parse(target)
	if err != nil {
		return "", false
	}
	if strings.Contains(target, "://") {
		// 绝对 URL：只接受 http/https
		switch ref.Scheme {
		case "http", "https":
		default:
			return "", false
		}
	}

	resolved := base.ResolveReference(ref)
	// 第三方域名 / 跨 host 的绝对 URL 整体丢弃，不迁移到基准 host
	if resolved.Host != base.Host {
		return "", false
	}

	// 只留 path，丢掉 query 与 fragment
	path := resolved.Path
	if path == "" || path == "/" {
		// 裸根路径没有探测价值
		return "", false
	}
	if isStaticPath(path) {
		return "", false
	}
	return path, true
}

// isStaticPath 判断路径是否指向静态资源（按最后一段的扩展名）。
func isStaticPath(path string) bool {
	path = strings.ToLower(path)
	if i := strings.LastIndex(path, "/"); i >= 0 {
		path = path[i+1:]
	}
	dot := strings.LastIndex(path, ".")
	if dot < 0 || dot == len(path)-1 {
		return false
	}
	_, ok := staticExts[path[dot+1:]]
	return ok
}
