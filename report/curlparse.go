package report

import (
	"fmt"
	"net/url"
	"strings"
)

// curl → 标准 HTTP 报文转换。
//
// 背景：agent 常用 exec curl 验证漏洞，证据/POC 字段里存的是 curl 命令原文；
// 报告需要"请求行+请求头+请求体 / 响应"的报文形态。这里把 curl 命令精确还原为
// 请求报文；命令之外的剩余文本（通常是 curl 的响应输出）作为响应区呈现。
//
// 输出沿用证据库报文格式：=== REQUEST ===\n...\n=== RESPONSE ===\n...

// CurlToTranscript 识别内容中的 curl 命令并转为报文格式。
// 多条 curl 时只转第一条（多包场景应由 http_probe 分包归档）；无 curl 返回原内容与 false。
func CurlToTranscript(content string) (string, bool) {
	start, ok := findCurlStart(content)
	if !ok {
		return content, false
	}
	args, cmdEnd := curlArgBlock(content, start)
	if strings.TrimSpace(args) == "" {
		return content, false
	}
	p := &curlParser{args: args}
	req, ok := p.parse()
	if !ok {
		return content, false
	}
	// 剩余文本 = curl 命令块之后的输出（响应）
	rest := strings.TrimSpace(content[cmdEnd:])
	resp := rest
	if resp == "" {
		resp = "（curl 命令未附带响应输出）"
	}
	return "=== REQUEST ===\n" + req + "\n=== RESPONSE ===\n" + resp, true
}

// findCurlStart 定位作为独立命令词的 curl（避免匹配文档里的普通 "curl" 单词）
func findCurlStart(s string) (int, bool) {
	off := 0
	for {
		i := strings.Index(s[off:], "curl")
		if i < 0 {
			return 0, false
		}
		abs := off + i
		before := byte(' ')
		if abs > 0 {
			before = s[abs-1]
		}
		after := byte(' ')
		if abs+4 < len(s) {
			after = s[abs+4]
		}
		isWord := func(c byte) bool {
			return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		}
		if !isWord(before) && !isWord(after) && after != '-' {
			return abs, true
		}
		off = abs + 4
	}
}

// curlArgBlock 取 curl 之后的参数块：支持 `\`+换行 续行，裸换行结束（引号内换行视为结束，罕见场景）
func curlArgBlock(s string, start int) (args string, end int) {
	i := start + 4
	// 跳过 curl 后的空白
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	blockStart := i
	for i < len(s) {
		switch s[i] {
		case '\'':
			i++
			for i < len(s) && s[i] != '\'' {
				if s[i] == '\\' && i+1 < len(s) {
					i++
				}
				i++
			}
			i++
		case '"':
			i++
			for i < len(s) && s[i] != '"' {
				if s[i] == '\\' && i+1 < len(s) {
					i++
				}
				i++
			}
			i++
		case '\\':
			if i+1 < len(s) && (s[i+1] == '\n' || s[i+1] == '\r') {
				i += 2
				continue
			}
			i++
		case '\n':
			return s[blockStart:i], i + 1
		default:
			i++
		}
	}
	return s[blockStart:], len(s)
}

// get0 取下一个值参数（不存在返回空串）；unquote0 去引号
func get0(p *curlParser) string {
	v, _, ok := p.next()
	if !ok {
		return ""
	}
	return v
}
func unquote0(s string) string { return unquote(s) }

type curlParser struct {
	args string
	pos  int
}

// curlArgs curl 参数的结构化解析结果（报文构造与漏洞记录时的 curl 回放共用）
type curlArgs struct {
	method  string
	rawURL  string
	body    string
	userAg  string
	headers []string // 有序请求头（含 -b/-u 合成项；不含自动补全的 Host）
	hostSet bool     // 是否显式指定 Host 头
}

// parseCurlArgs 遍历 curl 参数串提取方法/URL/头/体；解析不出 URL 返回 false
func parseCurlArgs(p *curlParser) (curlArgs, bool) {
	var a curlArgs
	seenHeaders := map[string]bool{}

	get := func() (string, bool, bool) {
		arg, hasNext, ok := p.next()
		return arg, hasNext, ok
	}
	for {
		arg, hasNext, ok := get()
		if !ok {
			break
		}
		switch {
		case arg == "-X" || arg == "--request":
			if hasNext {
				a.method = unquote0(get0(p))
			}
		case arg == "-H" || arg == "--header":
			if hasNext {
				h, _, _ := get()
				h = unquote(h)
				a.headers = append(a.headers, h)
				if k := strings.ToLower(h); strings.HasPrefix(k, "host:") {
					seenHeaders["host"] = true
				}
			}
		case arg == "-d" || arg == "--data" || arg == "--data-raw" || arg == "--data-binary" || arg == "--data-urlencode":
			if hasNext {
				d, _, _ := get()
				d = unquote(d)
				if a.body != "" {
					a.body += "&" + d
				} else {
					a.body = d
				}
				if a.method == "" {
					a.method = "POST"
				}
			}
		case arg == "-A" || arg == "--user-agent":
			if hasNext {
				a.userAg = unquote0(get0(p))
			}
		case arg == "-b" || arg == "--cookie":
			if hasNext {
				c := unquote0(get0(p))
				a.headers = append(a.headers, "Cookie: "+c)
			}
		case arg == "-u" || arg == "--user":
			if hasNext {
				u := unquote0(get0(p))
				a.headers = append(a.headers, "Authorization: Basic "+u+" （Basic 凭据原样保留）")
			}
		case arg == "--json":
			if hasNext {
				d := unquote0(get0(p))
				a.body = d
				if a.method == "" {
					a.method = "POST"
				}
				if !hasHeaderKey(a.headers, "content-type") {
					a.headers = append(a.headers, "Content-Type: application/json")
				}
			}
		case arg == "-k" || arg == "--insecure" || arg == "-s" || arg == "--silent" ||
			arg == "-i" || arg == "--include" || arg == "-v" || arg == "--verbose" ||
			arg == "-L" || arg == "--location" || arg == "--compressed" || arg == "-f" || arg == "--fail":
			// 输出控制类 flag：不影响报文
		case strings.HasPrefix(arg, "-"):
			// 未知 flag：吃掉它的值（保守处理，避免把值当 URL）
			if hasNext && !strings.HasPrefix(p.peek(), "-") {
				_, _, _ = get()
			}
		default:
			if a.rawURL == "" && (strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "https://") || !strings.HasPrefix(arg, "-")) {
				a.rawURL = unquote(arg)
			}
		}
	}
	if a.rawURL == "" {
		return curlArgs{}, false
	}
	a.hostSet = seenHeaders["host"]
	return a, true
}

// parse 解析 curl 参数串 → 完整请求报文（请求行 + 头 + 空行 + 体）
func (p *curlParser) parse() (string, bool) {
	a, ok := parseCurlArgs(p)
	if !ok {
		return "", false
	}
	method := a.method
	if method == "" {
		method = "GET"
	}
	hosts := a.headers
	if a.userAg != "" && !hasHeaderKey(hosts, "user-agent") {
		hosts = append(hosts, "User-Agent: "+a.userAg)
	}

	// 请求行：method path HTTP/1.1；Host 头
	host, path := splitURL(a.rawURL)
	if !a.hostSet {
		hosts = append([]string{"Host: " + host}, hosts...)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\n", method, path)
	for _, h := range hosts {
		b.WriteString(h)
		b.WriteString("\n")
	}
	if a.body != "" {
		if !hasHeaderKey(hosts, "content-length") {
			fmt.Fprintf(&b, "Content-Length: %d\n", len(a.body))
		}
		b.WriteString("\n")
		b.WriteString(a.body)
	} else {
		b.WriteString("\n")
	}
	return b.String(), true
}

// CurlRequest 结构化 curl 请求（供漏洞记录时的回放引擎原样重发）
type CurlRequest struct {
	Method    string
	URL       string
	Headers   []string // 有序 "Key: Value"（含 -b/-u 合成项）
	UserAgent string   // -A/--user-agent 指定的 UA（不在 Headers 里，回放时单独透传）
	Body      string
}

// ContainsCurlCommand 判断文本中是否存在可作为独立命令词的 curl
func ContainsCurlCommand(s string) bool {
	_, ok := findCurlStart(s)
	return ok
}

// ParseCurlRequest 识别并解析文本中的第一条 curl 命令为结构化请求。
// 多条 curl 只取第一条；无 curl 或解析不出 URL 时 ok=false。
func ParseCurlRequest(content string) (*CurlRequest, bool) {
	start, ok := findCurlStart(content)
	if !ok {
		return nil, false
	}
	args, _ := curlArgBlock(content, start)
	if strings.TrimSpace(args) == "" {
		return nil, false
	}
	a, ok := parseCurlArgs(&curlParser{args: args})
	if !ok {
		return nil, false
	}
	method := a.method
	if method == "" {
		method = "GET"
	}
	return &CurlRequest{Method: method, URL: a.rawURL, Headers: a.headers, UserAgent: a.userAg, Body: a.body}, true
}

// next 取下一个参数：支持空格分隔与引号块（单/双引号内含空格）与行尾续行 `\`
func (p *curlParser) next() (arg string, hasNext bool, ok bool) {
	s := p.args
	for p.pos < len(s) {
		// 跳过空白与续行符
		for p.pos < len(s) && (s[p.pos] == ' ' || s[p.pos] == '\t' || s[p.pos] == '\n' || s[p.pos] == '\r') {
			p.pos++
		}
		// 续行 `\` + 换行
		if p.pos < len(s) && s[p.pos] == '\\' && p.pos+1 < len(s) && (s[p.pos+1] == '\n' || s[p.pos+1] == '\r') {
			p.pos += 2
			continue
		}
		if p.pos >= len(s) {
			break
		}
		start := p.pos
		if s[p.pos] == '\'' || s[p.pos] == '"' {
			q := s[p.pos]
			p.pos++
			for p.pos < len(s) && s[p.pos] != q {
				if s[p.pos] == '\\' && p.pos+1 < len(s) {
					p.pos++
				}
				p.pos++
			}
			p.pos++ // 吃掉闭合引号
		} else {
			for p.pos < len(s) && s[p.pos] != ' ' && s[p.pos] != '\t' && s[p.pos] != '\n' && s[p.pos] != '\r' {
				p.pos++
			}
		}
		arg := s[start:p.pos]
		return arg, p.pos < len(s), true
	}
	return "", false, false
}

func (p *curlParser) peek() string {
	save := p.pos
	arg, _, _ := p.next()
	p.pos = save
	return arg
}

func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '\'' && s[len(s)-1] == '\'') || (s[0] == '"' && s[len(s)-1] == '"') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

func hasHeaderKey(headers []string, key string) bool {
	for _, h := range headers {
		if strings.HasPrefix(strings.ToLower(h), key+":") {
			return true
		}
	}
	return false
}

func splitURL(raw string) (host, path string) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		// 解析失败：整体当 path，host 留空提示
		return "(unparsed)", raw
	}
	host = u.Host
	path = u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}
	return host, path
}
