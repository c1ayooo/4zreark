package report

import (
	"encoding/base64"
	"html"
	"html/template"
	"regexp"
	"sort"
	"strings"
)

// 响应关键区域高亮：在响应原文上定位"证明漏洞的关键区域"，整体 HTML 转义后以
// <mark> 包裹（转义由本包完成，其余文本不可绕过转义——高亮不得引入对报告自身的注入）。
//
// 三级优先（高优先区间挖除低优先区间，互不嵌套）：
//   1. 内嵌图片（橙标还原）：data:image URI 或解码为图片魔数的 base64 长 run → 还原为 <img>
//   2. 证明位置（橙红 hl-proof）：agent 经 http_probe/save_evidence 的 proof 参数标注的
//      "证明漏洞的关键片段"（子串或正则）——这是报告该高亮的正主
//   3. 自动规则（黄 hl）：敏感字段键值、Authorization/Set-Cookie、JWT、身份证、手机号、邮箱，
//      以及请求回显（请求参数值在响应中出现=注入/反射/越权的直接证据）与漏洞类型特征正则

type hlRange struct {
	start, end int
	kind       hlKind
}

type hlKind int

const (
	hlAuto hlKind = iota
	hlProof
	hlImage
)

var (
	hlSensitiveRe = regexp.MustCompile(`(?i)(?:"?(?:access[_-]?token|refresh[_-]?token|api[_-]?key|access[_-]?key|session[_-]?id|jsessionid|authorization_token|password|passwd|pwd|token|secret|id_?card|idcard|身份证号|身份证|手机号|银行卡)"?\s*[:=]\s*"?[^",;}&\r\n]{1,120})|(?:authorization:\s*[^\r\n]{1,160})|(?:set-cookie:\s*[^\r\n]{1,160})`)
	hlJWTRe       = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}`)
	hlBearerRe    = regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._-]{16,}`)
	hlIDCardRe    = regexp.MustCompile(`\b[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:[0-2]\d|3[01])\d{3}[\dXx]\b`)
	hlPhoneRe     = regexp.MustCompile(`\b1[3-9]\d{9}\b`)
	hlEmailRe     = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`)
)

var hlEchoQueryRe = regexp.MustCompile(`[?&]([A-Za-z0-9_%-]+)=([^&\s]+)`)
var hlEchoJSONRe = regexp.MustCompile(`"([A-Za-z0-9_-]{2,32})"\s*:\s*"([^"]{4,128})"`)
var hlEchoFormRe = regexp.MustCompile(`(?:^|[\n\s&])([A-Za-z0-9_%-]+)=([^&\s]{4,128})`)

var hlTypePatterns = []struct {
	keywords []string
	res      []*regexp.Regexp
}{
	{[]string{"sql", "注入", "sqli"}, []*regexp.Regexp{
		regexp.MustCompile(`(?i)(sql syntax|sqlstate|ora-\d{5}|mysql|psql:\s|sqlite|syntax error|quoted string not properly terminated|unclosed quotation|odbc)`),
	}},
	{[]string{"命令注入", "command", "rce", "代码执行", "命令执行"}, []*regexp.Regexp{
		regexp.MustCompile(`(?i)(uid=\d+\([a-z-]+\) gid=|root:x?:0:0:|/bin/(ba)?sh|command not found)`)},
	},
	{[]string{"xss", "跨站"}, []*regexp.Regexp{
		regexp.MustCompile(`(?i)(<script[^>]*>|javascript:|\bonerror\s*=|\bonload\s*=|alert\()`)},
	},
	{[]string{"文件包含", "路径遍历", "目录遍历", "lfi", "traversal"}, []*regexp.Regexp{
		regexp.MustCompile(`root:x?:0:0:|\.\./|\[boot loader\]|daemon:/`)},
	},
}

var (
	hlDataURIRe = regexp.MustCompile(`data:image/(?:png|jpe?g|gif|webp|bmp);base64,[A-Za-z0-9+/=]{32,}`)
	hlB64RunRe  = regexp.MustCompile(`[A-Za-z0-9+/]{80,}={0,2}`)
)

// hlTypeRes 按漏洞类型关键字取特征正则
func hlTypeRes(vulnType string) []*regexp.Regexp {
	t := strings.ToLower(vulnType)
	if t == "" {
		return nil
	}
	var out []*regexp.Regexp
	for _, tp := range hlTypePatterns {
		for _, kw := range tp.keywords {
			if strings.Contains(t, strings.ToLower(kw)) {
				out = append(out, tp.res...)
				break
			}
		}
	}
	return out
}

// hlEchoTokens 从请求文本提取回显探针（参数值/JSON 值/form 值，4~128 字节，最多 20 个）
func hlEchoTokens(reqText string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if len(s) < 4 || len(s) > 128 || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	for _, m := range hlEchoQueryRe.FindAllStringSubmatch(reqText, -1) {
		add(m[2])
	}
	for _, m := range hlEchoJSONRe.FindAllStringSubmatch(reqText, -1) {
		add(m[2])
	}
	for _, m := range hlEchoFormRe.FindAllStringSubmatch(reqText, -1) {
		add(m[2])
	}
	if len(out) > 20 {
		out = out[:20]
	}
	return out
}

// hlProofRanges 证明位置区间：proofHint 优先按正则解析（无效则按字面子串）
func hlProofRanges(text, proofHint string) []hlRange {
	proofHint = strings.TrimSpace(proofHint)
	if proofHint == "" {
		return nil
	}
	var rs []hlRange
	if re, err := regexp.Compile(proofHint); err == nil {
		for _, loc := range re.FindAllStringIndex(text, 20) {
			rs = append(rs, hlRange{start: loc[0], end: loc[1], kind: hlProof})
		}
		return rs
	}
	off := 0
	for n := 0; n < 20; n++ {
		i := strings.Index(text[off:], proofHint)
		if i < 0 {
			break
		}
		rs = append(rs, hlRange{start: off + i, end: off + i + len(proofHint), kind: hlProof})
		off += i + len(proofHint)
	}
	return rs
}

// hlImageMime 解码 base64 前 32 字节识别图片魔数；非图片返回空
func hlImageMime(b64 string) string {
	raw, err := base64.StdEncoding.DecodeString(b64[:min(32, len(b64))])
	if err != nil && len(raw) == 0 {
		return ""
	}
	switch {
	case len(raw) >= 8 && string(raw[:8]) == "\x89PNG\r\n\x1a\n":
		return "image/png"
	case len(raw) >= 3 && raw[0] == 0xFF && raw[1] == 0xD8 && raw[2] == 0xFF:
		return "image/jpeg"
	case len(raw) >= 4 && string(raw[:4]) == "GIF8":
		return "image/gif"
	case len(raw) >= 12 && string(raw[:4]) == "RIFF" && string(raw[8:12]) == "WEBP":
		return "image/webp"
	case len(raw) >= 2 && raw[0] == 'B' && raw[1] == 'M':
		return "image/bmp"
	}
	return ""
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// hlImageRanges 识别响应中的内嵌图片：data:image URI 直接命中；
// 裸 base64 长 run 解码验魔数（防止把普通长 token 当图片），上限 4MB 字符。
func hlImageRanges(text string) []hlRange {
	var rs []hlRange
	for _, loc := range hlDataURIRe.FindAllStringIndex(text, 20) {
		rs = append(rs, hlRange{start: loc[0], end: loc[1], kind: hlImage})
	}
	for _, loc := range hlB64RunRe.FindAllStringIndex(text, 50) {
		if loc[1]-loc[0] > 4_200_000 {
			continue
		}
		if hlImageMime(text[loc[0]:loc[1]]) == "" {
			continue
		}
		rs = append(rs, hlRange{start: loc[0], end: loc[1], kind: hlImage})
	}
	return rs
}

// subtractRanges 从 ranges 中挖除 higher 区间（高优先级占位）
func subtractRanges(ranges, higher []hlRange) []hlRange {
	if len(higher) == 0 {
		return ranges
	}
	var out []hlRange
	for _, r := range ranges {
		cur := []hlRange{r}
		for _, h := range higher {
			var next []hlRange
			for _, c := range cur {
				if h.end <= c.start || h.start >= c.end {
					next = append(next, c)
					continue
				}
				if h.start > c.start {
					next = append(next, hlRange{start: c.start, end: h.start, kind: c.kind})
				}
				if h.end < c.end {
					next = append(next, hlRange{start: h.end, end: c.end, kind: c.kind})
				}
			}
			cur = next
		}
		out = append(out, cur...)
	}
	return out
}

// HighlightResponse 生成高亮后的响应 HTML：整体转义 + 分级 <mark>/<img>。
// proofHint 为 agent 标注的证明位置（子串或正则）；maxMarks 兜底防病态页面膨胀。
func HighlightResponse(respText, reqText, vulnType, proofHint string) template.HTML {
	if respText == "" {
		return ""
	}

	images := hlImageRanges(respText)
	proofs := subtractRanges(hlProofRanges(respText, proofHint), images)
	autoRes := []*regexp.Regexp{hlSensitiveRe, hlJWTRe, hlBearerRe, hlIDCardRe, hlPhoneRe, hlEmailRe}
	autoRes = append(autoRes, hlTypeRes(vulnType)...)
	var autos []hlRange
	for _, re := range autoRes {
		for _, loc := range re.FindAllStringIndex(respText, 50) {
			autos = append(autos, hlRange{start: loc[0], end: loc[1], kind: hlAuto})
		}
	}
	for _, lit := range hlEchoTokens(reqText) {
		off := 0
		for n := 0; n < 10; n++ {
			i := strings.Index(respText[off:], lit)
			if i < 0 {
				break
			}
			autos = append(autos, hlRange{start: off + i, end: off + i + len(lit), kind: hlAuto})
			off += i + len(lit)
		}
	}
	autos = subtractRanges(autos, proofs)
	autos = subtractRanges(autos, images)

	all := append(append(images, proofs...), autos...)
	sort.Slice(all, func(i, j int) bool { return all[i].start < all[j].start })

	const maxMarks = 300
	var b strings.Builder
	prev := 0
	marks := 0
	for _, r := range all {
		if r.start < prev {
			continue
		}
		b.WriteString(html.EscapeString(respText[prev:r.start]))
		switch r.kind {
		case hlImage:
			raw := respText[r.start:r.end]
			src := raw // data:image URI：整体即 src
			if !strings.HasPrefix(raw, "data:") {
				src = "data:" + hlImageMime(raw) + ";base64," + raw // 裸 base64：按魔数补 mime
			}
			b.WriteString(`<img class="resp-img" src="`)
			b.WriteString(html.EscapeString(src))
			b.WriteString(`" alt="响应内嵌图片（已还原）">`)
		case hlProof:
			b.WriteString(`<mark class="hl-proof">`)
			b.WriteString(html.EscapeString(respText[r.start:r.end]))
			b.WriteString("</mark>")
			marks++
		default:
			b.WriteString(`<mark class="hl">`)
			b.WriteString(html.EscapeString(respText[r.start:r.end]))
			b.WriteString("</mark>")
			marks++
		}
		prev = r.end
		if marks >= maxMarks {
			break
		}
	}
	b.WriteString(html.EscapeString(respText[prev:]))
	return template.HTML(b.String())
}
