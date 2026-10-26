package fingerprint

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"regexp"
	"strings"
	"time"

	"github.com/spaolacci/murmur3"
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/encoding/traditionalchinese"
)

const (
	scanTimeout    = 20 * time.Second
	faviconTimeout = 6 * time.Second
	maxBodyScan    = 512 * 1024
)

var titleRE = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// icpRE 页面 ICP 备案号提取：省简称 + ICP备/证 + 数字 + 号(-N 子号)。
// 页脚格式如 "粤ICP备14006354号-1"、"京ICP证123456号"；公安备案(公网安备)不是
// ICP，不匹配。主号 = 省+ICP备/证+数字+号（裂变反查用主号）。
// 省简称除 MIIT 标准简称外收录常见方言前缀：蜀(川)、陇(甘)——线上实测
// woniuxy.com 页脚即 "蜀ICP备15014130号-2"，标准集不含蜀会漏提。
var icpRE = regexp.MustCompile(`([京津沪渝冀晋蒙辽吉黑苏浙皖闽赣鲁豫鄂湘粤桂琼川黔滇藏陕甘青宁新蜀陇])ICP(备|证)(\d{4,10})号(?:-\d{1,6})?`)

// ExtractICP 从页面文本提取首个 ICP 备案号并归一化为主号（去 -N 子号）。
// 没有命中返回空串。多备案号页面取第一个（主站页脚通常只有一个主备案）。
func ExtractICP(body string) string {
	m := icpRE.FindStringSubmatch(body)
	if m == nil {
		return ""
	}
	return m[1] + "ICP" + m[2] + m[3] + "号"
}

// NormalizeICP 把任意文本（引擎返回行的 icp 字段、用户输入）中的 ICP 备案号
// 归一化为主号，供多引擎反查统一使用。无命中返回空串。
func NormalizeICP(raw string) string {
	return ExtractICP(raw)
}

// linkRE 提取 href 属性值（a/link 标签为主，兼容单引号与裸值）。
// 不解析完整 HTML：门户页链接密度高，正则单遍扫描足够且零依赖。
var linkRE = regexp.MustCompile(`(?is)<a\b[^>]*?\bhref\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))`)

// ExtractLinks 从页面 HTML 提取链接（绝对 URL，相对路径按 baseURL 解析）。
// 过滤 mailto/javascript/tel 等非 http 链接与页面内锚点，去重并截断到 limit。
// 业务系统入口常以相对路径（/oa、./mail）或跨子域绝对路径出现，都保留。
func ExtractLinks(body, baseURL string, limit int) []string {
	if limit <= 0 {
		limit = 50
	}
	base, baseErr := neturl.Parse(strings.TrimSpace(baseURL))
	out := make([]string, 0, 32)
	seen := map[string]bool{}
	for _, m := range linkRE.FindAllStringSubmatch(body, -1) {
		raw := m[2]
		if raw == "" {
			raw = m[3]
		}
		if raw == "" {
			raw = m[4]
		}
		raw = strings.TrimSpace(raw)
		if raw == "" || strings.HasPrefix(raw, "#") ||
			strings.HasPrefix(raw, "mailto:") || strings.HasPrefix(raw, "javascript:") ||
			strings.HasPrefix(raw, "tel:") {
			continue
		}
		u, err := neturl.Parse(raw)
		if err != nil || u == nil {
			continue
		}
		if u.Scheme == "" {
			if baseErr != nil || base == nil {
				continue // 相对路径但无 base，无法定位
			}
			u = base.ResolveReference(u)
		}
		if u.Scheme != "http" && u.Scheme != "https" || u.Host == "" {
			continue
		}
		u.Fragment = ""
		// 静态资源（css/js/图片/字体等）不进链接候选：对 links/link_hosts 分桶是纯噪声
		if PathKind(u.Path) == "static" {
			continue
		}
		link := u.String()
		if seen[link] {
			continue
		}
		seen[link] = true
		out = append(out, link)
		if len(out) >= limit {
			break
		}
	}
	return out
}

// ProbeHTTPObservation 主动探测目标并构建 Observation。
// target 支持 http(s):// 前缀；无前缀先 https 后 http 回退。
func ProbeHTTPObservation(ctx context.Context, target string, client *http.Client) (Observation, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return Observation{}, fmt.Errorf("目标为空")
	}
	urls := []string{}
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		urls = append(urls, target)
	} else {
		urls = append(urls, "https://"+target, "http://"+target)
	}
	if client == nil {
		client = &http.Client{
			Timeout: scanTimeout,
			Transport: &http.Transport{
				TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, // 渗透场景自签证书
				DisableKeepAlives: true,
			},
			// 跳数上限单点（本客户端无授权范围入参，scope 传 nil）+ 同主机跳转策略
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	var lastErr error
	for _, u := range urls {
		obs, err := probeOne(ctx, client, u)
		if err == nil {
			return obs, nil
		}
		lastErr = err
	}
	return Observation{}, fmt.Errorf("探测失败: %w", lastErr)
}

// charsetPattern 从 Content-Type 或 <meta> 标签取 charset 参数值。
var charsetFromHeaderRE = regexp.MustCompile(`(?i)charset\s*=\s*"?([a-z0-9_-]+)"?`)
var charsetFromMetaRE = regexp.MustCompile(`(?is)<meta[^>]+charset\s*=\s*["']?([a-z0-9_-]+)`)

// normalizeCharset 归一化 charset 名到本包支持的解码器：gb18030 / big5 / windows-1252，
// 空串表示 UTF-8 直读（unknown 一律直读 + ToValidUTF8 兜底，避免误解码造成更大破坏）。
func normalizeCharset(name string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "gb2312", "gbk", "gb18030", "gbk2312", "csgb2312":
		return "gb18030"
	case "big5", "big5hkscs", "big-five", "csbig5":
		return "big5"
	case "latin1", "iso-8859-1", "iso8859-1", "windows-1252", "windows1252", "cp1252":
		return "windows-1252"
	default:
		return ""
	}
}

// decodeHTMLBody 把页面字节解码为合法 UTF-8 字符串。
// 中文门户（高校 auth/webvpn 尤甚）常用 GBK：不解码时标题是非法 UTF-8 字节
// （如 0xce 0xf7 = "维"），PostgreSQL 入库直接报 invalid byte sequence，
// 一条毒化整批聚合 upsert。GB18030 是 GBK/GB2312 的超集，统一用它解。
// charset 判定顺序：Content-Type 头 → <meta> 嗅探（前 2KB）→ 直读。
func decodeHTMLBody(raw []byte, contentType string) string {
	charset := ""
	if m := charsetFromHeaderRE.FindStringSubmatch(contentType); len(m) == 2 {
		charset = m[1]
	}
	if normalizeCharset(charset) == "" {
		sniff := raw
		if len(sniff) > 2048 {
			sniff = sniff[:2048]
		}
		if m := charsetFromMetaRE.FindStringSubmatch(string(sniff)); len(m) == 2 {
			charset = m[1]
		}
	}
	var decoded []byte
	var err error
	switch normalizeCharset(charset) {
	case "gb18030":
		decoded, err = simplifiedchinese.GB18030.NewDecoder().Bytes(raw)
	case "big5":
		decoded, err = traditionalchinese.Big5.NewDecoder().Bytes(raw)
	case "windows-1252":
		decoded, err = charmap.Windows1252.NewDecoder().Bytes(raw)
	default:
		decoded, err = raw, nil
	}
	if err != nil || decoded == nil {
		decoded = raw
	}
	// 兜底：未声明 charset 的 GBK 页面等场景，替换非法字节而非让它们流进库
	return strings.ToValidUTF8(string(decoded), "\uFFFD")
}

// linkHostLabelPattern 页面链接主机校验（与 infocollect.ParseTarget 的域名规则同构）：
// 防止页面里的畸形 href（HTML 片段、下划线主机等）混进 links/link_hosts 当域名。
var linkHostLabelPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

func validLinkHost(host string) bool {
	host = strings.ToLower(strings.Trim(strings.TrimSpace(host), "[]"))
	if host == "" || strings.Contains(host, "..") {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || !linkHostLabelPattern.MatchString(label) {
			return false
		}
	}
	return true
}

func probeOne(ctx context.Context, client *http.Client, url string) (Observation, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Observation{}, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
	resp, err := client.Do(req)
	if err != nil {
		return Observation{}, err
	}
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyScan))
	// 原始字节与解码后文本分离：body_hash 保持原始口径（与 fofa 等外部哈希可比），
	// 标题/备案号/链接/规则匹配用解码后的 UTF-8 文本（GBK 页面否则全军覆没）。
	rawBody := string(bodyBytes)
	body := decodeHTMLBody(bodyBytes, resp.Header.Get("Content-Type"))

	obs := Observation{
		Status:      resp.StatusCode,
		Headers:     map[string]string{},
		Body:        body,
		ContentType: resp.Header.Get("Content-Type"),
		Server:      resp.Header.Get("Server"),
	}
	var hb strings.Builder
	for k, vs := range resp.Header {
		lk := strings.ToLower(k)
		for _, v := range vs {
			obs.Headers[lk] = v
			hb.WriteString(lk + ": " + v + "\n")
			if lk == "set-cookie" {
				obs.Cookie += v + "\n"
			}
		}
	}
	obs.HeaderText = hb.String()
	if m := titleRE.FindStringSubmatch(body); len(m) == 2 {
		obs.Title = strings.TrimSpace(m[1])
	}
	obs.BodyHash = md5Hex(rawBody)

	// 跟随重定向后，最终落点是哪个 URL 就按哪个回填：http→https、→/login 跟随
	// 成功时观测结果必须反映真实落点，否则看起来像“没跟随”。
	finalURL := url
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}
	obs.Protocol = "http"
	if strings.HasPrefix(finalURL, "https://") {
		obs.Protocol = "https"
	}
	// 从最终 URL 回填 host/port（资产入库与展示依赖）
	if u, perr := neturl.Parse(finalURL); perr == nil {
		obs.Host = u.Hostname()
		if p := u.Port(); p != "" {
			fmt.Sscanf(p, "%d", &obs.Port)
		} else if obs.Protocol == "https" {
			obs.Port = 443
		} else {
			obs.Port = 80
		}
	}
	obs.Path = finalURL
	if i := strings.IndexByte(finalURL, ':'); i >= 0 {
		rest := finalURL[i+3:] // 跳过 ://
		if j := strings.IndexByte(rest, '/'); j >= 0 {
			obs.Path = rest[j:]
		} else {
			obs.Path = "/"
		}
	}
	// favicon mmh3（fofa 风格：base64 后取 murmur3）
	favCtx, cancel := context.WithTimeout(ctx, faviconTimeout)
	defer cancel()
	if icon := fetchFaviconHash(favCtx, client, finalURL); icon != "" {
		obs.IconHash = icon
	}
	// 页面 ICP 备案号：ICP 裂变反查的锚点（探测顺带提取，零额外请求）
	obs.ICP = ExtractICP(body)
	// 页面链接：门户页常挂多个业务系统入口（mail/oa/survey…），
	// 提取出来就是资产线索——只提取不追访，追不追由调用方（agent）决定。
	// 上限放宽到 150：same_host 链接常占满名额，过小会截掉尾部跨域/CDN 主机
	//（分桶层另有每桶 20 host 上限，payload 不膨胀）
	links := ExtractLinks(body, finalURL, 150)
	// 畸形主机过滤：HTML 片段/下划线主机不配当域名（link_hosts 会进资产候选链路）
	filtered := links[:0]
	for _, link := range links {
		if u, err := neturl.Parse(link); err == nil && validLinkHost(u.Hostname()) {
			filtered = append(filtered, link)
		}
	}
	obs.Links = filtered
	return obs, nil
}

func fetchFaviconHash(ctx context.Context, client *http.Client, pageURL string) string {
	base := pageURL
	if i := strings.Index(base, "://"); i >= 0 {
		rest := base[i+3:]
		end := strings.IndexByte(rest, '/')
		host := rest
		if end >= 0 {
			host = rest[:end]
		}
		scheme := base[:i]
		base = scheme + "://" + host
	} else {
		return ""
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/favicon.ico", nil)
	if err != nil {
		return ""
	}
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return ""
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil || len(data) == 0 {
		return ""
	}
	return faviconMMH3(data)
}

// faviconMMH3 计算 favicon 字节的 mmh3 哈希（fofa 风格，int32 有符号十进制）。
// golden 基准与边界语义见 favicon_hash_golden_test.go。
func faviconMMH3(data []byte) string {
	h := murmur3.New32WithSeed(0) // mmh3 标准实现（非 seed 变体由 Sum32 覆盖）
	_, _ = h.Write([]byte(stdBase64MIME(data)))
	return fmt.Sprint(int32(h.Sum32()))
}

// stdBase64MIME 输出 76 列断行 + 结尾补 \n 的 MIME 风格 base64（与 Python
// base64.encodebytes 逐字节一致）。🔴 2026-09-28（EHole 对标 E1）：favicon mmh3
// 的社区标准配方是 mmh3(encodebytes(favicon))，dddd/EHole/FOFA 的 icon_hash 值全部
// 生成于该空间；此前用 base64.StdEncoding 单行编码，算出的哈希与规则值域完全
// 不同空间，库内 80 条 icon_hash 规则（dddd 快照）永不命中。实证：同一字节串
// 单行算法与标准算法产出两个不相干的哈希（docs/EHole指纹库对标-4zreco缺口
// 盘点与补齐方案.md §五）。
func stdBase64MIME(data []byte) string {
	raw := base64.StdEncoding.EncodeToString(data)
	var buf bytes.Buffer
	for i := 0; i < len(raw); i++ {
		buf.WriteByte(raw[i])
		if (i+1)%76 == 0 {
			buf.WriteByte('\n')
		}
	}
	// 只在最后一段不是整 76 列时补换行。整倍数时上面已经写过换行，
	// 再补一次会与 Python encodebytes 产生双换行（图标 55–57 字节就是
	// 这种边界），哈希随之落到另一个空间。
	if len(raw)%76 != 0 {
		buf.WriteByte('\n')
	}
	return buf.String()
}

func md5Hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}
