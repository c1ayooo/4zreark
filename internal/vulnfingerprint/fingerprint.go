// Package vulnfingerprint 漏洞级去重指纹 + 软匹配（对标 AutoHunter 移植项 #7，文档 §3.2）。
//
// 指纹口径（照搬对方实测形态）：sha256(主机 | endpoint(路径+参数名，剥参数值) | 方法 | 归一漏洞类型)，
// 跨任务、不含 task/conversation id——同一个注入点在不同参数值上不再重复报。
//
// 软匹配：同主机同类型标题高相似 / 跨主机同 endpoint 同类型——相似度为 Levenshtein 比
// （difflib ratio 的工程近似）。阈值默认取保守值并须用我方历史漏洞库回测后校准
// （对方阈值与其数据分布绑定，直接照搬会误合并）。
//
// 红线：本包只判「像不像」，不做删除/合并——查重命中回灌给调用方（模型/人工裁决），
// 防漏报优先于防重复（平台用户裁决红线：防漏扫）。
package vulnfingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"sort"
	"strings"
)

// 软匹配阈值（默认保守；待我方历史漏洞库回测后校准——见包注释）。
var (
	// SameHostTitleRatio 同主机同类型的标题相似度阈值（对方 0.86）。
	SameHostTitleRatio = 0.86
	// CrossHostTitleRatio 跨主机同 endpoint 同类型的标题相似度阈值（对方 0.78）。
	CrossHostTitleRatio = 0.78
)

// NormalizeHost 目标串 → 归一主机（小写、去协议/路径/端口、去尾点）。非 URL 形态按原文小写。
func NormalizeHost(target string) string {
	t := strings.ToLower(strings.TrimSpace(target))
	if t == "" {
		return ""
	}
	if i := strings.Index(t, "://"); i >= 0 {
		t = t[i+3:]
	}
	if i := strings.IndexAny(t, "/?#"); i >= 0 {
		t = t[:i]
	}
	// 去 userinfo
	if i := strings.LastIndex(t, "@"); i >= 0 {
		t = t[i+1:]
	}
	// 保留端口（同主机不同端口是不同服务面），去尾点
	return strings.TrimSuffix(t, ".")
}

// Endpoint 提取 endpoint：URL 路径 + 参数名集合（值剥掉、名排序）。
// 优先 vuln_urls 首个 URL；否则从 target/repro 里找首个 URL；都无 → 空串（指纹退化为主机+类型）。
func Endpoint(target, vulnURLs, reproSteps string) string {
	raw := firstURL(vulnURLs)
	if raw == "" {
		raw = firstURL(target)
	}
	if raw == "" {
		raw = firstURL(reproSteps)
	}
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	names := make([]string, 0, 4)
	for k := range u.Query() {
		names = append(names, strings.ToLower(k))
	}
	sort.Strings(names)
	if len(names) == 0 {
		return strings.ToLower(path)
	}
	return strings.ToLower(path) + "?" + strings.Join(names, "&")
}

// firstURL 文本中首个 http(s) URL。
func firstURL(text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	lower := strings.ToLower(text)
	for _, proto := range []string{"http://", "https://"} {
		if i := strings.Index(lower, proto); i >= 0 {
			rest := text[i:]
			if j := strings.IndexAny(rest, " \t\r\n\"'<>）)】]"); j > 0 {
				rest = rest[:j]
			}
			return rest
		}
	}
	return ""
}

// Fingerprint 去重指纹：sha256(主机 | endpoint | 方法 | 归一类型)。
// method 取复现步骤里的首个 HTTP 动词（默认 GET）；同注入点不同参数值指纹相同。
func Fingerprint(host, endpoint, method, vulnType string) string {
	h := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(host)) + "|" +
		strings.ToLower(strings.TrimSpace(endpoint)) + "|" +
		strings.ToUpper(strings.TrimSpace(method)) + "|" +
		strings.TrimSpace(vulnType)))
	return hex.EncodeToString(h[:])
}

// MethodFromRepro 复现步骤/证据里的首个 HTTP 动词（GET/POST/PUT/PATCH/DELETE），缺省 GET。
func MethodFromRepro(reproOrEvidence string) string {
	u := strings.ToUpper(reproOrEvidence)
	for _, m := range []string{"POST", "PUT", "PATCH", "DELETE", "GET"} {
		if strings.Contains(u, "\n"+m+" ") || strings.Contains(u, " "+m+" /") ||
			strings.HasPrefix(strings.TrimSpace(u), m+" ") {
			return m
		}
	}
	return "GET"
}

// Candidate 一条查重候选。
type Candidate struct {
	VulnID     string
	Title      string
	Kind       string  // exact：指纹完全一致 / same_host：同主机同类型高相似 / cross_host：跨主机同 endpoint 同类型
	Similarity float64 // 标题相似度（exact 为 1 的占位）
}

// TitleSimilarity Levenshtein 距离归一成 0-1 相似度（difflib ratio 近似）。
func TitleSimilarity(a, b string) float64 {
	a, b = strings.ToLower(strings.TrimSpace(a)), strings.ToLower(strings.TrimSpace(b))
	if a == b {
		return 1
	}
	ra, rb := []rune(a), []rune(b)
	if len(ra) == 0 || len(rb) == 0 {
		return 0
	}
	// 滚动两行 DP
	prev := make([]int, len(rb)+1)
	curr := make([]int, len(rb)+1)
	for j := 0; j <= len(rb); j++ {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		curr[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			curr[j] = minInt(prev[j]+1, curr[j-1]+1, prev[j-1]+cost)
		}
		prev, curr = curr, prev
	}
	dist := prev[len(rb)]
	maxLen := len(ra)
	if len(rb) > maxLen {
		maxLen = len(rb)
	}
	return 1.0 - float64(dist)/float64(maxLen)
}

func minInt(vals ...int) int {
	m := vals[0]
	for _, v := range vals[1:] {
		if v < m {
			m = v
		}
	}
	return m
}

// Existing 一条已存在漏洞的最小比对面（查重候选源）。
type Existing struct {
	ID, Title, Type, Target, VulnURLs, ReproSteps string
}

// Match 对已存在集合做查重：返回命中的候选（按强度排序：exact > same_host > cross_host）。
// 新记录面：newHost/newEndpoint/newMethod/newType/newTitle/newRepro。
// 只报告不裁决——是否合并由调用方（模型/人工）决定。
func Match(existing []Existing, newHost, newEndpoint, newMethod, newType, newTitle, newRepro string) []Candidate {
	newFP := Fingerprint(newHost, newEndpoint, newMethod, newType)
	var out []Candidate
	for _, e := range existing {
		eHost := NormalizeHost(e.Target)
		eEndpoint := Endpoint(e.Target, e.VulnURLs, e.ReproSteps)
		eType := strings.TrimSpace(e.Type)
		// 1. 精确指纹：同主机+同 endpoint(参数名)+同方法+同类型
		if Fingerprint(eHost, eEndpoint, MethodFromRepro(e.ReproSteps), eType) == newFP && newFP != "" {
			out = append(out, Candidate{VulnID: e.ID, Title: e.Title, Kind: "exact", Similarity: 1})
			continue
		}
		// 类型不同不比软匹配（不同漏洞族）
		if eType != newType {
			continue
		}
		sim := TitleSimilarity(e.Title, newTitle)
		// 2. 同主机同类型高相似
		if eHost == newHost && eHost != "" && sim >= SameHostTitleRatio {
			out = append(out, Candidate{VulnID: e.ID, Title: e.Title, Kind: "same_host", Similarity: sim})
			continue
		}
		// 3. 跨主机同 endpoint 同类型
		if eHost != newHost && eEndpoint != "" && eEndpoint == newEndpoint && sim >= CrossHostTitleRatio {
			out = append(out, Candidate{VulnID: e.ID, Title: e.Title, Kind: "cross_host", Similarity: sim})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return kindRank(out[i].Kind) < kindRank(out[j].Kind)
		}
		return out[i].Similarity > out[j].Similarity
	})
	return out
}

func kindRank(k string) int {
	switch k {
	case "exact":
		return 0
	case "same_host":
		return 1
	default:
		return 2
	}
}
