package webscan

import (
	"context"
	"fmt"
	"github.com/c1ayooo/4zreark/internal/useragent"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// 软 404 基线：有些站点对任意路径都返回 200 + 同一个错误页（或 WAF 挑战页），
// 目录扫描会把这些路径全部当成「命中」。这里先请求 2–3 个随机路径，若响应
// 状态/标题/正文长度高度一致，就把它当作基线，把同签名的扫描结果剔除。
//
// 只处理「成功形态」的基线（2xx/3xx）；真实 404/403 页面不建立基线，
// 那些由 spray 自身的 valid 判定处理。

type soft404Signature struct {
	status      int
	title       string
	contentType string
	bodyLen     int64
}

type soft404Filter struct {
	byOrigin map[string]*soft404Signature
	client   *http.Client
}

var soft404TitleRE = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// FilterSoft404Entries 按 URL 来源分组建立基线并过滤（批量模式用）。
func FilterSoft404Entries(ctx context.Context, entries []SprayEntry, client *http.Client) []SprayEntry {
	if len(entries) == 0 {
		return entries
	}
	if client == nil {
		client = &http.Client{
			Timeout: 8 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	f := &soft404Filter{byOrigin: map[string]*soft404Signature{}, client: client}
	out := make([]SprayEntry, 0, len(entries))
	for _, e := range entries {
		origin := originOf(firstNonEmptyString(e.URL, e.Host))
		if origin == "" {
			out = append(out, e)
			continue
		}
		sig, seen := f.byOrigin[origin]
		if !seen {
			sig = buildSoft404Signature(ctx, origin, f.client)
			f.byOrigin[origin] = sig
		}
		if sig != nil && sig.matches(e) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// FilterSoft404 单目标过滤（流式模式用）。
func FilterSoft404(ctx context.Context, target string, entries []SprayEntry, client *http.Client) []SprayEntry {
	origin := originOf(target)
	if origin == "" || len(entries) == 0 {
		return entries
	}
	if client == nil {
		client = &http.Client{
			Timeout: 8 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	sig := buildSoft404Signature(ctx, origin, client)
	if sig == nil {
		return entries
	}
	out := make([]SprayEntry, 0, len(entries))
	for _, e := range entries {
		if sig.matches(e) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// buildSoft404Signature 探测随机路径；签名一致才返回基线。
func buildSoft404Signature(ctx context.Context, origin string, client *http.Client) *soft404Signature {
	const probes = 3
	sigs := make([]soft404Signature, 0, probes)
	for i := 0; i < probes; i++ {
		u := fmt.Sprintf("%s/zre-soft404-%d-%d", origin, time.Now().UnixNano(), i)
		sig, ok := probeSoft404(ctx, u, client)
		if ok {
			sigs = append(sigs, sig)
		}
	}
	if len(sigs) < 2 {
		return nil
	}
	base := sigs[0]
	for _, s := range sigs[1:] {
		if s.status != base.status || s.title != base.title || s.contentType != base.contentType {
			return nil
		}
		if !lengthSimilar(s.bodyLen, base.bodyLen) {
			return nil
		}
	}
	return &base
}

func probeSoft404(ctx context.Context, rawURL string, client *http.Client) (soft404Signature, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return soft404Signature{}, false
	}
	req.Header.Set("User-Agent", useragent.Pick())
	resp, err := client.Do(req)
	if err != nil {
		return soft404Signature{}, false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	// 只在「看起来成功」的状态上建立软 404 基线
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return soft404Signature{}, false
	}
	title := ""
	if m := soft404TitleRE.FindStringSubmatch(string(body)); len(m) == 2 {
		title = normalizeSoftTitle(m[1])
	}
	ct := resp.Header.Get("Content-Type")
	if idx := strings.Index(ct, ";"); idx >= 0 {
		ct = ct[:idx]
	}
	return soft404Signature{
		status:      resp.StatusCode,
		title:       title,
		contentType: strings.ToLower(strings.TrimSpace(ct)),
		bodyLen:     int64(len(body)),
	}, true
}

func (s *soft404Signature) matches(e SprayEntry) bool {
	if s == nil {
		return false
	}
	if e.StatusCode != s.status {
		return false
	}
	if normalizeSoftTitle(e.Title) != s.title {
		return false
	}
	if s.contentType != "" && e.ContentType != "" {
		ect := strings.ToLower(e.ContentType)
		if idx := strings.Index(ect, ";"); idx >= 0 {
			ect = ect[:idx]
		}
		if strings.TrimSpace(ect) != s.contentType {
			return false
		}
	}
	return lengthSimilar(e.BodyLength, s.bodyLen)
}

func lengthSimilar(a, b int64) bool {
	if a == b {
		return true
	}
	diff := a - b
	if diff < 0 {
		diff = -diff
	}
	tolerance := b / 10
	if tolerance < 64 {
		tolerance = 64
	}
	return diff <= tolerance
}

func normalizeSoftTitle(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.Join(strings.Fields(s), " ")
}

func originOf(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func firstNonEmptyString(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
