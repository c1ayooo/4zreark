// Package subdomain 被动子域枚举：证书透明日志（crt.sh）+ 公开被动 DNS
// （HackerTarget / AlienVault OTX / RapidDNS）+ 可选 SecurityTrails API。
// 对应 srcradar 的 subfinder 被动面，纯 Go 实现，只做信息收集类的公开数据查询。
package subdomain

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/internal/outbound"
)

// Hit 单条被动发现结果。
type Hit struct {
	Name   string `json:"name"`
	Source string `json:"source"`
}

// Options 枚举开关与凭据。
type Options struct {
	// Client 可选注入 HTTP 客户端（出站代理等）；nil 时用内置默认。
	Client             *http.Client
	EnableCT           bool   // crt.sh / CertSpotter 证书透明（免 key）
	EnablePassiveDNS   bool   // HackerTarget / AlienVault OTX / RapidDNS（免 key）
	EnableCNPassiveDNS bool   // 国内被动源：千讯 / ip138 / chinaz Alexa（免 key）
	SecurityTrailsKey  string // 可选；非空时启用 SecurityTrails 子域 API
	Timeout            time.Duration
	Limit              int // 单源结果上限（防 API 失控），0 = 不限
}

// SourceEnabled 返回至少启用了源。
func (o Options) SourceEnabled() bool {
	return o.EnableCT || o.EnablePassiveDNS || o.EnableCNPassiveDNS || strings.TrimSpace(o.SecurityTrailsKey) != ""
}

// Result 聚合去重后的发现结果。
type Result struct {
	Hits   []Hit             `json:"hits"`
	PerSrc map[string]int    `json:"per_source"`
	Errors map[string]string `json:"errors,omitempty"`
}

// Enumerate 并发查询全部启用源，聚合去重。单源失败不影响其他源。
func Enumerate(ctx context.Context, domain string, opts Options) (*Result, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" || !strings.Contains(domain, ".") {
		return nil, fmt.Errorf("主域无效: %q", domain)
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 45 * time.Second
	}
	client := opts.Client
	if client == nil {
		// 被动收集源走代理设置页的 recon 配置（每次枚举时取，热生效）。
		client = outbound.HTTPClient("recon", opts.Timeout)
	}

	type srcResult struct {
		name string
		hits []Hit
		err  error
	}
	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		results []srcResult
	)
	run := func(name string, fn func() ([]Hit, error)) {
		defer wg.Done()
		hits, err := fn()
		mu.Lock()
		defer mu.Unlock()
		results = append(results, srcResult{name: name, hits: hits, err: err})
	}

	if opts.EnableCT {
		wg.Add(1)
		go run("ct_logs", func() ([]Hit, error) { return queryCrtSh(ctx, client, domain, opts.Limit) })
		wg.Add(1)
		go run("certspotter", func() ([]Hit, error) { return queryCertSpotter(ctx, client, domain, opts.Limit) })
	}
	if opts.EnablePassiveDNS {
		wg.Add(1)
		go run("passive_dns", func() ([]Hit, error) { return queryHackerTarget(ctx, client, domain, opts.Limit) })
		wg.Add(1)
		go run("alienvault_otx", func() ([]Hit, error) { return queryAlienVaultOTX(ctx, client, domain, opts.Limit) })
		wg.Add(1)
		go run("rapiddns", func() ([]Hit, error) { return queryRapidDNS(ctx, client, domain, opts.Limit) })
	}
	if opts.EnableCNPassiveDNS {
		wg.Add(1)
		go run("qianxun", func() ([]Hit, error) { return queryQianxun(ctx, client, domain, opts.Limit) })
		wg.Add(1)
		go run("ip138", func() ([]Hit, error) { return queryIP138(ctx, client, domain, opts.Limit) })
		wg.Add(1)
		go run("chinaz_alexa", func() ([]Hit, error) { return queryChinazAlexa(ctx, client, domain, opts.Limit) })
	}
	if key := strings.TrimSpace(opts.SecurityTrailsKey); key != "" {
		wg.Add(1)
		go run("securitytrails", func() ([]Hit, error) { return querySecurityTrails(ctx, client, domain, key, opts.Limit) })
	}
	wg.Wait()

	out := &Result{PerSrc: map[string]int{}, Errors: map[string]string{}}
	seen := map[string]bool{}
	for _, r := range results {
		if r.err != nil {
			out.Errors[r.name] = r.err.Error()
			continue
		}
		count := 0
		for _, h := range r.hits {
			name := normalizeName(h.Name, domain)
			if name == "" || seen[name] {
				continue
			}
			seen[name] = true
			out.Hits = append(out.Hits, Hit{Name: name, Source: r.name})
			count++
			if opts.Limit > 0 && count >= opts.Limit {
				break
			}
		}
		out.PerSrc[r.name] = count
	}
	return out, nil
}

// normalizeName 清洗为合法子域名；不属于该主域（含通配符条目）的丢弃。
func normalizeName(raw, domain string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	raw = strings.TrimSuffix(raw, ".")
	if raw == "" {
		return ""
	}
	// crt.sh 常返回多行/通配条目
	raw = strings.ReplaceAll(raw, "\n", " ")
	for _, part := range strings.Fields(raw) {
		part = strings.TrimPrefix(strings.TrimSpace(part), "*.")
		part = strings.TrimSuffix(part, ".")
		if part == "" {
			continue
		}
		if part == domain || strings.HasSuffix(part, "."+domain) {
			return part
		}
	}
	return ""
}

func queryCrtSh(ctx context.Context, client *http.Client, domain string, limit int) ([]Hit, error) {
	// %25 = SQL 通配 %，拉全部子域条目
	u := "https://crt.sh/?q=%25." + url.PathEscape(domain) + "&output=json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crt.sh: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("crt.sh: 限流(429)")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh: HTTP %d", resp.StatusCode)
	}
	// crt.sh 偶发返回非法 JSON/空体，按解析失败处理而不是中断
	body, err := io.ReadAll(io.LimitReader(resp.Body, 20<<20))
	if err != nil {
		return nil, fmt.Errorf("crt.sh: %w", err)
	}
	var entries []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("crt.sh: 响应解析失败")
	}
	hits := make([]Hit, 0, len(entries))
	for _, e := range entries {
		name := normalizeName(e.NameValue, domain)
		if name == "" {
			continue
		}
		hits = append(hits, Hit{Name: name})
		if limit > 0 && len(hits) >= limit*2 {
			break
		}
	}
	return hits, nil
}

func queryHackerTarget(ctx context.Context, client *http.Client, domain string, limit int) ([]Hit, error) {
	u := "https://api.hackertarget.com/hostsearch/?q=" + url.QueryEscape(domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("hackertarget: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("hackertarget: %w", err)
	}
	text := string(body)
	// 免费额度耗尽时返回错误文案而非列表
	if strings.Contains(text, "API count exceeded") || strings.Contains(strings.ToLower(text), "error") && !strings.Contains(text, ",") {
		return nil, fmt.Errorf("hackertarget: %s", strings.TrimSpace(text))
	}
	hits := []Hit{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, ",") {
			continue
		}
		name := normalizeName(strings.SplitN(line, ",", 2)[0], domain)
		if name == "" {
			continue
		}
		hits = append(hits, Hit{Name: name})
		if limit > 0 && len(hits) >= limit*2 {
			break
		}
	}
	return hits, nil
}

func querySecurityTrails(ctx context.Context, client *http.Client, domain, apiKey string, limit int) ([]Hit, error) {
	u := "https://api.securitytrails.com/v1/domain/" + url.PathEscape(domain) + "/subdomains"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("APIKEY", apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("securitytrails: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("securitytrails: HTTP %d", resp.StatusCode)
	}
	var payload struct {
		Subdomains []string `json:"subdomains"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&payload); err != nil {
		return nil, fmt.Errorf("securitytrails: 响应解析失败")
	}
	hits := make([]Hit, 0, len(payload.Subdomains))
	for _, sub := range payload.Subdomains {
		name := normalizeName(sub+"."+domain, domain)
		if name == "" {
			continue
		}
		hits = append(hits, Hit{Name: name})
		if limit > 0 && len(hits) >= limit*2 {
			break
		}
	}
	return hits, nil
}

// queryAlienVaultOTX AlienVault OTX 被动 DNS（免 key，公开数据）。
func queryAlienVaultOTX(ctx context.Context, client *http.Client, domain string, limit int) ([]Hit, error) {
	u := "https://otx.alienvault.com/api/v1/indicators/domain/" + url.PathEscape(domain) + "/passive_dns"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("alienvault_otx: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("alienvault_otx: 限流(429)")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("alienvault_otx: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 20<<20))
	if err != nil {
		return nil, fmt.Errorf("alienvault_otx: %w", err)
	}
	return parseOtxResponse(body, domain, limit)
}

// parseOtxResponse 解析 OTX passive_dns 响应（纯函数，供离线单测）。
func parseOtxResponse(body []byte, domain string, limit int) ([]Hit, error) {
	var payload struct {
		PassiveDNS []struct {
			Hostname string `json:"hostname"`
		} `json:"passive_dns"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("alienvault_otx: 响应解析失败")
	}
	hits := make([]Hit, 0, len(payload.PassiveDNS))
	for _, rec := range payload.PassiveDNS {
		name := normalizeName(rec.Hostname, domain)
		if name == "" {
			continue
		}
		hits = append(hits, Hit{Name: name})
		if limit > 0 && len(hits) >= limit*2 {
			break
		}
	}
	return hits, nil
}

// queryRapidDNS RapidDNS 被动 DNS 聚合（免 key）。HTML 表格解析，定位为加分源：
// 上游改版/限流只影响本源，进 Result.Errors 不拖累整体。
func queryRapidDNS(ctx context.Context, client *http.Client, domain string, limit int) ([]Hit, error) {
	u := "https://rapiddns.io/subdomain/" + url.PathEscape(domain) + "?full=1"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("rapiddns: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("rapiddns: 限流(429)")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rapiddns: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 20<<20))
	if err != nil {
		return nil, fmt.Errorf("rapiddns: %w", err)
	}
	return parseRapidDNSBody(body, domain, limit)
}

// parseRapidDNSBody 从 HTML 里提取本域子域（纯函数，供离线单测）。
func parseRapidDNSBody(body []byte, domain string, limit int) ([]Hit, error) {
	return parseDomainRegex(string(body), domain, limit)
}

// parseDomainRegex 文本/HTML 子域提取的共用实现（RapidDNS / 国内源 / 页面回灌
// 共用）：匹配「若干 label + 主域」形态，normalizeName 再做后缀边界过滤。
func parseDomainRegex(text, domain string, limit int) ([]Hit, error) {
	re, err := regexp.Compile(`(?i)(?:[a-z0-9_-]+\.)+` + regexp.QuoteMeta(domain))
	if err != nil {
		return nil, err
	}
	seenInBody := map[string]bool{}
	hits := []Hit{}
	for _, m := range re.FindAllString(text, -1) {
		if seenInBody[m] {
			continue
		}
		seenInBody[m] = true
		name := normalizeName(m, domain)
		if name == "" {
			continue
		}
		hits = append(hits, Hit{Name: name})
		if limit > 0 && len(hits) >= limit*2 {
			break
		}
	}
	return hits, nil
}
