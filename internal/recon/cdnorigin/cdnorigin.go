// Package cdnorigin CDN 真实 IP（源站）发现——对标 Desinter_scan cdn_ip collector
// （§三 #5，此前仅 cdnmatch 识别 CDN 而缺「反查真实 IP」三件套）。
//
// 三件套：① 证书 SAN 域名（crt.sh CT 日志，免 key）批量 A 解析；② DNS 历史
// （SecurityTrails，需 key）；③ 对每个候选 IP 用 cdnmatch.Classify 判定——
// 命中 CDN/WAF/云段（EdgeType 非空）的是边缘节点，未命中（local）的才是可能源站。
//
// 全部走第三方数据源 + DNS 解析，对目标零主动连接；源站候选仅列报，由调用方
// 决定是否授权后探测（与 link_hosts_unauthorized 语义一致）。
package cdnorigin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/internal/recon/cdnmatch"
	"github.com/c1ayooo/4zreark/internal/recon/dnsres"
)

// Origin 一个源站 IP 候选（含判定与证据来源）。
type Origin struct {
	IP      string   `json:"ip"`
	IsCDN   bool     `json:"is_cdn"`  // true = 仍被 CDN 覆盖（边缘节点），false = 源站候选
	Sources []string `json:"sources"` // 证据：san:<主机> / history:<ip>@<首见>
}

// Options 运行参数。
type Options struct {
	// SecurityTrailsKey 非空时启用 DNS 历史数据源（APIKEY 头）。
	SecurityTrailsKey string
	HTTPClient        *http.Client
	// Resolver 解析池（nil = 内部构造默认池）。
	Resolver *dnsres.Pool
	// Lookup 每个 SAN 主机的 A 记录解析（nil = 用 Resolver 池；测试注入免真实 DNS）。
	Lookup  func(ctx context.Context, host string) ([]string, error)
	Timeout time.Duration
}

// 外部数据源端点（测试可覆盖注入 mock，避免硬编码端点不可测）。
var (
	crtShEndpoint          = "https://crt.sh"
	securityTrailsEndpoint = "https://api.securitytrails.com"
)

// crtShEntry crt.sh JSON 单行（只取 SAN 名）。
type crtShEntry struct {
	NameValue string `json:"name_value"`
}

// Find 执行 CDN 真实 IP 发现：返回目标域证书 SAN 主机解析出的 IP + DNS 历史 IP，
// 全部经 cdnmatch 判定并去重（含 CDN 标记，源站候选 = IsCDN false）。
func Find(ctx context.Context, domain string, opts Options) ([]Origin, error) {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	domain = strings.TrimPrefix(strings.TrimPrefix(domain, "https://"), "http://")
	if domain == "" {
		return nil, fmt.Errorf("cdnorigin: 空域名")
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 25 * time.Second
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	pool := opts.Resolver
	if pool == nil {
		pool = dnsres.NewPool(nil, 16, 5*time.Second, 2)
	}

	// ① 证书 SAN 域名（crt.sh）。
	sans := queryCrtSANs(ctx, client, domain, timeout)
	// ② DNS 历史（SecurityTrails，有 key 时）。
	historyIPs := queryDNSHistory(ctx, client, domain, opts.SecurityTrailsKey, timeout)

	// ③ 解析 + 判定：SAN 主机解析出的 IP 与历史 IP 统一过 cdnmatch。
	var (
		mu      sync.Mutex
		origins = map[string]*Origin{} // ip → Origin
	)
	addIP := func(ip, source string) {
		if ip == "" {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		o, ok := origins[ip]
		if !ok {
			o = &Origin{IP: ip, IsCDN: cdnmatch.Classify("", []string{ip}).EdgeType != ""}
			origins[ip] = o
		}
		o.Sources = appendUnique(o.Sources, source)
	}
	// SAN 主机并发解析（有界并发；用 Lookup 注入点解耦真实 DNS，测试可 mock）。
	resolver := opts.Lookup
	if resolver == nil {
		resolver = func(ctx context.Context, host string) ([]string, error) {
			ans, err := pool.Resolve(ctx, host)
			if err != nil {
				return nil, err
			}
			if ans == nil || ans.NXDomain {
				return nil, nil
			}
			return ans.IPs, nil
		}
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)
	for _, san := range sans {
		san := san
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			ips, err := resolver(ctx, san)
			if err != nil || len(ips) == 0 {
				return
			}
			for _, ip := range ips {
				addIP(ip, "san:"+san)
			}
		}()
	}
	wg.Wait()
	for _, ip := range historyIPs {
		addIP(ip, "history")
	}
	// 源站候选优先（非 CDN 在前），组内按 IP 字典序。
	out := make([]Origin, 0, len(origins))
	for _, o := range origins {
		out = append(out, *o)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IsCDN != out[j].IsCDN {
			return !out[i].IsCDN // 非 CDN（源站候选）在前
		}
		return out[i].IP < out[j].IP
	})
	return out, nil
}

// queryCrtSANs 拉目标域证书 SAN 域名（含通配剥离、去重、排除主域自身）。
func queryCrtSANs(ctx context.Context, client *http.Client, domain string, timeout time.Duration) []string {
	u := crtShEndpoint + "/?q=%25." + url.PathEscape(domain) + "&output=json"
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, u, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; reconkit-cdnorigin/1.0)")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil
	}
	var entries []crtShEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, e := range entries {
		for _, raw := range strings.Split(e.NameValue, "\n") {
			name := strings.ToLower(strings.TrimSpace(raw))
			name = strings.TrimSuffix(name, ".")
			name = strings.TrimPrefix(name, "*.")
			if name == "" || name == domain || !strings.HasSuffix(name, "."+domain) {
				continue
			}
			if !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	return out
}

// queryDNSHistory 拉 SecurityTrails DNS 历史 A 记录 IP（无 key 时返回空）。
func queryDNSHistory(ctx context.Context, client *http.Client, domain, apiKey string, timeout time.Duration) []string {
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		return nil
	}
	u := securityTrailsEndpoint + "/v1/history/" + url.PathEscape(domain) + "/dns/a"
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, u, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("APIKEY", apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; reconkit-cdnorigin/1.0)")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil
	}
	var payload struct {
		Data struct {
			Records []struct {
				Values []struct {
					IP        string `json:"ip"`
					FirstSeen string `json:"first_seen"`
				} `json:"values"`
			} `json:"records"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, rec := range payload.Data.Records {
		for _, v := range rec.Values {
			if ip := strings.TrimSpace(v.IP); ip != "" && !seen[ip] {
				seen[ip] = true
				out = append(out, ip)
			}
		}
	}
	return out
}

// appendUnique 追加去重。
func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}
