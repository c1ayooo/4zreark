// extra_sources.go 被动子域源的补强组：国内 DNS 数据集（千讯/ip138/chinaz
// Alexa 子域排名，免 key，HTML 解析——OneForAll 国内源模块组的对应物）+
// CertSpotter 证书透明（crt.sh 的免 key 冗余源，crt.sh 超时是常态）。
// 全部为加分源语义：上游改版/反爬只影响本源，失败进 Result.Errors 不拖累整体。
package subdomain

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// cnSourceUA 国内源对 UA/Referer 更敏感，统一带浏览器头。
func cnSourceUA(req *http.Request, referer string) {
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	if referer != "" {
		req.Header.Set("Referer", referer)
	}
}

// queryQianxun 千讯 dnsdb.io 子域聚合页（服务端渲染表格，正则提取）。
func queryQianxun(ctx context.Context, client *http.Client, domain string, limit int) ([]Hit, error) {
	return fetchHTMLAndExtract(ctx, client, "https://www.dnsdb.io/"+url.PathEscape(domain)+"/dnsdb/", domain, limit, "qianxun")
}

// queryIP138 site.ip138.com 域名解析记录页（历史子域表格）。
func queryIP138(ctx context.Context, client *http.Client, domain string, limit int) ([]Hit, error) {
	return fetchHTMLAndExtract(ctx, client, "https://site.ip138.com/"+url.PathEscape(domain)+"/domain.htm", domain, limit, "ip138")
}

// queryChinazAlexa chinaz Alexa 排名页（子域排名表格，服务端渲染）。
func queryChinazAlexa(ctx context.Context, client *http.Client, domain string, limit int) ([]Hit, error) {
	return fetchHTMLAndExtract(ctx, client, "https://alexa.chinaz.com/"+url.PathEscape(domain), domain, limit, "chinaz")
}

// fetchHTMLAndExtract 国内 HTML 数据集源的共用骨架：拉页 → 正则提取本域子域。
// 与 RapidDNS 同解析策略（parseRapidDNSBody），反爬页面返回非 200 时按本源失败处理。
func fetchHTMLAndExtract(ctx context.Context, client *http.Client, u, domain string, limit int, srcName string) ([]Hit, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	cnSourceUA(req, "")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", srcName, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("%s: 限流(429)", srcName)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", srcName, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", srcName, err)
	}
	return extractHitsFromHTML(string(body), domain, limit)
}

// extractHitsFromHTML 从 HTML 文本提取本域子域（纯函数，供离线单测；
// 与 parseRapidDNSBody 同语义，独立一份避免国内源测试绑到 rapiddns 用例上）。
func extractHitsFromHTML(body, domain string, limit int) ([]Hit, error) {
	return parseDomainRegex(body, domain, limit)
}

// queryCertSpotter CertSpotter 证书透明（免 key 有速率限制；挂 EnableCT 语义下）。
func queryCertSpotter(ctx context.Context, client *http.Client, domain string, limit int) ([]Hit, error) {
	u := "https://api.certspotter.com/v1/issuances?domain=" + url.QueryEscape(domain) + "&include_subdomains=true&expand=dns_names"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("certspotter: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("certspotter: 限流(429)")
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("certspotter: 域名无证书记录")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("certspotter: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 20<<20))
	if err != nil {
		return nil, fmt.Errorf("certspotter: %w", err)
	}
	return parseCertSpotterBody(body, domain, limit)
}

// parseCertSpotterBody 解析 issuances 列表（纯函数，供离线单测）。
func parseCertSpotterBody(body []byte, domain string, limit int) ([]Hit, error) {
	var entries []struct {
		DNSNames []string `json:"dns_names"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("certspotter: 响应解析失败")
	}
	hits := make([]Hit, 0, len(entries)*2)
	for _, e := range entries {
		for _, n := range e.DNSNames {
			name := normalizeName(strings.TrimSpace(n), domain)
			if name == "" {
				continue
			}
			hits = append(hits, Hit{Name: name})
			if limit > 0 && len(hits) >= limit*2 {
				return hits, nil
			}
		}
	}
	return hits, nil
}
