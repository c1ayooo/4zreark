// artifacts.go 目标自身工件里的子域提取（OneForAll「常规检查」模块组的对应物）：
// robots.txt / sitemap.xml / crossdomain.xml / CSP 响应头 / HTTPS 证书 SAN。
// 与 Enumerate 的被动数据源不同——这组源直接请求目标域名本身，必须走带授权
// 范围重定向复验的探测客户端（pipeline 传 probeClient，不走 passiveClient）。
package subdomain

import (
	"context"
	"crypto/tls"
	"encoding/xml"
	"errors"
	"fmt"
	"github.com/c1ayooo/4zreark/internal/recon/directhttp"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// errArtifactNotFound 工件不存在（404 属常态：多数站没有 crossdomain/sitemap），
// 不进 Result.Errors，只计 PerSrc=0。
var errArtifactNotFound = errors.New("工件不存在")

// CollectFromArtifacts 从目标自身工件提取本域子域。single-source 失败进
// Result.Errors 不拖累整体（与 Enumerate 同语义）。
func CollectFromArtifacts(ctx context.Context, domain string, client *http.Client, limit int) *Result {
	if client == nil {
		client = directhttp.Client(&http.Client{Timeout: 15 * time.Second})
	}
	out := &Result{PerSrc: map[string]int{}, Errors: map[string]string{}}
	seen := map[string]bool{}
	add := func(src string, hits []Hit) {
		count := 0
		for _, h := range hits {
			name := normalizeName(h.Name, domain)
			if name == "" || seen[name] {
				continue
			}
			seen[name] = true
			out.Hits = append(out.Hits, Hit{Name: name, Source: src})
			count++
			if limit > 0 && count >= limit {
				break
			}
		}
		out.PerSrc[src] = count
	}
	// step 拉取一个工件源：失败记 Errors（404 属常态不记，网络错误记）。
	step := func(src string, fn func() ([]Hit, error)) {
		hits, err := fn()
		if err != nil {
			out.PerSrc[src] = 0
			if !errors.Is(err, errArtifactNotFound) {
				out.Errors[src] = err.Error()
			}
			return
		}
		add(src, hits)
	}

	// robots.txt：Disallow/Sitemap 行里的本域主机少见但零成本，主要吃 sitemap 行。
	step("robots_txt", func() ([]Hit, error) {
		body, err := fetchArtifact(ctx, client, "https://"+domain+"/robots.txt")
		if err != nil {
			return nil, err
		}
		return extractFromText(body, domain), nil
	})
	// sitemap.xml：国内政企站几乎必放，<loc> 全量 URL 提取主机。
	step("sitemap_xml", func() ([]Hit, error) {
		body, err := fetchArtifact(ctx, client, "https://"+domain+"/sitemap.xml")
		if err != nil {
			return nil, err
		}
		return parseSitemapURLs(body, domain), nil
	})
	// crossdomain.xml：<allow-access-from domain="*.sub.example.com"/>
	step("crossdomain_xml", func() ([]Hit, error) {
		body, err := fetchArtifact(ctx, client, "https://"+domain+"/crossdomain.xml")
		if err != nil {
			return nil, err
		}
		return extractFromText(body, domain), nil
	})
	// CSP：首页 Content-Security-Policy 头里的本域源（script-src/img-src 等）。
	step("csp_header", func() ([]Hit, error) {
		hdr, err := fetchHeader(ctx, client, "https://"+domain, "Content-Security-Policy")
		if err != nil {
			return nil, err
		}
		return extractFromText(hdr, domain), nil
	})
	// 证书 SAN：直连 :443 拿叶子证书 DNSNames（无需完整 TLS 探活）。
	step("cert_san", func() ([]Hit, error) { return fetchCertSANs(ctx, domain) })
	return out
}

// fetchArtifact 拉取工件原文（4MB 上限；非 200 按错误返回但不中断其他工件）。
func fetchArtifact(ctx context.Context, client *http.Client, u string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "", errArtifactNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// fetchHeader 只取单个响应头（CSP 用；同样受探测客户端的范围重定向复验约束）。
func fetchHeader(ctx context.Context, client *http.Client, u, header string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10)) // 只吃头，body 掐断
	return resp.Header.Get(header), nil
}

// fetchCertSANs 直连 443 提取叶子证书 SAN（自签容忍：只为读 DNSNames，不为校验）。
func fetchCertSANs(ctx context.Context, domain string) ([]Hit, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(&d, "tcp", domain+":443", &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("无对端证书")
	}
	hits := make([]Hit, 0, len(certs[0].DNSNames))
	for _, name := range certs[0].DNSNames {
		hits = append(hits, Hit{Name: name})
	}
	return hits, nil
}

// parseSitemapURLs 解析 sitemap.xml（含 sitemap index 的子 <sitemap><loc> 也按
// 主机提取——不做二级抓取，一轮防循环）。纯函数供离线单测。
func parseSitemapURLs(body string, domain string) []Hit {
	type urlset struct {
		URLs []struct {
			Loc string `xml:"loc"`
		} `xml:"url"`
	}
	type sitemapindex struct {
		Sitemaps []struct {
			Loc string `xml:"loc"`
		} `xml:"sitemap"`
	}
	var names []string
	var idx sitemapindex
	if err := xml.Unmarshal([]byte(body), &idx); err == nil && len(idx.Sitemaps) > 0 {
		for _, s := range idx.Sitemaps {
			names = append(names, s.Loc)
		}
	}
	var us urlset
	if err := xml.Unmarshal([]byte(body), &us); err == nil {
		for _, u := range us.URLs {
			names = append(names, u.Loc)
		}
	}
	// XML 里混了非法字符时退回正则兜底
	if len(names) == 0 {
		return extractFromText(body, domain)
	}
	return extractFromText(strings.Join(names, "\n"), domain)
}

// ExtractFromText 文本（工件/页面回灌）共用的本域子域提取器：
// 与被动源 HTML 解析共用 parseDomainRegex，normalizeName 做后缀边界过滤。
// 返回去重后的子域名列表。
func ExtractFromText(text, domain string) []string {
	hits, err := parseDomainRegex(text, domain, 0)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(hits))
	for _, h := range hits {
		out = append(out, h.Name)
	}
	return out
}

// extractFromText 工件解析的内部形态（保留 Hit 以便 add 记数）。
func extractFromText(text, domain string) []Hit {
	hits, err := parseDomainRegex(text, domain, 0)
	if err != nil {
		return nil
	}
	return hits
}
