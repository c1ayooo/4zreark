// Package oob 带外验证与被动补充:DNSLog 客户端(自 4zreco 直接搬,dnslog.cn
// 协议或自建兼容服务)、VirusTotal 被动子域(同搬)、AI 协议端点探测(按 4zreco
// aiprobe 的探测面精简实现——LLM/OpenAI 兼容端点、MCP、A2A 的 well-known 与
// 常见路径,版本/深度以 4zreco 为准的完整移植留待需要时补充)。
package oob

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DnslogDefaultBase 默认服务(dnslog.cn,可自建覆盖)。
const DnslogDefaultBase = "http://dnslog.cn"

func dnslogCookieFile() string {
	return filepath.Join(os.TempDir(), "4zrec_dnslog_cookie.txt")
}

// DnslogGetDomain 拿临时域名;会话 cookie 持久化(记录查询必须带同 cookie)。
func DnslogGetDomain(ctx context.Context, base string) (string, error) {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if base == "" {
		base = DnslogDefaultBase
	}
	client := &http.Client{Timeout: 12 * time.Second}
	resp, err := client.Get(base + "/getdomain.php")
	if err != nil {
		return "", fmt.Errorf("请求失败: %v(dnslog.cn 不稳定时稍后重试或换自建服务)", err)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	cookie := ""
	for _, c := range resp.Cookies() {
		if c.Name != "" {
			if cookie != "" {
				cookie += "; "
			}
			cookie += c.Name + "=" + c.Value
		}
	}
	if cookie != "" {
		_ = os.WriteFile(dnslogCookieFile(), []byte(cookie), 0o600)
	}
	return strings.TrimSpace(string(body)), nil
}

// DnslogGetRecords 查记录;waitSec>0 时先等待(给目标触发 DNS 查询的时间)。
// 返回原始记录行(JSON 数组或行文本均按 4zreco 解析口径拆条)。
func DnslogGetRecords(ctx context.Context, base, domain string, waitSec int) ([]string, error) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return nil, fmt.Errorf("get_records 需要 domain(get_domain 拿到的临时域名)")
	}
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if base == "" {
		base = DnslogDefaultBase
	}
	if waitSec > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(waitSec) * time.Second):
		}
	}
	client := &http.Client{Timeout: 12 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/getrecords.php?t="+url.QueryEscape(domain), nil)
	if raw, err := os.ReadFile(dnslogCookieFile()); err == nil && len(raw) > 0 {
		req.Header.Set("Cookie", strings.TrimSpace(string(raw)))
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求失败: %v", err)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return parseDnslogRecords(string(body)), nil
}

// parseDnslogRecords dnslog.cn 的两种输出形态:JSON 数组或 % 结尾的行文本。
func parseDnslogRecords(raw string) []string {
	raw = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(raw), "%"))
	if strings.HasPrefix(raw, "[") {
		var arr []string
		if json.Unmarshal([]byte(raw), &arr) == nil {
			var out []string
			for _, s := range arr {
				if s = strings.TrimSpace(s); s != "" {
					out = append(out, s)
				}
			}
			return out
		}
	}
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}

// VTSubdomains VirusTotal 被动子域(不触达目标);分页限速 0.5s 尊重免费额度。
// includeIPs 时对前 40 个子域反查解析记录(额外请求,注意免费 Key 4 次/分钟)。
func VTSubdomains(ctx context.Context, apiKey, domain string, limit int, includeIPs bool, client *http.Client, baseURL string) ([]string, map[string][]string, error) {
	if baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/"); baseURL == "" {
		baseURL = "https://www.virustotal.com/api/v3"
	}
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return nil, nil, fmt.Errorf("domain 必填")
	}
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		return nil, nil, fmt.Errorf("未配置 VirusTotal API Key(VT_API_KEY 环境变量或系统设置)")
	}
	if limit <= 0 {
		limit = 40
	}
	if limit > 1000 {
		limit = 1000
	}
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	var (
		subdomains []string
		nextURL    string
		page       int
	)
	for len(subdomains) < limit {
		u := nextURL
		if u == "" {
			u = fmt.Sprintf("%s/domains/%s/subdomains?limit=40", baseURL, url.PathEscape(domain))
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, nil, err
		}
		req.Header.Set("x-apikey", apiKey)
		resp, err := client.Do(req)
		if err != nil {
			return nil, nil, fmt.Errorf("请求失败: %v(检查网络或 Key 有效性)", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, nil, fmt.Errorf("VirusTotal API %d: %s", resp.StatusCode, truncate(string(body), 300))
		}
		var data struct {
			Data []struct {
				ID string `json:"id"`
			} `json:"data"`
			Links struct {
				Next string `json:"next"`
			} `json:"links"`
		}
		if err := json.Unmarshal(body, &data); err != nil {
			return nil, nil, fmt.Errorf("解析响应失败: %v", err)
		}
		for _, item := range data.Data {
			if id := strings.TrimSpace(item.ID); id != "" {
				subdomains = append(subdomains, id)
			}
		}
		nextURL = data.Links.Next
		page++
		if nextURL == "" || page >= 40 {
			break
		}
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	if len(subdomains) > limit {
		subdomains = subdomains[:limit]
	}
	ips := map[string][]string{}
	if includeIPs && len(subdomains) > 0 {
		capN := len(subdomains)
		if capN > 40 {
			capN = 40
		}
		for _, sub := range subdomains[:capN] {
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
				fmt.Sprintf("%s/domains/%s/resolutions?limit=10", baseURL, url.PathEscape(sub)), nil)
			req.Header.Set("x-apikey", apiKey)
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			if resp.StatusCode != 200 {
				continue
			}
			var res struct {
				Data []struct {
					Attributes struct {
						IP string `json:"ip_address"`
					} `json:"attributes"`
				} `json:"data"`
			}
			if json.Unmarshal(body, &res) == nil {
				for _, d := range res.Data {
					if d.Attributes.IP != "" {
						ips[sub] = append(ips[sub], d.Attributes.IP)
					}
				}
			}
			select {
			case <-ctx.Done():
				return subdomains, ips, nil
			case <-time.After(500 * time.Millisecond):
			}
		}
	}
	return subdomains, ips, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// ParseRecordsForTest 暴露解析函数(测试用;语义同 DnslogGetRecords 的拆条)。
func ParseRecordsForTest(raw string) []string { return parseDnslogRecords(raw) }
