// Package ctlog 证书透明日志查询（crt.sh）：被动发现子域——只查公开 CT 库，
// 不接触目标主机，符合巡航「纯被动源」原则。
//
// crt.sh 偶发慢/限流：单次查询带超时与 429 退避，失败由调用方记 warning
// 跳过（不重试轰炸）。
package ctlog

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/internal/useragent"
)

type entry struct {
	NameValue string `json:"name_value"`
	Issuer    string `json:"issuer_name"`
	NotBefore string `json:"not_before"`
}

// QuerySubdomains 查询某域名在 CT 日志里出现过的证书 SAN/CN，
// 返回去重后的子域列表（含泛匹配剥离，如 *.example.com 展开丢弃）。
func QuerySubdomains(ctx context.Context, domain string) ([]string, error) {
	domain = strings.TrimSpace(strings.ToLower(strings.TrimPrefix(domain, "*.")))
	if domain == "" {
		return nil, fmt.Errorf("域名为空")
	}
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			// 429/超时后等 5s 再试一次，不更多
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(5 * time.Second):
			}
		}
		names, err := fetchOnce(ctx, url, domain)
		if err == nil {
			return names, nil
		}
		lastErr = err
		if !strings.Contains(err.Error(), "429") {
			break
		}
	}
	return nil, lastErr
}

func fetchOnce(ctx context.Context, url, domain string) ([]string, error) {
	cctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", useragent.Pick())
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("crt.sh 429 限流")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh 返回 %d", resp.StatusCode)
	}

	var entries []entry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("解析 crt.sh 响应失败: %w", err)
	}

	seen := make(map[string]bool)
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		for _, raw := range strings.Split(e.NameValue, "\n") {
			n := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(raw, "*.")))
			if n == "" || seen[n] {
				continue
			}
			// 只留查询域及其子域（crt.sh 会带出同证书的其它域名）。
			// 归属判断必须与查询参数 domain 比对——此前拿候选名自己的
			// 后两段做后缀判断是恒真式，无关域名全部混入候选。
			if n == domain || strings.HasSuffix(n, "."+domain) {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	return out, nil
}
