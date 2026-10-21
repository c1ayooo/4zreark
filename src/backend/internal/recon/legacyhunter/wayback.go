package legacyhunter

// Wayback CDX API 客户端：拉取目标域的历史快照 URL 清单（遗留系统猎人的数据源）。
// web.archive.org/cdx/search/cdx 无需 API key，纯 GET + JSON 解析。

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/c1ayooo/4zreark/internal/useragent"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// CDXOptions 查询参数。
type CDXOptions struct {
	// Limit 返回条目上限（0 = 默认 500）。
	Limit int
	// Timeout 单次请求超时（0 = 30s）。
	Timeout time.Duration
	// Client 注入的 HTTP 客户端（nil = http.DefaultClient）。
	Client *http.Client
}

// CDXEntry 一条历史快照。
type CDXEntry struct {
	Timestamp  string `json:"timestamp"`
	Original   string `json:"original"`
	StatusCode string `json:"statuscode"`
}

// cdxEndpoint CDX API 端点（常量便于测试替换）。
var cdxEndpoint = "https://web.archive.org/cdx/search/cdx"

// QueryCDX 拉取 domain 全部子路径的历史快照（只收历史 statuscode 200 的快照，
// 按 URL 去重——遗留端点是按路径判定的，重复快照无意义）。
func QueryCDX(ctx context.Context, domain string, opts CDXOptions) ([]CDXEntry, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimSuffix(domain, "/")
	if domain == "" {
		return nil, fmt.Errorf("legacyhunter: 空域名")
	}
	limit := opts.Limit
	if limit <= 0 {
		limit = 500
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	client := opts.Client
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	q := url.Values{}
	q.Set("url", domain+"/*")
	q.Set("output", "json")
	q.Set("fl", "timestamp,original,statuscode")
	q.Set("filter", "statuscode:200")
	q.Set("collapse", "urlkey")
	q.Set("limit", fmt.Sprintf("%d", limit))
	endpoint := cdxEndpoint + "?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", useragent.Pick())
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("legacyhunter: CDX 请求失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("legacyhunter: CDX HTTP %d", resp.StatusCode)
	}
	// 响应限长守卫（默认 500 条 × 200 字节远小于此；防恶意响应撑爆内存）。
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	return parseCDX(body)
}

// parseCDX 解析 CDX JSON 响应：首行为字段名，其余为数据行。
// 空响应（无快照）返回空列表而非错误。
func parseCDX(body []byte) ([]CDXEntry, error) {
	if len(strings.TrimSpace(string(body))) == 0 {
		return nil, nil
	}
	var raw [][]string
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("legacyhunter: CDX 响应解析失败: %w", err)
	}
	if len(raw) < 2 {
		return nil, nil // 无快照行
	}
	// 首行字段名 → 列索引
	cols := map[string]int{}
	for i, h := range raw[0] {
		cols[h] = i
	}
	ts, okTS := cols["timestamp"]
	orig, okOrig := cols["original"]
	status, okStatus := cols["statuscode"]
	if !okTS || !okOrig {
		return nil, fmt.Errorf("legacyhunter: CDX 响应缺字段（timestamp/original）")
	}
	out := make([]CDXEntry, 0, len(raw)-1)
	for _, row := range raw[1:] {
		if ts >= len(row) || orig >= len(row) {
			continue
		}
		e := CDXEntry{Timestamp: row[ts], Original: row[orig]}
		if okStatus && status < len(row) {
			e.StatusCode = row[status]
		}
		out = append(out, e)
	}
	return out, nil
}
