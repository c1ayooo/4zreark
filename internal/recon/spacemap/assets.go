// assets.go 引擎响应行 → 归一化结果。移植自 4zreco info_collect_schedule_assets.go
// 的 assetsFromProviderRows 及行取值助手;差异仅在于输出类型:4zreco 归一化为
// database.Asset,这里输出本地 Result,入库映射由 server 装配层走 AssetStore
// (域名→subdomain、IP→ip、host+port+protocol/title→service)。
package spacemap

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Result 一行引擎查询结果的归一化形态(未入库的资产候选)。
type Result struct {
	Source   string // 引擎展示名(ProviderDisplayName)
	Query    string // 命中它的引擎查询语句
	Host     string // 首选主机形态(domain 优先,其次 ip)
	Domain   string
	IP       string
	Port     int
	Title    string
	Protocol string
	Server   string
	Country  string
	Province string
	City     string
}

// ResultsFromRows 把某引擎的响应行归一化为资产候选。
func ResultsFromRows(provider, query string, rows []map[string]interface{}) []*Result {
	provider = normalizeProvider(provider)
	source := ProviderDisplayName(provider)
	results := make([]*Result, 0, len(rows))
	for _, row := range rows {
		r := &Result{Source: source, Query: query}
		switch provider {
		case "zoomeye":
			r.IP = rowStringValue(row, "ip")
			r.Port = rowIntValue(row, "port")
			r.Domain = rowStringValue(row, "domain", "hostname")
			// ZoomEye 的 title/app 常以 list 形态返回（对标 AutoHunter 踩坑链）
			r.Title = rowJoinedValue(row, "title", "portinfo.title")
			r.Protocol = cleanAssetProtocol(rowStringValue(row, "service"))
			r.Server = rowJoinedValue(row, "app", "portinfo.app")
			r.Country = rowStringValue(row, "country")
			r.City = rowStringValue(row, "city")
		case "quake":
			r.IP = rowStringValue(row, "ip")
			r.Port = rowIntValue(row, "port")
			// host 回落链（AutoHunter 实测顺序）：service.http.host → hostname → domain
			r.Domain = rowStringValue(row, "service.http.host", "hostname", "domain")
			// title 回落：结构化字段缺失时从旧版 service.response 抠 <title>
			r.Title = rowStringValue(row, "service.http.title")
			if r.Title == "" {
				r.Title = htmlTitleFromBody(rowStringValue(row, "service.response"))
			}
			r.Protocol = cleanAssetProtocol(rowStringValue(row, "service.name"))
			r.Server = rowStringValue(row, "service.http.server")
			r.Country = rowStringValue(row, "location.country_cn", "country_cn")
			r.Province = rowStringValue(row, "location.province_cn", "province_cn")
			r.City = rowStringValue(row, "location.city_cn", "city_cn")
		case "shodan":
			r.IP = rowStringValue(row, "ip_str", "ip")
			r.Port = rowIntValue(row, "port")
			r.Domain = rowFirstOfList(row, "hostnames")
			if r.Domain == "" {
				r.Domain = rowFirstOfList(row, "domains")
			}
			r.Title = rowStringValue(row, "http.title")
			r.Protocol = cleanAssetProtocol(rowStringValue(row, "transport"))
			r.Server = rowStringValue(row, "product")
			r.Country = rowStringValue(row, "location.country_name", "location.country_code", "country")
			r.City = rowStringValue(row, "location.city")
		case "hunter":
			// 鹰图 openApi 行：url/ip/port/domain/web_title/protocol/company/number(ICP)。
			r.IP = rowStringValue(row, "ip")
			r.Port = rowIntValue(row, "port")
			r.Domain = rowStringValue(row, "domain")
			if r.Domain == "" {
				// 非 web 资产 domain 为空：从 url 提取主机
				if u := rowStringValue(row, "url"); u != "" {
					r.Domain = urlHostOrEmpty(u)
				}
			}
			r.Title = rowStringValue(row, "web_title")
			r.Protocol = cleanAssetProtocol(rowStringValue(row, "protocol"))
		default:
			r.Host = rowStringValue(row, "host")
			r.IP = rowStringValue(row, "ip")
			r.Port = rowIntValue(row, "port")
			r.Domain = rowStringValue(row, "domain")
			r.Title = rowStringValue(row, "title")
			r.Protocol = cleanAssetProtocol(rowStringValue(row, "protocol"))
			r.Server = rowStringValue(row, "server")
			r.Country = rowStringValue(row, "country")
			r.Province = rowStringValue(row, "province")
			r.City = rowStringValue(row, "city")
		}
		if r.Host == "" {
			if r.Domain != "" {
				r.Host = r.Domain
			} else if r.IP != "" {
				r.Host = r.IP
			}
		}
		if r.Host == "" && r.IP == "" && r.Domain == "" {
			continue
		}
		results = append(results, r)
	}
	return results
}

// SearchEngineAssets 面向 agent 工具的空间测绘查询:执行引擎查询并归一化。
// 返回候选(未入库)、引擎原始行(样本展示)与命中总数。
func (h *Client) SearchEngineAssets(ctx context.Context, engine, query string, size, page int) ([]*Result, []map[string]interface{}, int, error) {
	resp, err := h.SearchProviderCtx(ctx, engine, SearchRequest{Query: query, Size: size, Page: page})
	if err != nil {
		return nil, nil, 0, err
	}
	return ResultsFromRows(engine, resp.Query, resp.Results), resp.Results, resp.Total, nil
}

func rowStringValue(row map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		v := valueByPath(row, k)
		if v == nil {
			continue
		}
		switch t := v.(type) {
		case string:
			if s := strings.TrimSpace(t); s != "" {
				return s
			}
		case float64:
			return strconv.FormatFloat(t, 'f', -1, 64)
		default:
			if s := strings.TrimSpace(sprintfNoNil(v)); s != "" {
				return s
			}
		}
	}
	return ""
}

// sprintfNoNil fmt.Sprint(nil) 会得到 "<nil>",这里归为空串。
func sprintfNoNil(v interface{}) string {
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}

func rowIntValue(row map[string]interface{}, keys ...string) int {
	for _, k := range keys {
		v := valueByPath(row, k)
		if v == nil {
			continue
		}
		switch t := v.(type) {
		case float64:
			return int(t)
		case string:
			if n, err := strconv.Atoi(strings.TrimSpace(t)); err == nil {
				return n
			}
		}
	}
	return 0
}

func rowFirstOfList(row map[string]interface{}, key string) string {
	v := valueByPath(row, key)
	switch t := v.(type) {
	case []interface{}:
		for _, item := range t {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s)
			}
		}
	case string:
		parts := strings.Split(strings.Trim(t, ","), ",")
		for _, p := range parts {
			if s := strings.TrimSpace(p); s != "" {
				return s
			}
		}
	}
	return ""
}

// rowJoinedValue 与 rowStringValue 同语义，但字段值为数组时把字符串项拼接返回
// （ZoomEye 的 title/app 会以 list 形态返回，直接 fmt.Sprint 会得到 "[a b]" 垃圾值；
// 对标 AutoHunter 归一回落链移植项 #3）。map 形态（org 等嵌套对象）不拼、返回空。
func rowJoinedValue(row map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		v := valueByPath(row, k)
		if v == nil {
			continue
		}
		switch t := v.(type) {
		case string:
			if s := strings.TrimSpace(t); s != "" {
				return s
			}
		case []interface{}:
			parts := make([]string, 0, len(t))
			for _, item := range t {
				if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
					parts = append(parts, strings.TrimSpace(s))
				}
			}
			if len(parts) > 0 {
				return strings.Join(parts, ", ")
			}
		}
	}
	return ""
}

// htmlTitlePattern 从 HTTP 响应原文抠 <title>（Quake 旧版 API 的 service.response
// 无结构化 title 字段时的回落；只看前 8KB，大小写不敏感）。
var htmlTitlePattern = regexp.MustCompile(`(?is)<title[^>]*>\s*(.*?)\s*</title>`)

func htmlTitleFromBody(body string) string {
	if body == "" {
		return ""
	}
	if len(body) > 8192 {
		body = body[:8192]
	}
	m := htmlTitlePattern.FindStringSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	title := strings.TrimSpace(m[1])
	if len([]rune(title)) > 256 {
		title = string([]rune(title)[:256])
	}
	return title
}

// cleanAssetProtocol 归一化引擎返回的协议字段，避免整批入库被单条脏值拖垮：
//   - 小写、去空格；quake 的 service.name 形如 "http/ssl"，取 "/" 前段 → "http"
//   - 其余非法字符（空格/斜杠外的符号等）一律置空（协议为可选字段，置空可入库）
func cleanAssetProtocol(raw string) string {
	v := strings.ToLower(strings.TrimSpace(raw))
	if v == "" {
		return ""
	}
	if idx := strings.IndexByte(v, '/'); idx >= 0 {
		v = v[:idx]
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '.' || c == '-' {
			continue
		}
		return ""
	}
	if v == "" || v[0] < 'a' || v[0] > 'z' {
		return ""
	}
	if len(v) > 32 {
		return ""
	}
	return v
}

// urlHostOrEmpty 从 URL 字符串提取小写主机名（去端口/FQDN 尾点）；解析失败返回空串。
func urlHostOrEmpty(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	return strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
}
