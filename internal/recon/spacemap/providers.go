// Package spacemap 是五引擎空间测绘(fofa/zoomeye/quake/shodan/hunter)的引擎
// 客户端层——直接移植自 4zreco internal/handler/infocollect 的非 HTTP 路径
// (fofa_ctx.go / fofa_providers.go / fofa.go 的纯函数部分),provider 请求/响应
// 差异适配与归一化逻辑原样保留;宿主差异只有两处:
//   - 配置来源:4zreco 读 config.yaml + env,这里注入 KeyResolver/BaseURLResolver
//     (server 装配层接 settings 表 + env,见 keys.go);
//   - 输出资产模型:4zreco 归一化为 database.Asset,这里输出本地 Result
//     (见 assets.go),入库由调用方走 AssetStore。
//
// 引擎 API 的坑(ZoomEye 列表形态字段、Quake include 不收 icp、Shodan 100 条/
// 页循环、Hunter page_size≤100 等)都在 provider 适配层内消化,注释原样保留。
package spacemap

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/internal/outbound"
	"github.com/c1ayooo/4zreark/internal/recon/collect"
)

// Client 是一次空间测绘查询的执行端。零依赖可测:resolver 均为注入函数。
type Client struct {
	httpClient *http.Client
	// KeyResolver 返回某引擎的 API Key(空=未配置)。env 优先、settings 兜底
	// 的解析在 server 装配层(keys.go),此处只消费。
	KeyResolver func(provider string) string
	// BaseURLResolver 返回某引擎的自定义端点(空=内置默认,支持自建反代)。
	BaseURLResolver func(provider string) string
	// SourceRecorder 源状态台账回写回调(装配层注入;nil = 不记录,尽力而为)。
	SourceRecorder func(provider, status, errMsg string)
}

// NewClient 构造引擎客户端。60s 超时与 4zreco 对齐(引擎偶发慢查询)。
// 代理走设置页的 recon 配置（每次查询新建客户端时取，热生效）。
func NewClient() *Client {
	return &Client{httpClient: outbound.HTTPClient("recon", 60*time.Second)}
}

// SearchRequest 引擎查询入参(engine 归一化名之外的原始形态)。
type SearchRequest struct {
	Provider string `json:"provider,omitempty"`
	Query    string `json:"query"`
	Size     int    `json:"size,omitempty"`
	Page     int    `json:"page,omitempty"`
	Fields   string `json:"fields,omitempty"`
	Full     bool   `json:"full,omitempty"`
}

type apiResponse struct {
	Error   bool            `json:"error"`
	ErrMsg  string          `json:"errmsg"`
	Size    int             `json:"size"`
	Page    int             `json:"page"`
	Total   int             `json:"total"`
	Mode    string          `json:"mode"`
	Query   string          `json:"query"`
	Results [][]interface{} `json:"results"`
}

// SearchResponse 五引擎统一响应结构。
type SearchResponse struct {
	Provider      string                   `json:"provider,omitempty"`
	Query         string                   `json:"query"`
	Size          int                      `json:"size"`
	Page          int                      `json:"page"`
	Total         int                      `json:"total"`
	Fields        []string                 `json:"fields"`
	ResultsCount  int                      `json:"results_count"`
	ExpectedCount int                      `json:"expected_count,omitempty"`
	Shortfall     int                      `json:"shortfall,omitempty"`
	Warning       string                   `json:"warning,omitempty"`
	Results       []map[string]interface{} `json:"results"`
}

// spaceSearchEnvelope zoomeye/quake/shodan 的公共响应壳(字段名各取所需)。
type spaceSearchEnvelope struct {
	Code       interface{}     `json:"code"`
	Message    string          `json:"message"`
	Error      string          `json:"error"`
	Query      string          `json:"query"`
	Total      int             `json:"total"`
	TotalCount int             `json:"total_count"`
	Page       int             `json:"page"`
	PageSize   int             `json:"pagesize"`
	Data       json.RawMessage `json:"data"`
	Matches    json.RawMessage `json:"matches"`
	Meta       struct {
		Pagination struct {
			Total int `json:"total"`
		} `json:"pagination"`
	} `json:"meta"`
}

// Providers 全部受支持的引擎(归一化名)。
var Providers = []string{"fofa", "zoomeye", "quake", "shodan", "hunter"}

func normalizeProvider(provider string) string {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "", "fofa":
		return "fofa"
	case "zoomeye", "zoom-eye":
		return "zoomeye"
	case "quake":
		return "quake"
	case "shodan":
		return "shodan"
	case "hunter", "yingtu":
		return "hunter"
	default:
		return ""
	}
}

// ProviderDisplayName 引擎展示名(资产 Source 列与日志用)。
func ProviderDisplayName(provider string) string {
	switch normalizeProvider(provider) {
	case "zoomeye":
		return "ZoomEye"
	case "quake":
		return "Quake"
	case "shodan":
		return "Shodan"
	case "hunter":
		return "Hunter"
	default:
		return "FOFA"
	}
}

// DefaultFieldsForProvider 各引擎的默认返回字段(4zreco 实测调优结果)。
func DefaultFieldsForProvider(provider string) string {
	switch normalizeProvider(provider) {
	case "zoomeye":
		return "ip,port,domain,hostname,title,service,app,country,city"
	case "quake":
		// 注意：include 里不能带 icp——实测 Quake openAPI 报
		// "筛选字段传参错误: ['icp']"（q2001），会把整条查询打挂。
		// ICP 信息依赖默认响应行（若包含），裂变键提取失败时静默跳过。
		return "ip,port,domain,service.name,service.http.title,location.country_cn,location.province_cn,location.city_cn"
	case "shodan":
		return "ip_str,port,hostnames,domains,org,isp,location.country_name,location.city,product,transport"
	default:
		return "host,ip,port,domain,title,protocol,icp,company,country,province,city,server"
	}
}

// SearchProviderCtx 以给定引擎执行一次查询,返回统一响应结构。
// 每次实际调用(含未配置 key)回写源状态台账(凭据健康,尽力而为)。
func (h *Client) SearchProviderCtx(ctx context.Context, provider string, req SearchRequest) (*SearchResponse, error) {
	provider = normalizeProvider(provider)
	if provider == "" {
		return nil, fmt.Errorf("provider 不支持，可选：fofa、zoomeye、quake、shodan、hunter")
	}
	req.Query = strings.TrimSpace(req.Query)
	if req.Query == "" {
		return nil, fmt.Errorf("query 不能为空")
	}
	if req.Size <= 0 {
		req.Size = 100
	}
	if req.Page <= 0 {
		req.Page = 1
	}
	if req.Size > 10000 {
		req.Size = 10000
	}
	if req.Fields == "" {
		req.Fields = DefaultFieldsForProvider(provider)
	}
	apiKey := h.resolveAPIKey(provider)
	if apiKey == "" {
		h.recordSourceStatus(provider, "not_configured", "API Key 未配置")
		return nil, fmt.Errorf("%s 未配置 API Key（系统设置 → 空间测绘，或环境变量）", ProviderDisplayName(provider))
	}
	var (
		resp *SearchResponse
		err  error
	)
	switch provider {
	case "zoomeye":
		resp, err = h.zoomEyeSearchCtx(ctx, req, apiKey)
	case "quake":
		resp, err = h.quakeSearchCtx(ctx, req, apiKey)
	case "shodan":
		resp, err = h.shodanSearchCtx(ctx, req, apiKey)
	case "hunter":
		resp, err = h.hunterSearchCtx(ctx, req, apiKey)
	default:
		resp, err = h.fofaSearchCtx(ctx, req, apiKey)
	}
	if err != nil {
		status := "error"
		if collect.IsAuthError(err) {
			status = "auth_failed"
		}
		h.recordSourceStatus(provider, status, err.Error())
		return resp, err
	}
	h.recordSourceStatus(provider, "ok", "")
	return resp, nil
}

func (h *Client) recordSourceStatus(provider, status, errMsg string) {
	if h.SourceRecorder != nil {
		h.SourceRecorder(provider, status, errMsg)
	}
}

// SourceConfigured 引擎 key 是否已配置。
func (h *Client) SourceConfigured(provider string) bool {
	return strings.TrimSpace(h.resolveAPIKey(provider)) != ""
}

func (h *Client) resolveAPIKey(provider string) string {
	if h.KeyResolver == nil {
		return ""
	}
	return strings.TrimSpace(h.KeyResolver(normalizeProvider(provider)))
}

func (h *Client) resolveBaseURL(provider string) string {
	provider = normalizeProvider(provider)
	if h.BaseURLResolver != nil {
		if v := strings.TrimSpace(h.BaseURLResolver(provider)); v != "" {
			return canonicalizeBaseURL(provider, v)
		}
	}
	switch provider {
	case "zoomeye":
		return "https://api.zoomeye.ai/v2/search"
	case "quake":
		return "https://quake.360.net/api/v3/search/quake_service"
	case "shodan":
		return "https://api.shodan.io"
	case "hunter":
		return "https://hunter.qianxin.com/openApi/search"
	default:
		return "https://fofa.info/api/v1/search/all"
	}
}

// canonicalizeBaseURL 引擎端点别名归一(4zreco 实测:zoomeye.org 域已弃用、
// quake 360.cn 与 360.net 是两套环境)。
func canonicalizeBaseURL(provider, raw string) string {
	v := strings.TrimSpace(raw)
	if v == "" {
		return v
	}
	switch normalizeProvider(provider) {
	case "zoomeye":
		v = strings.Replace(v, "://api.zoomeye.org", "://api.zoomeye.ai", 1)
	case "quake":
		v = strings.Replace(v, "://quake.360.cn", "://quake.360.net", 1)
	}
	return v
}

// EnvKeyNames 各引擎的环境变量名(env 优先于 settings)。
var EnvKeyNames = map[string]string{
	"fofa":    "FOFA_API_KEY",
	"zoomeye": "ZOOMEYE_API_KEY",
	"quake":   "QUAKE_API_KEY",
	"shodan":  "SHODAN_API_KEY",
	"hunter":  "HUNTER_API_KEY",
}

func (h *Client) fofaSearchCtx(ctx context.Context, req SearchRequest, apiKey string) (*SearchResponse, error) {
	baseURL := h.resolveBaseURL("fofa")
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("FOFA base_url 无效: %w", err)
	}
	qb64 := base64.StdEncoding.EncodeToString([]byte(req.Query))
	params := u.Query()
	params.Set("key", apiKey)
	params.Set("qbase64", qb64)
	params.Set("size", fmt.Sprintf("%d", req.Size))
	params.Set("page", fmt.Sprintf("%d", req.Page))
	params.Set("fields", strings.TrimSpace(req.Fields))
	if req.Full {
		params.Set("full", "true")
	} else {
		params.Set("full", "false")
	}
	u.RawQuery = params.Encode()

	var apiResp apiResponse
	if err := h.doJSONRequestCtx(ctx, http.MethodGet, u.String(), apiKey, "", nil, &apiResp, "FOFA"); err != nil {
		return nil, err
	}
	if apiResp.Error {
		msg := strings.TrimSpace(apiResp.ErrMsg)
		if msg == "" {
			msg = "FOFA 返回错误"
		}
		return nil, fmt.Errorf("%s", msg)
	}
	fields := splitAndCleanCSV(req.Fields)
	results := make([]map[string]interface{}, 0, len(apiResp.Results))
	for _, row := range apiResp.Results {
		item := make(map[string]interface{}, len(fields))
		for i, f := range fields {
			if i < len(row) {
				item[f] = row[i]
			} else {
				item[f] = nil
			}
		}
		results = append(results, item)
	}
	return &SearchResponse{
		Provider:     "fofa",
		Query:        req.Query,
		Size:         apiResp.Size,
		Page:         apiResp.Page,
		Total:        apiResp.Total,
		Fields:       fields,
		ResultsCount: len(results),
		Results:      results,
	}, nil
}

func (h *Client) zoomEyeSearchCtx(ctx context.Context, req SearchRequest, apiKey string) (*SearchResponse, error) {
	baseURL := h.resolveBaseURL("zoomeye")
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("ZoomEye base_url 无效: %w", err)
	}
	body := map[string]interface{}{
		"qbase64":  base64.StdEncoding.EncodeToString([]byte(req.Query)),
		"page":     req.Page,
		"pagesize": req.Size,
	}
	if fields := strings.TrimSpace(req.Fields); fields != "" {
		body["fields"] = fields
	}
	var apiResp spaceSearchEnvelope
	if err := h.doJSONRequestCtx(ctx, http.MethodPost, u.String(), apiKey, "API-KEY", body, &apiResp, "ZoomEye"); err != nil {
		return nil, err
	}
	rows, err := decodeSpaceSearchRows(apiResp.Data)
	if err != nil {
		return nil, fmt.Errorf("解析 ZoomEye 响应失败: %w", err)
	}
	if zoomEyeRequestFailed(apiResp.Code, apiResp.Message) {
		msg := firstNonEmpty(apiResp.Message, messageFromRawObject(apiResp.Data), "ZoomEye 返回错误")
		return nil, fmt.Errorf("%s", msg)
	}
	fields := splitAndCleanCSV(req.Fields)
	return &SearchResponse{
		Provider:     "zoomeye",
		Query:        firstNonEmpty(apiResp.Query, req.Query),
		Size:         firstPositive(apiResp.PageSize, req.Size),
		Page:         firstPositive(apiResp.Page, req.Page),
		Total:        apiResp.Total,
		Fields:       fields,
		ResultsCount: len(rows),
		Results:      projectRows(rows, fields),
	}, nil
}

func (h *Client) quakeSearchCtx(ctx context.Context, req SearchRequest, apiKey string) (*SearchResponse, error) {
	baseURL := h.resolveBaseURL("quake")
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("Quake base_url 无效: %w", err)
	}
	fields := splitAndCleanCSV(req.Fields)
	body := map[string]interface{}{
		"query":  req.Query,
		"size":   req.Size,
		"start":  (req.Page - 1) * req.Size,
		"latest": req.Full,
	}
	if len(fields) > 0 {
		body["include"] = fields
	}
	var apiResp spaceSearchEnvelope
	if err := h.doJSONRequestCtx(ctx, http.MethodPost, u.String(), apiKey, "X-QuakeToken", body, &apiResp, "Quake"); err != nil {
		return nil, err
	}
	rows, err := decodeSpaceSearchRows(apiResp.Data)
	if err != nil {
		return nil, fmt.Errorf("解析 Quake 响应失败: %w", err)
	}
	if !isZeroSpaceSearchCode(apiResp.Code) {
		msg := firstNonEmpty(apiResp.Message, messageFromRawObject(apiResp.Data), "Quake 返回错误")
		return nil, fmt.Errorf("%s", msg)
	}
	total := firstPositive(apiResp.TotalCount, apiResp.Meta.Pagination.Total)
	return &SearchResponse{
		Provider:     "quake",
		Query:        req.Query,
		Size:         req.Size,
		Page:         req.Page,
		Total:        total,
		Fields:       fields,
		ResultsCount: len(rows),
		Results:      projectRows(rows, fields),
	}, nil
}

func (h *Client) shodanSearchCtx(ctx context.Context, req SearchRequest, apiKey string) (*SearchResponse, error) {
	baseURL := strings.TrimRight(h.resolveBaseURL("shodan"), "/") + "/shodan/host/search"
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("Shodan base_url 无效: %w", err)
	}
	var apiResp spaceSearchEnvelope
	targetSize := req.Size
	if targetSize <= 0 {
		targetSize = 100
	}
	if targetSize > 1000 {
		targetSize = 1000
	}
	page := req.Page
	matches := make([]map[string]interface{}, 0, targetSize)
	pagesNeeded := (targetSize + 99) / 100
	for i := 0; i < pagesNeeded; i++ {
		pageURL := *u
		params := pageURL.Query()
		params.Set("key", apiKey)
		params.Set("query", req.Query)
		params.Set("page", fmt.Sprintf("%d", page+i))
		params.Set("minify", "false")
		if fields := strings.TrimSpace(req.Fields); fields != "" {
			params.Set("fields", fields)
		}
		pageURL.RawQuery = params.Encode()
		apiResp = spaceSearchEnvelope{}
		if err := h.doJSONRequestCtx(ctx, http.MethodGet, pageURL.String(), "", "", nil, &apiResp, "Shodan"); err != nil {
			return nil, err
		}
		if errMsg := firstNonEmpty(apiResp.Error, apiResp.Message); errMsg != "" {
			return nil, fmt.Errorf("%s", errMsg)
		}
		pageMatches, err := decodeSpaceSearchRows(apiResp.Matches)
		if err != nil {
			return nil, fmt.Errorf("解析 Shodan 响应失败: %w", err)
		}
		if len(pageMatches) == 0 {
			break
		}
		matches = append(matches, pageMatches...)
		if len(matches) >= targetSize {
			matches = matches[:targetSize]
			break
		}
	}
	fields := splitAndCleanCSV(req.Fields)
	return &SearchResponse{
		Provider:     "shodan",
		Query:        req.Query,
		Size:         targetSize,
		Page:         page,
		Total:        apiResp.Total,
		Fields:       fields,
		ResultsCount: len(matches),
		Results:      projectRows(matches, fields),
	}, nil
}

// hunterSearchCtx 奇安信鹰图 openApi/search 适配：
// GET {base}?api-key=&search=<urlsafe-base64(query)>&page=&page_size=&is_web_search=3
// 响应 {"code":20000,"data":{"total":N,"arr":[...]}}；行字段 url/ip/port/domain/
// web_title/number(ICP 备案号)/company 等，不 projection 原样透出。
func (h *Client) hunterSearchCtx(ctx context.Context, req SearchRequest, apiKey string) (*SearchResponse, error) {
	baseURL := strings.TrimRight(h.resolveBaseURL("hunter"), "/")
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("Hunter base_url 无效: %w", err)
	}
	targetSize := req.Size
	if targetSize <= 0 {
		targetSize = 100
	}
	if targetSize > 500 {
		targetSize = 500
	}
	page := req.Page
	matches := make([]map[string]interface{}, 0, targetSize)
	total := 0
	// page_size 上限 100：请求较大 size 时按页循环（与 Shodan 适配器同策略）
	for i := 0; i*100 < targetSize; i++ {
		pageURL := *u
		params := pageURL.Query()
		params.Set("api-key", apiKey)
		params.Set("search", base64.RawURLEncoding.EncodeToString([]byte(req.Query)))
		params.Set("page", fmt.Sprintf("%d", page+i))
		params.Set("page_size", "100")
		params.Set("is_web_search", "3") // 1=web 2=非web 3=全部
		pageURL.RawQuery = params.Encode()
		var apiResp struct {
			Code int    `json:"code"`
			Msg  string `json:"msg"`
			Data struct {
				Total int                      `json:"total"`
				Arr   []map[string]interface{} `json:"arr"`
			} `json:"data"`
		}
		if err := h.doJSONRequestCtx(ctx, http.MethodGet, pageURL.String(), "", "", nil, &apiResp, "Hunter"); err != nil {
			return nil, err
		}
		// 20000=成功；其余（积分不足/参数错误/无权限）透出 msg
		if apiResp.Code != 20000 {
			msg := strings.TrimSpace(apiResp.Msg)
			if msg == "" {
				msg = fmt.Sprintf("Hunter 返回错误码 %d", apiResp.Code)
			}
			return nil, fmt.Errorf("%s", msg)
		}
		total = apiResp.Data.Total
		if len(apiResp.Data.Arr) == 0 {
			break
		}
		matches = append(matches, apiResp.Data.Arr...)
		if len(matches) >= targetSize {
			matches = matches[:targetSize]
			break
		}
	}
	return &SearchResponse{
		Provider:     "hunter",
		Query:        req.Query,
		Size:         targetSize,
		Page:         page,
		Total:        total,
		ResultsCount: len(matches),
		Results:      matches,
	}, nil
}

// engineGates 是引擎级节拍门（进程级共享）：Client 每次 NewClient() 都是新实例，
// 限流状态挂实例上会被并发新建架空，所以挂在包级。
// 策略来自 collect.PolicyFor（fofa/quake… 单飞 + 引擎专属最小间隔），
// 付费配额引擎背靠背翻页连发会烧配额/触发风控。
var engineGates sync.Map // map[string]*engineGate

type engineGate struct {
	mu   sync.Mutex
	next time.Time
}

// waitEngineTurn 预约同一引擎的下一次请求时点并等到它。
// 预约在锁内完成（保证间隔按发起顺序推进），等待在锁外做（不阻塞其他引擎）。
func waitEngineTurn(ctx context.Context, engine string) {
	g, _ := engineGates.LoadOrStore(strings.ToLower(strings.TrimSpace(engine)), &engineGate{})
	gate := g.(*engineGate)
	gate.mu.Lock()
	wait := time.Until(gate.next)
	gate.next = time.Now().Add(collect.PolicyFor(engine).MinInterval)
	gate.mu.Unlock()
	if wait > 0 {
		select {
		case <-ctx.Done():
		case <-time.After(wait):
		}
	}
}

// doJSONRequestCtx 统一 JSON 请求:UA 伪装、引擎错误提取、32MB 响应上限。
func (h *Client) doJSONRequestCtx(ctx context.Context, method, endpoint, apiKey, headerName string, body interface{}, out interface{}, label string) error {
	// 引擎节拍：进程级最小间隔，翻页循环也必须排队。
	waitEngineTurn(ctx, label)
	if ctx.Err() != nil {
		return fmt.Errorf("%s 请求在限流排队时被取消: %w", label, ctx.Err())
	}

	respBody, statusCode, err := h.doOnce(ctx, method, endpoint, apiKey, headerName, body, label)
	if err != nil {
		return err
	}
	// 429 限流退避：按 Retry-After 等一次（封顶 30 秒）再重试一回。
	if statusCode == http.StatusTooManyRequests {
		select {
		case <-ctx.Done():
			return fmt.Errorf("%s 请求在限流退避时被取消: %w", label, ctx.Err())
		case <-time.After(10 * time.Second):
		}
		waitEngineTurn(ctx, label)
		respBody, statusCode, err = h.doOnce(ctx, method, endpoint, apiKey, headerName, body, label)
		if err != nil {
			return err
		}
	}
	if statusCode < 200 || statusCode >= 300 {
		return fmt.Errorf("%s", extractRemoteAPIError(respBody, statusCode, label))
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		if msg := extractRemoteAPIError(respBody, statusCode, label); strings.Contains(msg, "网页") {
			return fmt.Errorf("%s", msg)
		}
		return fmt.Errorf("解析 %s 响应失败: %w", label, err)
	}
	return nil
}

// doOnce 发一次请求并读干响应体（上限 32MB），不解析 JSON。
func (h *Client) doOnce(ctx context.Context, method, endpoint, apiKey, headerName string, body interface{}, label string) ([]byte, int, error) {
	var reqBody *strings.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, fmt.Errorf("创建请求失败: %w", err)
		}
		reqBody = strings.NewReader(string(b))
	} else {
		reqBody = strings.NewReader("")
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, endpoint, reqBody)
	if err != nil {
		return nil, 0, fmt.Errorf("创建请求失败: %w", err)
	}
	httpReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36")
	httpReq.Header.Set("Accept", "application/json")
	if body != nil {
		httpReq.Header.Set("Content-Type", "application/json")
	}
	if headerName != "" && apiKey != "" {
		httpReq.Header.Set(headerName, apiKey)
	}
	resp, err := h.httpClient.Do(httpReq)
	if err != nil {
		_, _, timeout := safeRequestError(err)
		if timeout {
			return nil, 0, fmt.Errorf("%s 请求超时（60 秒）", label)
		}
		return nil, 0, fmt.Errorf("无法连接 %s 服务，请检查服务器网络或代理配置", label)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("读取 %s 响应失败: %w", label, err)
	}
	return respBody, resp.StatusCode, nil
}

func safeRequestError(err error) (status int, message string, timeout bool) {
	var netErr net.Error
	timeout = errors.Is(err, context.DeadlineExceeded) ||
		(errors.As(err, &netErr) && netErr.Timeout())
	return 0, "", timeout
}

func splitAndCleanCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, p := range parts {
		v := strings.TrimSpace(p)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func projectRows(rows []map[string]interface{}, fields []string) []map[string]interface{} {
	if len(fields) == 0 {
		return rows
	}
	out := make([]map[string]interface{}, 0, len(rows))
	for _, row := range rows {
		item := make(map[string]interface{}, len(fields))
		for _, field := range fields {
			item[field] = valueByPath(row, field)
		}
		out = append(out, item)
	}
	return out
}

func valueByPath(row map[string]interface{}, path string) interface{} {
	if row == nil {
		return nil
	}
	if v, ok := row[path]; ok {
		return v
	}
	parts := strings.Split(path, ".")
	var current interface{} = row
	for _, part := range parts {
		m, ok := current.(map[string]interface{})
		if !ok {
			return nil
		}
		current, ok = m[part]
		if !ok {
			return nil
		}
	}
	return current
}

func firstPositive(values ...int) int {
	for _, v := range values {
		if v > 0 {
			return v
		}
	}
	return 0
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func isZeroSpaceSearchCode(code interface{}) bool {
	switch v := code.(type) {
	case nil:
		return false
	case int:
		return v == 0
	case int64:
		return v == 0
	case float64:
		return v == 0
	case json.Number:
		n, err := v.Int64()
		return err == nil && n == 0
	case string:
		return strings.TrimSpace(v) == "0"
	default:
		return false
	}
}

func isZoomEyeSuccessCode(code interface{}) bool {
	switch v := code.(type) {
	case int:
		return v == 60000
	case int64:
		return v == 60000
	case float64:
		return v == 60000
	case json.Number:
		n, err := v.Int64()
		return err == nil && n == 60000
	case string:
		return strings.TrimSpace(v) == "60000"
	default:
		return false
	}
}

func zoomEyeRequestFailed(code interface{}, message string) bool {
	if isZoomEyeSuccessCode(code) {
		return false
	}
	msg := strings.ToLower(strings.TrimSpace(message))
	if code == nil || isZeroSpaceSearchCode(code) {
		return msg != "" && msg != "success" && msg != "ok" && msg != "successful."
	}
	return true
}

func decodeSpaceSearchRows(raw json.RawMessage) ([]map[string]interface{}, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil, nil
	}
	switch raw[0] {
	case '[':
		var rows []map[string]interface{}
		if err := json.Unmarshal(raw, &rows); err != nil {
			return nil, err
		}
		if rows == nil {
			return []map[string]interface{}{}, nil
		}
		return rows, nil
	case '{':
		var obj map[string]interface{}
		if err := json.Unmarshal(raw, &obj); err != nil {
			return nil, err
		}
		if len(obj) == 0 {
			return []map[string]interface{}{}, nil
		}
		for _, key := range []string{"data", "items", "matches", "results", "list", "records"} {
			nested, ok := obj[key]
			if !ok {
				continue
			}
			switch rows := nested.(type) {
			case []map[string]interface{}:
				return rows, nil
			case []interface{}:
				return interfaceSliceToRowMaps(rows), nil
			}
		}
		return []map[string]interface{}{}, nil
	default:
		return nil, fmt.Errorf("unexpected JSON value")
	}
}

func interfaceSliceToRowMaps(items []interface{}) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(items))
	for _, item := range items {
		if row, ok := item.(map[string]interface{}); ok {
			out = append(out, row)
		}
	}
	return out
}

func messageFromRawObject(raw json.RawMessage) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '{' {
		return ""
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return ""
	}
	for _, key := range []string{"message", "error", "errmsg", "msg"} {
		if s, ok := obj[key].(string); ok {
			if msg := strings.TrimSpace(s); msg != "" {
				return msg
			}
		}
	}
	return ""
}

func extractRemoteAPIError(body []byte, statusCode int, label string) string {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var obj map[string]interface{}
		if err := json.Unmarshal(trimmed, &obj); err == nil {
			for _, key := range []string{"error", "message", "errmsg", "msg"} {
				if s, ok := obj[key].(string); ok {
					if msg := strings.TrimSpace(s); msg != "" {
						return msg
					}
				}
			}
		}
	}
	if len(trimmed) > 0 && trimmed[0] == '<' {
		return fmt.Sprintf("%s 返回了网页而不是 JSON（HTTP %d），请检查 Base URL 或网络是否被拦截", label, statusCode)
	}
	if statusCode < 200 || statusCode >= 300 {
		return fmt.Sprintf("%s 返回非 2xx: %d", label, statusCode)
	}
	return ""
}
