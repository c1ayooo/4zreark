// Package miit 工信部 ICP 备案查询原生客户端（移植自 4zrecon，增加全局限速门）。
// @file      : client.go
// @author    : c1ay
// @time      : 2026/10/15
// -------------------------------------------
// 工信部 ICP 备案查询原生客户端（自 HG-ha/ICP_Query Rust 版移植，替代 ymicp 侧车）。
//
// 协议流（hlwicpfwc.miit.gov.cn）：
//  1. POST /api/auth，body=authKey=md5("testtest"+ts)&timeStamp=ts → params.bussiness=token
//  2. POST /api/image/getCheckImagePoint（header token）→ uuid + bigImage/smallImage(base64 PNG)
//  3. 本地几何缺口定位 → x 偏移
//  4. POST /api/image/checkImage {"key":uuid,"value":"x"} → success=true, params=sign
//  5. POST /api/icpAbbreviateInfo/queryByCondition（header token+sign+uuid）
//
// 反爬要点：headers 必须带 Origin/Referer/随机 __jsluid_s Cookie；创宇盾拦截特征是
// 响应体含「当前访问疑似黑客攻击」。Rust 版用默认 TLS 即可通过，无需浏览器指纹伪装。
package miit

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/internal/resilience"
)

const (
	authURL           = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/auth"
	getCheckImageURL  = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/image/getCheckImagePoint"
	checkImageURL     = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/image/checkImage"
	queryURL          = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/icpAbbreviateInfo/queryByCondition"
	userAgent         = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.41 Safari/537.36 Edg/101.0.1210.32"
	captchaMaxRetry   = 5
	blockMarker       = "当前访问疑似黑客攻击"
	errBlocked        = "当前访问已被创宇盾拦截"
	defaultTimeout    = 30 * time.Second
	tokenExpireSafety = 30 * time.Second // token 提前过期量，避免边界拿到死 token
)

// serviceType：web=1, app=6, mapp=7, kapp=8（对齐 Rust getbeian 映射）
const (
	ServiceTypeWeb  = 1
	ServiceTypeApp  = 6
	ServiceTypeMapp = 7
	ServiceTypeKapp = 8
)

// ErrBlocked 出口 IP 被创宇盾拦截（换 IP/代理或等待解封，重试无意义）
var ErrBlocked = fmt.Errorf(errBlocked)

// Item 备案记录（字段名与工信部返回一致）
type Item struct {
	Domain           string `json:"domain"`
	DomainID         int64  `json:"domainId"`
	ServiceID        int64  `json:"serviceId"`
	MainID           int64  `json:"mainId"`
	ServiceLicence   string `json:"serviceLicence"`
	MainLicence      string `json:"mainLicence"`
	UnitName         string `json:"unitName"`
	NatureName       string `json:"natureName"`
	LimitAccess      string `json:"limitAccess"`
	UpdateRecordTime string `json:"updateRecordTime"`
	ContentTypeName  string `json:"contentTypeName"`
	LeaderName       string `json:"leaderName"`
}

// Page 一页查询结果
type Page struct {
	Total   int
	Pages   int
	PageNum int
	Items   []Item
}

// Client 工信部查询客户端（并发安全）。
//
// 采集风控（resilience 纵深熔断）：
//   - 每个上游 host 一个熔断器：连续失败开闸、创宇盾拦截立即开闸，
//     冷却期指数退避；开闸期间请求直接以 *resilience.CircuitOpenError 拒绝；
//   - 出口代理池：proxy 支持逗号/换行分隔多代理，轮转使用；被封出口自动拉黑换道，
//     全部被封时回退直连并由熔断器节流。
type Client struct {
	timeout  time.Duration
	gate     *requestGate
	pool     *resilience.ProxyPool
	breakers *resilience.BreakerSet

	clientsMu sync.Mutex
	clients   map[string]*http.Client // 按出口串（""=直连）惰性建连

	mu          sync.Mutex
	token       string
	tokenExpire time.Time
}

// New 创建客户端；proxy 支持逗号/换行分隔的多个代理（单条 http:// 前缀可省略），
// 兼容旧签名：单代理串行为不变，多代理时按池轮转。
func New(proxy string, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &Client{
		timeout:  timeout,
		pool:     resilience.NewProxyPool(proxy),
		breakers: resilience.NewBreakerSet(),
		clients:  map[string]*http.Client{},
		gate:     newRequestGate(5 * time.Second),
	}
}

// SetMinInterval 设置任意两次工信部请求之间的最小间隔（默认 5s）。
// 所有 token/验证码/查询请求共用该节拍；调小会显著增加被封风险。
func (c *Client) SetMinInterval(d time.Duration) {
	if c.gate != nil {
		c.gate.setInterval(d)
	}
}

// clientFor 返回绑定指定出口的 HTTP 客户端（惰性创建并缓存）。
// 多代理时按出口隔离连接池，避免复用被风控盯上的 TCP/TLS 会话。
func (c *Client) clientFor(proxy string) *http.Client {
	c.clientsMu.Lock()
	defer c.clientsMu.Unlock()
	if hc, ok := c.clients[proxy]; ok {
		return hc
	}
	transport := &http.Transport{
		MaxIdleConnsPerHost: 30,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, // 对齐 Rust danger_accept_invalid_certs
	}
	if p := normalizeProxy(proxy); p != "" {
		if u, err := url.Parse(p); err == nil {
			transport.Proxy = http.ProxyURL(u)
		}
	}
	hc := &http.Client{Transport: transport, Timeout: c.timeout}
	c.clients[proxy] = hc
	return hc
}

// normalizeProxy 归一出口串：去空白，无 scheme 时补 http://（对齐原 New 语义）。
func normalizeProxy(proxy string) string {
	p := strings.TrimSpace(proxy)
	if p == "" {
		return ""
	}
	if !strings.Contains(p, "://") {
		p = "http://" + p
	}
	return p
}

// requestHost 提取请求 URL 的 host，作为熔断器粒度（hlwicpfwc.miit.gov.cn 等）。
func requestHost(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil && u.Host != "" {
		return u.Host
	}
	return rawURL
}

func baseHeaders() map[string]string {
	return map[string]string{
		"User-Agent": userAgent,
		"Origin":     "https://beian.miit.gov.cn",
		"Referer":    "https://beian.miit.gov.cn/",
		"Cookie":     "__jsluid_s=" + randHex(32),
		"Accept":     "application/json, text/plain, */*",
	}
}

// post 发起一次带风控防护的上游请求（token/验证码/查询共用）。
//
// 纵深熔断流程：
//  1. 检查按 host 的熔断器：开闸期间直接拒绝（*resilience.CircuitOpenError，带建议等待时长）；
//  2. 过全局 5s 限速门后，从代理池轮出一个出口发请求；
//  3. 按结果回填熔断器与代理池：成功 → RecordSuccess/ok；创宇盾拦截 → RecordBlocked/blocked
//     （池内还有其他可用出口时，同一请求内换道重试 1 次）；网络错/5xx → RecordFailure/error。
func (c *Client) post(ctx context.Context, rawURL string, headers map[string]string, contentType string, body []byte) ([]byte, error) {
	host := requestHost(rawURL)
	bk := c.breakers.Get(host)

	proxy := c.pool.Pick()
	data, err := c.doOnce(ctx, bk, host, proxy, rawURL, headers, contentType, body, true)
	if errors.Is(err, ErrBlocked) {
		// 当前出口被创宇盾拦截：池内还有其他可用出口时换道重试一次。
		// 验证码层面的重试逻辑（solveCaptcha）保持不变。
		if alt, ok := c.pool.PickExcluding(proxy); ok {
			return c.doOnce(ctx, bk, host, alt, rawURL, headers, contentType, body, false)
		}
	}
	return data, err
}

// doOnce 执行单次请求并回填熔断器/代理池状态。checkBreaker=false 用于被拦截后的
// 换道重试：这是同一个调用内的续发请求，不再重复过闸（此时熔断器刚被 RecordBlocked 打开）。
func (c *Client) doOnce(ctx context.Context, bk *resilience.Breaker, host, proxy, rawURL string, headers map[string]string, contentType string, body []byte, checkBreaker bool) ([]byte, error) {
	if checkBreaker {
		if ok, retryAfter := bk.Allow(); !ok {
			return nil, &resilience.CircuitOpenError{Host: host, RetryAfter: retryAfter}
		}
	}
	if c.gate != nil {
		if err := c.gate.wait(ctx); err != nil {
			return nil, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := c.clientFor(proxy).Do(req)
	if err != nil {
		bk.RecordFailure()
		c.pool.Report(proxy, resilience.OutcomeError)
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusInternalServerError {
		bk.RecordFailure()
		c.pool.Report(proxy, resilience.OutcomeError)
		return nil, fmt.Errorf("工信部服务器异常（HTTP %d）", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		bk.RecordFailure()
		c.pool.Report(proxy, resilience.OutcomeError)
		return nil, err
	}
	if strings.Contains(string(data), blockMarker) {
		bk.RecordBlocked()
		c.pool.Report(proxy, resilience.OutcomeBlocked)
		return nil, ErrBlocked
	}
	bk.RecordSuccess()
	c.pool.Report(proxy, resilience.OutcomeOK)
	return data, nil
}

// getToken 取业务 token（缓存到过期）；authKey = md5("testtest"+timeStamp)
func (c *Client) getToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Now().Before(c.tokenExpire) {
		return c.token, nil
	}
	ts := time.Now().UnixMilli()
	sum := md5.Sum([]byte(fmt.Sprintf("testtest%d", ts)))
	body := fmt.Sprintf("authKey=%s&timeStamp=%d", hex.EncodeToString(sum[:]), ts)
	data, err := c.post(ctx, authURL, baseHeaders(), "application/x-www-form-urlencoded", []byte(body))
	if err != nil {
		return "", fmt.Errorf("获取 token 失败: %w", err)
	}
	var res struct {
		Success bool `json:"success"`
		Params  struct {
			Bussiness string `json:"bussiness"`
			Expire    int64  `json:"expire"`
		} `json:"params"`
	}
	if err := json.Unmarshal(data, &res); err != nil {
		return "", fmt.Errorf("token 响应解析失败: %w (%s)", err, truncate(data, 200))
	}
	if res.Params.Bussiness == "" {
		return "", fmt.Errorf("token 响应缺少 bussiness: %s", truncate(data, 200))
	}
	expire := time.Duration(res.Params.Expire) * time.Millisecond
	if expire > tokenExpireSafety {
		expire -= tokenExpireSafety
	}
	c.token = res.Params.Bussiness
	c.tokenExpire = time.Now().Add(expire)
	return c.token, nil
}

// clientUid 构造 point-<uuid4 形态随机串>（对齐 Rust get_client_uid）
func clientUID() string {
	chars := "0123456789abcdef"
	uid := make([]byte, 36)
	for i := range uid {
		uid[i] = chars[rand.Intn(16)]
	}
	uid[14] = '4'
	uid[19] = chars[(3&hexVal(uid[19]))|8]
	uid[8], uid[13], uid[18], uid[23] = '-', '-', '-', '-'
	return "point-" + string(uid)
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	default:
		return 0
	}
}

// solveCaptcha 完整滑块流程：取图 → 定位缺口 → checkImage 换 sign。
// 识别失败自动换一张重试（对齐 sidecar retry_times 语义）。
func (c *Client) solveCaptcha(ctx context.Context, token string) (uuid, sign string, err error) {
	var lastErr error
	for attempt := 0; attempt < captchaMaxRetry; attempt++ {
		uuid, sign, lastErr = c.tryCaptcha(ctx, token)
		if lastErr == nil {
			return uuid, sign, nil
		}
		if lastErr == ErrBlocked {
			return "", "", lastErr
		}
		select {
		case <-time.After(time.Second):
		case <-ctx.Done():
			return "", "", ctx.Err()
		}
	}
	return "", "", fmt.Errorf("验证码识别失败（重试 %d 次）: %w", captchaMaxRetry, lastErr)
}

func (c *Client) tryCaptcha(ctx context.Context, token string) (uuid, sign string, err error) {
	headers := baseHeaders()
	headers["token"] = token
	data, err := c.post(ctx, getCheckImageURL, headers, "application/json", []byte(clientUID()))
	if err != nil {
		return "", "", fmt.Errorf("请求验证码失败: %w", err)
	}
	var res struct {
		Params struct {
			UUID       string `json:"uuid"`
			BigImage   string `json:"bigImage"`
			SmallImage string `json:"smallImage"`
		} `json:"params"`
	}
	if err := json.Unmarshal(data, &res); err != nil {
		return "", "", fmt.Errorf("验证码响应解析失败: %w", err)
	}
	if res.Params.UUID == "" || res.Params.BigImage == "" || res.Params.SmallImage == "" {
		return "", "", fmt.Errorf("验证码响应字段缺失: %s", truncate(data, 200))
	}
	offset, err := MatchSliderOffset(res.Params.SmallImage, res.Params.BigImage)
	if err != nil {
		return "", "", err
	}
	checkBody, _ := json.Marshal(map[string]string{"key": res.Params.UUID, "value": fmt.Sprintf("%d", offset)})
	data, err = c.post(ctx, checkImageURL, headers, "application/json", checkBody)
	if err != nil {
		return "", "", err
	}
	var check struct {
		Success bool            `json:"success"`
		Code    int             `json:"code"`
		Msg     string          `json:"msg"`
		Params  json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(data, &check); err != nil {
		return "", "", fmt.Errorf("checkImage 响应解析失败: %w", err)
	}
	if !check.Success {
		return "", "", fmt.Errorf("checkImage 未通过: code=%d msg=%s", check.Code, check.Msg)
	}
	sign = strings.Trim(string(check.Params), `"`)
	if sign == "" || sign == "null" {
		return "", "", fmt.Errorf("checkImage 响应缺少 sign")
	}
	return res.Params.UUID, sign, nil
}

// Query 统一查询（web/app/mapp/kapp 共用 queryByCondition）。
// 返回工信部原始 JSON 的 code/success 由调用方按需检查；本函数保证 success=true 才返回数据。
func (c *Client) Query(ctx context.Context, search string, serviceType, pageNum, pageSize int) (*Page, error) {
	token, err := c.getToken(ctx)
	if err != nil {
		return nil, err
	}
	uuid, sign, err := c.solveCaptcha(ctx, token)
	if err != nil {
		return nil, err
	}

	body, _ := json.Marshal(map[string]interface{}{
		"pageNum":     pageNum,
		"pageSize":    pageSize,
		"unitName":    search,
		"serviceType": serviceType,
	})
	headers := baseHeaders()
	headers["token"] = token
	headers["sign"] = sign
	headers["uuid"] = uuid

	data, err := c.post(ctx, queryURL, headers, "application/json", body)
	if err != nil {
		return nil, err
	}
	var res struct {
		Code    int    `json:"code"`
		Msg     string `json:"msg"`
		Success bool   `json:"success"`
		Params  struct {
			Total int    `json:"total"`
			Pages int    `json:"pages"`
			List  []Item `json:"list"`
		} `json:"params"`
	}
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, fmt.Errorf("查询响应解析失败: %w (%s)", err, truncate(data, 200))
	}
	if res.Code == 500 {
		return nil, fmt.Errorf("工信部服务器异常: %s", truncate(data, 200))
	}
	if !res.Success {
		return nil, fmt.Errorf("查询失败 code=%d msg=%s", res.Code, res.Msg)
	}
	return &Page{Total: res.Params.Total, Pages: res.Params.Pages, PageNum: pageNum, Items: res.Params.List}, nil
}

func randHex(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = "0123456789abcdef"[rand.Intn(16)]
	}
	return string(b)
}

func truncate(data []byte, n int) string {
	s := strings.TrimSpace(string(data))
	if len(s) > n {
		s = s[:n] + "…"
	}
	return s
}
