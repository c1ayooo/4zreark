package wih

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/internal/useragent"
)

// Config 同源受控探测配置。零值字段会被 NormalizeConfig 补成默认值。
type Config struct {
	// MaxCandidatesPerSite 单站点最多探测的候选数
	MaxCandidatesPerSite int
	// MaxRedirects 单次请求最多跟随的重定向数
	MaxRedirects int
	// PerSiteBudget 单站点探测总预算（含建软 404 基线的开销）
	PerSiteBudget time.Duration
	// PerRequestTimeout 单请求超时（client.Timeout）
	PerRequestTimeout time.Duration
	// RateDelay 相邻两次请求之间的强制间隔（限速）
	RateDelay time.Duration
	// BodySampleBytes GET 响应只读前 N 字节做摘要
	BodySampleBytes int64
	// UserAgent 自定义 UA；为空时随机挑选一个桌面 UA
	UserAgent string
}

// 默认参数：单站 20 个候选、60s 预算、单请求 8s、限速 200ms。
const (
	defaultMaxCandidates = 20
	defaultMaxRedirects  = 3
	defaultSiteBudget    = 60 * time.Second
	defaultReqTimeout    = 8 * time.Second
	defaultRateDelay     = 200 * time.Millisecond
	defaultBodySample    = 16 << 10 // 16KiB
)

// DefaultConfig 返回默认探测配置。
func DefaultConfig() Config {
	return Config{
		MaxCandidatesPerSite: defaultMaxCandidates,
		MaxRedirects:         defaultMaxRedirects,
		PerSiteBudget:        defaultSiteBudget,
		PerRequestTimeout:    defaultReqTimeout,
		RateDelay:            defaultRateDelay,
		BodySampleBytes:      defaultBodySample,
	}
}

// NormalizeConfig 把零值字段补成默认值。
func NormalizeConfig(c Config) Config {
	if c.MaxCandidatesPerSite <= 0 {
		c.MaxCandidatesPerSite = defaultMaxCandidates
	}
	if c.MaxRedirects <= 0 {
		c.MaxRedirects = defaultMaxRedirects
	}
	if c.PerSiteBudget <= 0 {
		c.PerSiteBudget = defaultSiteBudget
	}
	if c.PerRequestTimeout <= 0 {
		c.PerRequestTimeout = defaultReqTimeout
	}
	if c.RateDelay < 0 {
		c.RateDelay = defaultRateDelay
	}
	if c.BodySampleBytes <= 0 {
		c.BodySampleBytes = defaultBodySample
	}
	return c
}

// ProbeEndpoint 单条候选路径的受控探测结论。
// 只记录以下白名单字段：状态码、方法、Content-Type、Content-Length、
// Server、Allow；绝不记录/转发 Cookie、Authorization、Set-Cookie。
type ProbeEndpoint struct {
	// URL 实际探测的 URL。同源重定向跟随到最终地址；
	// 重定向跳出同 host 时记录重定向目标并置 OffSite。
	URL string `json:"url"`
	// Method 得到该结论所用的方法（HEAD，或被拒后回退的 GET）
	Method string `json:"method"`
	// StatusCode 最终响应状态码（OffSite 时是同源侧的 3xx）
	StatusCode int `json:"status_code"`
	// ContentType 响应 Content-Type（原样，含 charset）
	ContentType string `json:"content_type"`
	// ContentLength 响应 Content-Length（未知为 -1）
	ContentLength int64 `json:"content_length"`
	// Server 响应 Server 头
	Server string `json:"server,omitempty"`
	// Allow 响应 Allow 头（405 时常见）
	Allow string `json:"allow,omitempty"`
	// Verified 是否可验证：2xx/3xx 且未命中软 404 基线
	Verified bool `json:"verified"`
	// Digest GET 响应前 16KiB 的 sha256 前 16 个 hex 字符（仅 GET 有）
	Digest string `json:"digest,omitempty"`
	// OffSite 重定向跳出同 host，已停止跟随
	OffSite bool `json:"off_site,omitempty"`
}

// SiteProbeResult 单站点的探测结果。
type SiteProbeResult struct {
	// Origin 归一化后的站点源（scheme://host）
	Origin string `json:"origin"`
	// Probed 实际拿到响应的候选探测次数（网络失败的候选不计入）
	Probed int `json:"probed"`
	// Endpoints 各候选的探测结论
	Endpoints []ProbeEndpoint `json:"endpoints"`
}

// Prober 同源受控探测器。
// 复用 webscan/httpx.go 的传输层思路（忽略 TLS 校验、保守的拨号超时），
// 但客户端为受控探测定制：无 CookieJar、重定向同源内跟随、
// 跳出同 host 立即停（ErrUseLastResponse），并只读响应前 16KiB。
type Prober struct {
	cfg       Config
	client    *http.Client
	userAgent string
	transport *http.Transport
}

// NewProber 创建探测器，零值配置自动补默认值。
func NewProber(cfg Config) *Prober {
	cfg = NormalizeConfig(cfg)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 10 * time.Second,
		}).DialContext,
		MaxIdleConns:        50,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     30 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   cfg.PerRequestTimeout,
		// 刻意不设置 CookieJar：不带任何会话态，服务端种下的 Cookie 也不会被回传
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= cfg.MaxRedirects {
				return http.ErrUseLastResponse
			}
			// 重定向跳出同 host：记录目标 URL 并停止跟随（保留最后一个同源响应）
			if st := redirectStateFrom(req.Context()); st != nil &&
				st.originHost != "" && req.URL.Host != st.originHost {
				st.offSite = req.URL.String()
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	ua := cfg.UserAgent
	if ua == "" {
		ua = useragent.Pick()
	}
	return &Prober{
		cfg:       cfg,
		client:    client,
		userAgent: ua,
		transport: transport,
	}
}

// ProbeSite 对同一站点的候选路径做受控探测。
// 整个过程受站点预算（PerSiteBudget）约束，随时响应 ctx 取消；
// 候选数超过 MaxCandidatesPerSite 时截断；请求之间按 RateDelay 限速。
func (p *Prober) ProbeSite(ctx context.Context, originURL string, candidates []EndpointCandidate) *SiteProbeResult {
	result := &SiteProbeResult{Origin: originOf(originURL)}
	if result.Origin == "" || len(candidates) == 0 {
		return result
	}

	siteCtx, cancel := context.WithTimeout(ctx, p.cfg.PerSiteBudget)
	defer cancel()

	if max := p.cfg.MaxCandidatesPerSite; len(candidates) > max {
		candidates = candidates[:max]
	}

	st := &siteState{}
	for _, cand := range candidates {
		if siteCtx.Err() != nil {
			break
		}
		ep := p.probeOne(siteCtx, result.Origin, cand.Path, st)
		if ep == nil {
			continue
		}
		result.Endpoints = append(result.Endpoints, *ep)
		result.Probed++
	}
	return result
}

// FetchPage 抓取页面文本（只读、限长），返回 body 与 Content-Type。
// ok=false 表示请求失败或非 2xx/3xx。与探测共用同一套受控客户端，
// 供模块侧拿 HTML/JS 文本做词法提取。
func (p *Prober) FetchPage(ctx context.Context, rawURL string, maxBytes int64) (string, string, bool) {
	if ctx.Err() != nil {
		return "", "", false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", "", false
	}
	req.Header.Set("User-Agent", p.userAgent)
	req.Header.Set("Accept", "text/html,application/javascript,*/*;q=0.8")

	resp, err := p.client.Do(req)
	if err != nil {
		return "", "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return "", "", false
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if err != nil && len(data) == 0 {
		return "", "", false
	}
	return string(data), resp.Header.Get("Content-Type"), true
}

// probeOne 探测单个候选：先 HEAD，405/403/501 时回退 GET。
func (p *Prober) probeOne(ctx context.Context, origin, path string, st *siteState) *ProbeEndpoint {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	target := origin + path
	rctx := withRedirectState(ctx, &redirectState{originHost: hostOfURL(origin)})

	// 第一击：HEAD（只关心状态与响应头，不拉正文）
	head, ok := p.request(rctx, http.MethodHead, target)
	if !ok {
		return nil
	}
	resp := head
	method := http.MethodHead

	// HEAD 被明确拒绝时回退 GET，拿真实状态码与正文摘要
	if head.status == http.StatusMethodNotAllowed ||
		head.status == http.StatusForbidden ||
		head.status == http.StatusNotImplemented {
		if get, ok := p.request(rctx, http.MethodGet, target); ok {
			resp = get
			method = http.MethodGet
			// Allow 头在被拒的 HEAD 响应上，带过来说明服务端允许什么方法
			if resp.allow == "" {
				resp.allow = head.allow
			}
		}
	}

	ep := &ProbeEndpoint{
		URL:           resp.finalURL,
		Method:        method,
		StatusCode:    resp.status,
		ContentType:   resp.contentType,
		ContentLength: resp.contentLength,
		Server:        resp.server,
		Allow:         resp.allow,
		Digest:        resp.digest,
	}
	// 重定向跳出同 host：记录重定向目标并标记（请求已在客户端侧被拦截）
	if rs := redirectStateFrom(rctx); rs != nil && rs.offSite != "" {
		ep.URL = rs.offSite
		ep.OffSite = true
	}
	ep.Verified = isVerifiableStatus(ep.StatusCode) && !p.isSoft404(ctx, origin, st, resp)
	return ep
}

// request 发起一次受控请求。只记录白名单响应头；GET 只读前 BodySampleBytes 字节。
func (p *Prober) request(ctx context.Context, method, target string) (*probeResp, bool) {
	if ctx.Err() != nil {
		return nil, false
	}
	// 站内限速：每个请求前统一等待，任何取消立即放弃
	if !sleepCtx(ctx, p.cfg.RateDelay) {
		return nil, false
	}
	req, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		return nil, false
	}
	req.Header.Set("User-Agent", p.userAgent)
	req.Header.Set("Accept", "*/*")
	// 受控红线：不携带任何凭证——不设置 Cookie/Authorization，
	// client 无 CookieJar，Set-Cookie 也不在记录白名单里。
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()

	var body []byte
	if method == http.MethodGet {
		body, _ = io.ReadAll(io.LimitReader(resp.Body, p.cfg.BodySampleBytes))
	} else {
		// HEAD 稍微排空以便连接复用，但不读取正文
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 8<<10))
	}

	pr := &probeResp{
		status:        resp.StatusCode,
		contentType:   resp.Header.Get("Content-Type"),
		contentLength: resp.ContentLength,
		server:        resp.Header.Get("Server"),
		allow:         resp.Header.Get("Allow"),
		finalURL:      resp.Request.URL.String(),
	}
	if method == http.MethodGet {
		pr.digest = digestOf(body)
		pr.evidenceLen = int64(len(body))
		if pr.contentLength < 0 {
			pr.contentLength = pr.evidenceLen
		}
	} else if resp.ContentLength >= 0 {
		pr.evidenceLen = resp.ContentLength
	} else {
		pr.evidenceLen = -1
	}
	return pr, true
}

// soft404Probes 建软 404 基线要探测的随机路径数，与 webscan/soft404.go 一致取 2~3。
const soft404Probes = 2

// soft404Baseline 软 404 基线签名：状态码 + Content-Type + 正文长度（带容差）。
// 思路参考 scanner/webscan/soft404.go：对任意路径都返回相同「成功形态」响应的
// 站点，其 2xx 不能当作真实命中。
type soft404Baseline struct {
	status      int
	contentType string
	bodyLen     int64
}

// siteState 单站点探测过程中的懒加载状态。
type siteState struct {
	baseline      *soft404Baseline
	baselineTried bool
}

// isSoft404 判断该响应是否命中软 404 基线（只在 2xx 上判定）。
// 基线懒加载：站点出第一个 2xx 时才花 2 个随机请求去建。
func (p *Prober) isSoft404(ctx context.Context, origin string, st *siteState, pr *probeResp) bool {
	if st == nil || pr.status < 200 || pr.status >= 400 {
		return false
	}
	if !st.baselineTried {
		st.baselineTried = true
		st.baseline = p.buildSoft404Baseline(ctx, origin)
	}
	if st.baseline == nil {
		return false
	}
	if pr.status != st.baseline.status {
		return false
	}
	if normalizeContentType(pr.contentType) != st.baseline.contentType {
		return false
	}
	if pr.evidenceLen < 0 || st.baseline.bodyLen < 0 {
		// 没有长度证据（如 HEAD 无 Content-Length）时不判定
		return false
	}
	return lengthSimilar(pr.evidenceLen, st.baseline.bodyLen)
}

// buildSoft404Baseline 向站点请求 2 个随机路径；响应形态一致才返回基线。
func (p *Prober) buildSoft404Baseline(ctx context.Context, origin string) *soft404Baseline {
	sigs := make([]*probeResp, 0, soft404Probes)
	for i := 0; i < soft404Probes; i++ {
		if ctx.Err() != nil {
			return nil
		}
		target := fmt.Sprintf("%s/zre-wih-soft404-%d-%d", origin, time.Now().UnixNano(), i)
		// 建基线的随机请求同样走同源重定向约束与限速
		rctx := withRedirectState(ctx, &redirectState{originHost: hostOfURL(origin)})
		pr, ok := p.request(rctx, http.MethodGet, target)
		if !ok {
			continue
		}
		// 只在「成功形态」（2xx/3xx）上建立基线；真实 404/403 由状态码判定兜住
		if pr.status < 200 || pr.status >= 400 {
			return nil
		}
		sigs = append(sigs, pr)
	}
	if len(sigs) < soft404Probes {
		return nil
	}
	a, b := sigs[0], sigs[1]
	if a.status != b.status {
		return nil
	}
	if normalizeContentType(a.contentType) != normalizeContentType(b.contentType) {
		return nil
	}
	if !lengthSimilar(a.evidenceLen, b.evidenceLen) {
		return nil
	}
	return &soft404Baseline{
		status:      a.status,
		contentType: normalizeContentType(a.contentType),
		bodyLen:     a.evidenceLen,
	}
}

// probeResp 单次响应中允许记录的字段（内部表示）。
type probeResp struct {
	status        int
	contentType   string
	contentLength int64
	server        string
	allow         string
	finalURL      string
	// digest GET 响应前 N 字节的 sha256 前 16 hex；HEAD 为空
	digest string
	// evidenceLen 长度证据：GET 为实读字节数，HEAD 为 Content-Length（未知 -1）
	evidenceLen int64
}

// redirectState 通过 ctx 随请求传递的重定向控制状态。
type redirectState struct {
	originHost string
	offSite    string
}

type wihCtxKey struct{}

func withRedirectState(ctx context.Context, st *redirectState) context.Context {
	return context.WithValue(ctx, wihCtxKey{}, st)
}

func redirectStateFrom(ctx context.Context) *redirectState {
	st, _ := ctx.Value(wihCtxKey{}).(*redirectState)
	return st
}

// isVerifiableStatus 2xx/3xx 视为可验证；404/400/502 等记为 unverified。
func isVerifiableStatus(code int) bool {
	return code >= 200 && code < 400
}

// normalizeContentType 去掉 charset 等参数并转小写，便于基线比对。
func normalizeContentType(ct string) string {
	if i := strings.Index(ct, ";"); i >= 0 {
		ct = ct[:i]
	}
	return strings.ToLower(strings.TrimSpace(ct))
}

// lengthSimilar 长度近似相等（容差 max(64, b/10)），用于软 404 比对。
func lengthSimilar(a, b int64) bool {
	if a == b {
		return true
	}
	diff := a - b
	if diff < 0 {
		diff = -diff
	}
	tolerance := b / 10
	if tolerance < 64 {
		tolerance = 64
	}
	return diff <= tolerance
}

// digestOf sha256 前 16 个 hex 字符。
func digestOf(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])[:16]
}

// sleepCtx 可取消的 sleep。返回 false 表示 ctx 已取消。
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// originOf 归一化出 scheme://host；无法解析返回空串。
func originOf(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// hostOfURL 取 URL 的 host 部分（含端口），取不到返回空串。
func hostOfURL(origin string) string {
	u, err := url.Parse(origin)
	if err != nil {
		return ""
	}
	return u.Host
}
