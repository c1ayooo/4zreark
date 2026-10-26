package verifyrunner

// run.go —— 剧本确定性执行（施工单 E1）。
//
// 语义：
//   1. 步骤严格串行（红线：并发 ≤2 取更严 = 1），每步一个请求（repeat 控制重复次数）；
//   2. 断言失败即停：失败步状态 ∈ RefutedStatusIn → refuted；其余失败 → blocked
//      （「中途失败 ≠ 测过没问题」，证据保留到失败步，施工单 E1 失败语义）；
//   3. 全部通过 → confirmed；
//   4. Cookie jar 每次运行独立（状态不跨剧本泄漏）；重定向仅限同 host，
//      跨 host 302 停在 3xx（scope 纪律：剧本不得把请求带出目标 host）。

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/c1ayooo/4zreark/internal/useragent"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/c1ayooo/4zreark/internal/recon/directhttp"
)

// RunOptions 一次运行的入参。
type RunOptions struct {
	Vars        map[string]string // 渲染变量（host 必填；其余须覆盖剧本 RequiresVars）
	BaseURL     string            // 可选：相对 URL 的基底（空 = 剧本 URL 必须自带 scheme）
	Timeout     time.Duration     // 单步超时（0 = 剧本 limits 或默认）
	Client      *http.Client      // 测试注入；nil = directhttp 直连 + cookie jar
	MaxRequests int               // 测试注入覆写（默认剧本 limits）
	Resolver    DNSResolver       // dns 步解析器（测试注入）；nil = 平台侧默认（net.DefaultResolver）
	TCPDialer   TCPDialer         // tcp 步拨号器（测试注入）；nil = 平台侧默认（&net.Dialer{Timeout: 单步超时}）
}

// Run 确定性执行剧本。恒返回非 nil 的 RunResult（失败语义在 Verdict/Reason，不靠 error）；
// error 仅在入参本身非法（变量缺失等）时返回。
func Run(ctx context.Context, pb *Playbook, opts RunOptions) (*RunResult, error) {
	if pb == nil {
		return nil, fmt.Errorf("剧本为空")
	}
	vars := map[string]string{}
	for k, v := range opts.Vars {
		vars[k] = strings.TrimSpace(v)
	}
	if vars["host"] == "" {
		return nil, fmt.Errorf("变量 host 必填（剧本 %s）", pb.ID)
	}
	for _, req := range pb.VarsRequired {
		if vars[req] == "" {
			return nil, fmt.Errorf("剧本 %s 需要变量 %s（入参 vars 未提供）", pb.ID, req)
		}
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultStepTimeout
		if ms := pb.Limits.PerStepTimeoutMS; ms > 0 {
			timeout = time.Duration(ms) * time.Millisecond
		}
	}
	if timeout > MaxStepTimeout {
		timeout = MaxStepTimeout
	}

	jar, _ := cookiejar.New(nil)
	client := opts.Client
	if client == nil {
		client = directhttp.Client(&http.Client{})
	}
	// 独立 jar + 同 host 重定向守卫（不篡改调用方注入的 client 的长期状态）
	cloned := *client
	cloned.Timeout = timeout
	cloned.Jar = jar
	baseURL := ""
	if u, err := url.Parse(render(opts.BaseURL, vars)); err == nil && u.Host != "" {
		baseURL = u.Host
	}
	cloned.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= MaxRedirectsPerStep {
			return fmt.Errorf("重定向次数超 %d", MaxRedirectsPerStep)
		}
		if baseURL != "" && req.URL.Host != baseURL {
			return http.ErrUseLastResponse // 跨 host：停在 3xx，不跟随
		}
		if via[0].URL.Host != req.URL.Host {
			return http.ErrUseLastResponse
		}
		return nil
	}

	maxReq := pb.Limits.MaxRequests
	if maxReq <= 0 {
		maxReq = DefaultMaxRequests
	}
	if opts.MaxRequests > 0 && opts.MaxRequests < maxReq {
		maxReq = opts.MaxRequests
	}
	resolver := opts.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver // dns 步 resolver 固定平台侧（步骤不可自定义）
	}
	tcpDialer := opts.TCPDialer
	if tcpDialer == nil {
		tcpDialer = &net.Dialer{Timeout: timeout}
	}

	res := &RunResult{PlaybookID: pb.ID, Extracted: map[string]string{}}
	start := time.Now()
	for _, st := range pb.Steps {
		repeat := st.Request.Repeat
		if repeat < 0 {
			repeat = 0
		}
		for i := 0; i <= repeat; i++ {
			if res.Requests >= maxReq {
				res.Verdict = VerdictBlocked
				res.Reason = fmt.Sprintf("已达 max_requests=%d 硬顶，步骤 %s 未执行", maxReq, st.Name)
				res.DurationMS = time.Since(start).Milliseconds()
				return res, nil
			}
			// 按 kind 分派（tcp/dns 与 http 同一循环：串行、同 repeat/请求硬顶，
			// dns 查询与 tcp 连接同样计入 max_requests——观测不豁免硬顶）
			var sr *StepResult
			switch KindOf(st.Kind) {
			case StepKindTCP:
				sr = runTCPStep(ctx, tcpDialer, &st, vars, timeout)
			case StepKindDNS:
				sr = runDNSStep(ctx, resolver, &st, vars, timeout)
			default:
				sr = runStep(ctx, &cloned, &st, vars, opts.BaseURL)
			}
			res.Steps = append(res.Steps, *sr)
			res.Requests++
			for k, v := range sr.Extracted {
				res.Extracted[k] = v
				vars[k] = v
			}
			if !sr.OK {
				res.Verdict, res.Reason = classifyFailure(pb, &st, sr)
				res.DurationMS = time.Since(start).Milliseconds()
				return res, nil
			}
		}
	}
	res.Verdict = VerdictConfirmed
	res.Reason = fmt.Sprintf("全部 %d 步骤断言通过", len(pb.Steps))
	res.DurationMS = time.Since(start).Milliseconds()
	return res, nil
}

// classifyFailure 失败分类：refuted（证伪）/ blocked（中断，非「测过」）。
func classifyFailure(pb *Playbook, st *Step, sr *StepResult) (string, string) {
	for _, s := range pb.RefutedStatusIn {
		if s == sr.Status {
			return VerdictRefuted, fmt.Sprintf("步骤 %s 状态 %d 命中 refuted_status_in，假设证伪", st.Name, sr.Status)
		}
	}
	if sr.Status == 0 {
		return VerdictBlocked, fmt.Sprintf("步骤 %s 网络错误: %s", st.Name, sr.FailReason)
	}
	if KindOf(st.Kind) != StepKindHTTP {
		// tcp/dns 步 Status 非 HTTP 状态码（1=观测完成），失败原因在断言里
		return VerdictBlocked, fmt.Sprintf("步骤 %s 断言未过: %s", st.Name, sr.FailReason)
	}
	return VerdictBlocked, fmt.Sprintf("步骤 %s 断言未过（status=%d）： %s", st.Name, sr.Status, sr.FailReason)
}

// runStep 执行单步（repeat 层已展开，此处恰一次请求）。
func runStep(ctx context.Context, client *http.Client, st *Step, vars map[string]string, baseURL string) *StepResult {
	sr := &StepResult{Name: st.Name, Extracted: map[string]string{}}
	method := strings.ToUpper(strings.TrimSpace(st.Request.Method))
	rawURL := render(st.Request.URL, vars)
	if !strings.Contains(rawURL, "://") && baseURL != "" {
		rawURL = strings.TrimSuffix(baseURL, "/") + "/" + strings.TrimLeft(rawURL, "/")
	}
	reqURL, err := url.Parse(rawURL)
	if err != nil || reqURL.Host == "" {
		sr.FailReason = fmt.Sprintf("URL 非法: %s", rawURL)
		return sr
	}
	sr.URL = rawURL
	sr.Method = method

	var body io.Reader
	if st.Request.Body != "" {
		body = strings.NewReader(render(st.Request.Body, vars))
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		sr.FailReason = err.Error()
		return sr
	}
	req.Header.Set("User-Agent", useragent.Pick())
	for k, v := range st.Request.Headers {
		req.Header.Set(render(k, vars), render(v, vars))
	}
	sr.ReqHeaders = map[string]string{}
	for k := range st.Request.Headers {
		sr.ReqHeaders[render(k, vars)] = "***" // 请求头值可能含凭据，摘要脱敏
	}

	stepStart := time.Now()
	resp, err := client.Do(req)
	sr.DurationMS = time.Since(stepStart).Milliseconds()
	if err != nil {
		// ErrUseLastResponse 不会进 err；其余按网络错误
		sr.FailReason = err.Error()
		return sr
	}
	defer resp.Body.Close()
	sr.Status = resp.StatusCode

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBody))
	bodyText := string(bodyBytes)
	if len(bodyText) > RespSnippetLen {
		sr.RespSnippet = bodyText[:RespSnippetLen]
	} else {
		sr.RespSnippet = bodyText
	}
	headerText := headersBlob(resp)

	// 提取（先于断言：提取失败不算断言失败，但变量为空串）
	for _, ex := range st.Extract {
		val := extractValue(ex, headerText, bodyText, "")
		sr.Extracted[ex.Name] = val
	}

	if st.Expect != nil {
		if reason := checkExpectation(st.Expect, resp.StatusCode, headerText, bodyText, sr.DurationMS); reason != "" {
			sr.FailReason = reason
			return sr
		}
	}
	sr.OK = true
	return sr
}

// checkExpectation http 断言面（全部声明项满足 = ""；否则返回失败原因）。
// headerText 为 headersBlob 产物（header 断言与 headers 提取同一口径）。
func checkExpectation(ex *Expectation, status int, headerText, body string, durationMS int64) string {
	if ex.Status != 0 && status != ex.Status {
		return fmt.Sprintf("期望状态 %d 实际 %d", ex.Status, status)
	}
	if len(ex.StatusIn) > 0 {
		ok := false
		for _, s := range ex.StatusIn {
			if status == s {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Sprintf("状态 %d 不在期望集合 %v", status, ex.StatusIn)
		}
	}
	for _, s := range ex.Contains {
		if !strings.Contains(body, s) {
			return fmt.Sprintf("响应体不含 %q", s)
		}
	}
	if len(ex.ContainsAny) > 0 {
		ok := false
		for _, s := range ex.ContainsAny {
			if strings.Contains(body, s) {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Sprintf("响应体不含任一特征 %v", ex.ContainsAny)
		}
	}
	for _, s := range ex.NotContains {
		if strings.Contains(body, s) {
			return fmt.Sprintf("响应体含禁止特征 %q", s)
		}
	}
	if ex.Regex != "" {
		re, err := regexp.Compile(ex.Regex)
		if err != nil {
			return fmt.Sprintf("正则非法: %v", err)
		}
		if !re.MatchString(body) {
			return fmt.Sprintf("响应体不匹配正则 %q", ex.Regex)
		}
	}
	// V3：header 断言（对 headersBlob 文本判定，如 "Set-Cookie: sid=" / CORS 头判据）
	for _, s := range ex.RespHeaderContains {
		if !strings.Contains(headerText, s) {
			return fmt.Sprintf("响应头不含 %q", s)
		}
	}
	if ex.RespHeaderRegex != "" {
		re, err := regexp.Compile(ex.RespHeaderRegex)
		if err != nil {
			return fmt.Sprintf("正则非法: %v", err)
		}
		if !re.MatchString(headerText) {
			return fmt.Sprintf("响应头不匹配正则 %q", ex.RespHeaderRegex)
		}
	}
	return checkDurationExpectation(ex, durationMS)
}

// checkDurationExpectation 时延差分断言（V3，各 kind 通用）：runner 只做比较，
// 阈值由模型按基线步推理给出。0 = 不检查。
func checkDurationExpectation(ex *Expectation, durationMS int64) string {
	if ex.DurationMSLt > 0 && durationMS >= int64(ex.DurationMSLt) {
		return fmt.Sprintf("耗时 %dms 未低于 %dms（时延差分判据未命中）", durationMS, ex.DurationMSLt)
	}
	if ex.DurationMSGt > 0 && durationMS <= int64(ex.DurationMSGt) {
		return fmt.Sprintf("耗时 %dms 未高于 %dms（时延差分判据未命中）", durationMS, ex.DurationMSGt)
	}
	return ""
}

// checkTCPExpectation tcp 断言面（V1）：connect_ok/banner_* + 时延。
func checkTCPExpectation(ex *Expectation, connected bool, banner string, durationMS int64) string {
	if ex.ConnectOK != nil && *ex.ConnectOK != connected {
		if *ex.ConnectOK {
			return "连接未建立（connect_ok=true 判据未命中）"
		}
		return "端口开放，与 connect_ok=false 判据不符"
	}
	for _, s := range ex.BannerContains {
		if !strings.Contains(banner, s) {
			return fmt.Sprintf("banner 不含 %q", s)
		}
	}
	for _, s := range ex.BannerNotContains {
		if strings.Contains(banner, s) {
			return fmt.Sprintf("banner 含禁止特征 %q", s)
		}
	}
	if ex.BannerRegex != "" {
		re, err := regexp.Compile(ex.BannerRegex)
		if err != nil {
			return fmt.Sprintf("正则非法: %v", err)
		}
		if !re.MatchString(banner) {
			return fmt.Sprintf("banner 不匹配正则 %q", ex.BannerRegex)
		}
	}
	return checkDurationExpectation(ex, durationMS)
}

// checkDNSExpectation dns 断言面（V2）：对查询结果文本/记录数判定 + 时延。
// NXDOMAIN（0 条记录）也是可观测结论，由 resolve_count_lt 表达。
func checkDNSExpectation(ex *Expectation, answerText string, count int, durationMS int64) string {
	for _, s := range ex.ResolveContains {
		if !strings.Contains(answerText, s) {
			return fmt.Sprintf("解析结果不含 %q", s)
		}
	}
	for _, s := range ex.CnameChainContains {
		if !strings.Contains(answerText, s) {
			return fmt.Sprintf("CNAME 解析目标不含 %q", s)
		}
	}
	for _, s := range ex.TxtContains {
		if !strings.Contains(answerText, s) {
			return fmt.Sprintf("TXT 记录不含 %q", s)
		}
	}
	if ex.ResolveCountLT > 0 && count >= ex.ResolveCountLT {
		return fmt.Sprintf("解析记录数 %d 未少于 %d（NXDOMAIN 判据未命中）", count, ex.ResolveCountLT)
	}
	return checkDurationExpectation(ex, durationMS)
}

// headersBlob 响应头扁平文本（header 断言与 headers 提取共用同一口径）。
func headersBlob(resp *http.Response) string {
	var b strings.Builder
	for k, vs := range resp.Header {
		b.WriteString(k)
		b.WriteString(": ")
		b.WriteString(strings.Join(vs, ","))
		b.WriteByte('\n')
	}
	return b.String()
}

// extractValue 从 body/headers/banner 提取捕获组 1；失败返回空串（不致命）。
func extractValue(ex StepExtract, headerText, body, banner string) string {
	re, err := regexp.Compile(ex.Regex)
	if err != nil {
		return ""
	}
	var text string
	switch strings.ToLower(strings.TrimSpace(ex.From)) {
	case "headers":
		text = headerText
	case "banner":
		text = banner
	default:
		text = body
	}
	if m := re.FindStringSubmatch(text); m != nil && len(m) > 1 {
		return m[1]
	}
	return ""
}

// runTCPStep 执行 tcp 步（V1）：connect → 可选 payload 写入 → banner 读取 → 断言。
// 观测语义：banner 截断 RespSnippetLen 入证据（与 http 响应体同规格）；
// 连接失败 Status=0 → blocked（与 http 网络错误同语义——超时/被过滤≠「测过」）。
// 例外：connect_ok=false 且收到明确 RST（ECONNREFUSED）时，端口关闭是可观测
// 结论而非网络错误，按断言判定（判「修复后端口已关」类假设用）。
func runTCPStep(ctx context.Context, dialer TCPDialer, st *Step, vars map[string]string, timeout time.Duration) *StepResult {
	sr := &StepResult{Name: st.Name, Method: "TCP", Extracted: map[string]string{}}
	host := render(st.Request.Host, vars)
	port := st.Request.Port
	sr.URL = fmt.Sprintf("tcp://%s:%d", host, port)
	if strings.TrimSpace(host) == "" || port <= 0 {
		sr.FailReason = "tcp 步缺 request.host/port（渲染后为空）"
		return sr
	}
	stepStart := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	sr.DurationMS = time.Since(stepStart).Milliseconds()
	if err != nil {
		if st.Expect != nil && st.Expect.ConnectOK != nil && !*st.Expect.ConnectOK && isConnRefused(err) {
			// 明确拒绝（RST）＝端口关闭的可观测判据；超时/过滤仍按网络错误 blocked
			sr.Status = 1
			if reason := checkTCPExpectation(st.Expect, false, "", sr.DurationMS); reason != "" {
				sr.FailReason = reason
				return sr
			}
			sr.OK = true
			return sr
		}
		sr.FailReason = err.Error()
		return sr
	}
	defer conn.Close()
	sr.Status = 1 // 连接已建立（非 HTTP 状态码，证据展示用）

	if payload := decodeTCPPayload(st.Request.PayloadHex); len(payload) > 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(timeout))
		if _, werr := conn.Write(payload); werr != nil {
			sr.FailReason = "payload 写入失败: " + werr.Error()
			return sr
		}
	}
	// banner 读取：读到连接关闭/超时/满 RespSnippetLen 为止（服务端保持连接不关时
	// 逐步超时兜底——banner 判据的确定性优先于快）
	buf := make([]byte, RespSnippetLen)
	var banner []byte
	for len(banner) < RespSnippetLen {
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
		n, rerr := conn.Read(buf)
		banner = append(banner, buf[:n]...)
		if rerr != nil {
			break // EOF / 超时：banner 到此为止
		}
	}
	sr.RespSnippet = string(banner)

	// 提取（先于断言，与 http 步同语义）
	for _, ex := range st.Extract {
		sr.Extracted[ex.Name] = extractValue(ex, "", "", sr.RespSnippet)
	}
	if st.Expect != nil {
		if reason := checkTCPExpectation(st.Expect, true, sr.RespSnippet, sr.DurationMS); reason != "" {
			sr.FailReason = reason
			return sr
		}
	}
	sr.OK = true
	return sr
}

// runDNSStep 执行 dns 步（V2）：单次查询 + 断言。仅观测不攻击（无畸形查询面，
// 标准库查询形态固定）；resolver 由 Run 注入（平台侧，步骤不可自定义）。
// NXDOMAIN/无此主机按 0 条记录观测处理（IsNotFound 是权威否定回答，非网络错误）。
func runDNSStep(ctx context.Context, resolver DNSResolver, st *Step, vars map[string]string, timeout time.Duration) *StepResult {
	sr := &StepResult{Name: st.Name, Method: "DNS", Extracted: map[string]string{}}
	name := strings.TrimSuffix(render(st.Request.QueryName, vars), ".")
	qtype := strings.ToUpper(strings.TrimSpace(st.Request.QueryType))
	if qtype == "" {
		qtype = "A"
	}
	sr.URL = fmt.Sprintf("dns://%s?type=%s", name, qtype)
	if strings.TrimSpace(name) == "" {
		sr.FailReason = "dns 步缺 request.query_name（渲染后为空）"
		return sr
	}
	qctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	stepStart := time.Now()
	var answers []string
	switch qtype {
	case "CNAME":
		cname, err := resolver.LookupCNAME(qctx, name)
		if err != nil && !isDNSNotFound(err) {
			sr.FailReason = err.Error()
			return sr
		}
		if c := strings.TrimSuffix(cname, "."); c != "" {
			answers = []string{c}
		}
	case "TXT":
		txts, err := resolver.LookupTXT(qctx, name)
		if err != nil && !isDNSNotFound(err) {
			sr.FailReason = err.Error()
			return sr
		}
		answers = txts
	case "NS":
		nss, err := resolver.LookupNS(qctx, name)
		if err != nil && !isDNSNotFound(err) {
			sr.FailReason = err.Error()
			return sr
		}
		for _, ns := range nss {
			answers = append(answers, strings.TrimSuffix(ns.Host, "."))
		}
	default: // A
		addrs, err := resolver.LookupHost(qctx, name)
		if err != nil && !isDNSNotFound(err) {
			sr.FailReason = err.Error()
			return sr
		}
		answers = addrs
	}
	sr.DurationMS = time.Since(stepStart).Milliseconds()
	sr.Status = 1 // 查询完成（含 NXDOMAIN：0 条记录也是可观测结论）
	answerText := strings.Join(answers, "\n")
	sr.RespSnippet = answerText
	if len(sr.RespSnippet) > RespSnippetLen {
		sr.RespSnippet = sr.RespSnippet[:RespSnippetLen]
	}
	if st.Expect != nil {
		if reason := checkDNSExpectation(st.Expect, answerText, len(answers), sr.DurationMS); reason != "" {
			sr.FailReason = reason
			return sr
		}
	}
	sr.OK = true
	return sr
}

// decodeTCPPayload hex 解码步骤 payload（parse 期已校验，此处容错返回 nil）。
func decodeTCPPayload(hexStr string) []byte {
	if strings.TrimSpace(hexStr) == "" {
		return nil
	}
	b, err := hex.DecodeString(strings.TrimSpace(hexStr))
	if err != nil {
		return nil
	}
	return b
}

// isConnRefused 明确的连接拒绝（收到 RST）：端口「关闭」的可观测判据；
// 超时/被过滤不算——那属于「未获观测」，维持 blocked 语义。
func isConnRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}

// isDNSNotFound 权威否定回答（NXDOMAIN/无此主机）：可观测结论而非网络错误。
func isDNSNotFound(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.IsNotFound
	}
	return strings.Contains(strings.ToLower(err.Error()), "no such host")
}

// render 渲染 {{var}}。
func render(text string, vars map[string]string) string {
	if !strings.Contains(text, "{{") {
		return text
	}
	return RenderVars(text, vars)
}
