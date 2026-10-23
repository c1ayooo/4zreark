package enterprise

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tidwall/gjson"
)

// qccProvider 企查查适配器。
//
// 端点（网页 SSR，数据在 window.__INITIAL_STATE__ / companyDetail 内嵌 JSON）：
//   - 搜索：GET /web/search?key=<kw> → search.searchRes.Result[]
//   - 详情：GET /firm/<keyNo>.html → companyDetail{Name,Oper.Name,RegistCapi,Status,...}
//
// 上游对纯 API 端点（/api/...）有 m 参数与字段加密，网页 SSR 路径不做加密，
// 因此这里只走页面解析。Session config：cookie（必填，需含 QCCSESSID + acw_tc）。
type qccProvider struct {
	c     *webClient
	guard *qccGuard // 采集风控：per-host 熔断 + 代理池（见 qcc_resilience.go）
}

const qccBase = "https://www.qcc.com"

func NewQccProvider(cookie string, proxyURL string) (Provider, error) {
	cookie = strings.TrimSpace(cookie)
	if cookie == "" {
		return nil, SessionMissing("企查查会话未配置：请在企业数据源中填写 Cookie（需含 QCCSESSID）")
	}
	c, err := newWebClient(qccBase, proxyURL, 20*time.Second)
	if err != nil {
		return nil, err
	}
	c.headers["Cookie"] = cookie
	c.headers["Referer"] = qccBase + "/"
	c.headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
	// proxyURL 同样支持逗号/换行分隔多代理：交给守卫的代理池轮转（见 qcc_resilience.go）。
	return &qccProvider{c: c, guard: newQccGuard(proxyURL)}, nil
}

func (q *qccProvider) Name() string { return "qcc" }

// 企查查风控极敏感：连续请求十几次就会 412/405 并把出口 IP 拉黑，
// 因此所有请求串行化并保证最小间隔（全局，跨 provider 实例共享）。
const qccMinInterval = 2500 * time.Millisecond

var qccGate struct {
	mu   sync.Mutex
	last time.Time
}

func qccThrottle() {
	qccGate.mu.Lock()
	defer qccGate.mu.Unlock()
	if d := time.Since(qccGate.last); d < qccMinInterval {
		time.Sleep(qccMinInterval - d)
	}
	qccGate.last = time.Now()
}

// get 带限速的 GET，并把风控状态码翻译成可操作的错误。
// 熔断器/代理池/结果回填在 qcc_resilience.go 的 qccGuard.get 中实现。
func (q *qccProvider) get(ctx context.Context, path string) (string, error) {
	return q.guard.get(ctx, q.c, path)
}

// extractBalanced 从 pos 处的 '{' 开始做括号匹配，返回完整 JSON 对象文本。
func extractBalanced(s string, start int) (string, bool) {
	if start < 0 || start >= len(s) || s[start] != '{' {
		return "", false
	}
	depth := 0
	inStr := false
	esc := false
	for i := start; i < len(s); i++ {
		ch := s[i]
		if inStr {
			switch {
			case esc:
				esc = false
			case ch == '\\':
				esc = true
			case ch == '"':
				inStr = false
			}
			continue
		}
		switch ch {
		case '"':
			inStr = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return s[start : i+1], true
			}
		}
	}
	return "", false
}

// initialState 解析页面里 window.__INITIAL_STATE__ 的 JSON。
func initialState(body string) (gjson.Result, error) {
	i := strings.Index(body, "window.__INITIAL_STATE__")
	if i < 0 {
		return gjson.Result{}, fmt.Errorf("页面无状态数据（Cookie 失效或触发企查查风控，请在浏览器完成验证后更新 Cookie）")
	}
	j := strings.IndexAny(body[i:], "{")
	if j < 0 {
		return gjson.Result{}, fmt.Errorf("状态数据格式异常")
	}
	raw, ok := extractBalanced(body, i+j)
	if !ok {
		return gjson.Result{}, fmt.Errorf("状态 JSON 不完整（页面可能被拦截）")
	}
	return gjson.Parse(raw), nil
}

// objectAfter 提取 key 之后紧跟的 JSON 对象（用于 companyDetail）。
func objectAfter(body, key string) (gjson.Result, bool) {
	i := strings.Index(body, key)
	if i < 0 {
		return gjson.Result{}, false
	}
	j := strings.Index(body[i:], "{")
	if j < 0 {
		return gjson.Result{}, false
	}
	raw, ok := extractBalanced(body, i+j)
	if !ok {
		return gjson.Result{}, false
	}
	return gjson.Parse(raw), true
}

func cleanName(s string) string {
	return strings.TrimSpace(stripHTML(s))
}

// Search GET /web/search?key=<kw> → search.searchRes.Result[]（20 条/页）。
func (q *qccProvider) Search(ctx context.Context, keyword string, limit int) ([]CompanyRef, error) {
	body, err := q.get(ctx, "/web/search?key="+url.QueryEscape(keyword))
	if err != nil {
		return nil, err
	}
	st, err := initialState(body)
	if err != nil {
		return nil, err
	}
	res := st.Get("search.searchRes")
	if res.Get("Status").Int() != 200 {
		return nil, fmt.Errorf("企查查搜索失败（Status=%s），会话可能已失效", res.Get("Status").String())
	}
	out := []CompanyRef{}
	for _, it := range res.Get("Result").Array() {
		keyNo := strings.TrimSpace(it.Get("KeyNo").String())
		name := cleanName(it.Get("Name").String())
		if keyNo != "" && name != "" {
			out = append(out, CompanyRef{ExtID: keyNo, Name: name})
		}
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("搜索无结果或会话失效（企查查）")
	}
	return out, nil
}

// Detail GET /firm/<keyNo>.html → companyDetail。
func (q *qccProvider) Detail(ctx context.Context, extID string) (*CompanyDetail, error) {
	extID = strings.TrimSpace(extID)
	if extID == "" {
		return nil, fmt.Errorf("企查查详情需要 keyNo")
	}
	body, err := q.get(ctx, "/firm/"+url.PathEscape(extID)+".html")
	if err != nil {
		return nil, err
	}
	cd, ok := objectAfter(body, `"companyDetail":`)
	if !ok {
		return nil, fmt.Errorf("详情页无 companyDetail（Cookie 失效或需登录/验证）")
	}
	d := &CompanyDetail{
		ExtID:             extID,
		Name:              cleanName(cd.Get("Name").String()),
		LegalPerson:       cleanName(cd.Get("Oper.Name").String()),
		OpenStatus:        cleanName(cd.Get("Status").String()),
		Phone:             cleanName(cd.Get("ContactNumber").String()),
		Email:             cleanName(cd.Get("Email").String()),
		CreditCode:        cleanName(cd.Get("CreditCode").String()),
		Address:           cleanName(cd.Get("Address").String()),
		Industry:          cleanName(cd.Get("Industry.Industry").String()),
		RegisteredCapital: cleanName(cd.Get("RegistCapi").String()),
	}
	if d.Industry == "" {
		d.Industry = cleanName(cd.Get("Industry").String())
	}
	if d.Name == "" {
		return nil, fmt.Errorf("详情页未解析到企业名（页面结构可能变化）")
	}
	return d, nil
}

// Branches 企查查分支列表在独立 tab（/firm/branch_<keyNo>.html），暂未接入。
func (q *qccProvider) Branches(ctx context.Context, extID string, page, size int) ([]CompanyRef, bool, error) {
	return []CompanyRef{}, false, nil
}

// Investments 对外投资同样在独立 tab，暂未接入。
func (q *qccProvider) Investments(ctx context.Context, extID string, page, size int) ([]CompanyRef, bool, error) {
	return []CompanyRef{}, false, nil
}

// Domains ICP 备案在知识产权 tab，暂未接入；采集主路径请用 miit ICP 查询。
func (q *qccProvider) Domains(ctx context.Context, extID string, page, size int) ([]DomainHit, bool, error) {
	return []DomainHit{}, false, nil
}

// ParseCapitalWan 把 "6500万元" / "200万美元" / "1.2亿元" 归一成万元数值。
// 外币按原值返回（不换算汇率），供调用方判断是否需要人工复核。
func ParseCapitalWan(v string) (float64, bool) {
	s := strings.TrimSpace(v)
	if s == "" {
		return 0, false
	}
	// 先剥外币标识（单遍 NewReplacer 不会二次处理，必须分两步）
	body := strings.NewReplacer("美元", "", "港元", "", "港币", "", "欧元", "").Replace(s)
	body = strings.TrimSpace(body)
	mult := 1.0
	switch {
	case strings.Contains(body, "亿"):
		mult = 10000
	case strings.Contains(body, "万"):
		mult = 1
	default:
		mult = 0.0001 // 单位元
	}
	num := strings.NewReplacer("亿", "", "万", "", "元", "", "人民币", "", ",", "", " ", "").Replace(body)
	f, err := strconv.ParseFloat(num, 64)
	if err != nil {
		return 0, false
	}
	return f * mult, true
}
