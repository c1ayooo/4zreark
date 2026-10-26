package enterprise

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
	"github.com/tidwall/gjson"
)

// 小蓝本浏览器签名通道（Go 内嵌 rod，替代外部 Node/Playwright 进程）。
//
// 背景：小蓝本业务接口（bluebook 网关）服务端强校验 h_sign 动态签名（绑定时间戳+
// 会话密钥，混淆于前端 webpack 闭包），纯服务端 HTTP 无法复现。前端页面加载时由
// xlbsiren 混淆脚本 hook XMLHttpRequest，页面内 XHR 会自动注入合法 h_sign。
//
// 实现：登录接口（xiaolanben.go）取 token + login-id，CDP 种 cookie 到 .xiaolanben.com
// 域；打开 sou.xiaolanben.com 企业查询应用作为签名上下文；页面内原生 XHR 查询走
// 前端 hook 自动签名。浏览器会话进程级缓存复用，登录态失效自动重登。
//
// 关键坑：必须 headless=old——新版 headless 被上游风控识别（验签 403），old 模式
// 签名注入正常（实测 403→401/200）。这是上游防爬检测，不是偶发网络问题。

var xlbRodMu sync.Mutex
var xlbRodLogged = false
var xlbRodPage *rod.Page
var xlbRodBrowser *rod.Browser

// xlbOpMu 全部页面级操作（导航/XHR/截图）共用一把锁：签名通道是进程级单页，
// 深度采集 BFS 与手工检索并发时会互相取消在途导航（实测 -32000 navigated or closed）。
// 串行化之后同源操作排队执行；不同 provider 不受影响。
var xlbOpMu sync.Mutex

// lockXlbOp 取操作锁并返回释放函数。
func lockXlbOp() func() {
	xlbOpMu.Lock()
	return func() { xlbOpMu.Unlock() }
}

// osStat 供测试替换。
var osStat = os.Stat

// queryBlocked 无 Chrome 环境时的兜底。
func (p *xiaolanbenProvider) queryBlocked(kind string) error {
	return fmt.Errorf("小蓝本%s接口受上游 h_sign 动态签名保护，且本机未找到 chrome/chromium，无法提供浏览器签名通道；请安装 Chrome 或改用天眼查/爱企查等已接入数据源完成企业关系收集", kind)
}

// xlbChromeBin 探测本机 Chrome（与 webrender.FindChrome 同序）。
func (p *xiaolanbenProvider) xlbChromeBin() string {
	candidates := []string{
		"/usr/bin/google-chrome", "/usr/bin/google-chrome-stable",
		"/usr/bin/chromium",
		"/home/c1ay/.local/bin/google-chrome",
		"/root/.cache/ms-playwright/chromium-1223/chrome-linux64/chrome",
		"/usr/bin/chromium-browser",
	}
	for _, c := range candidates {
		if _, err := osStat(c); err == nil {
			return c
		}
	}
	return ""
}

// xlbSignPage 返回已登录的 sou 查询页（进程级缓存复用）。
func (p *xiaolanbenProvider) xlbSignPage(ctx context.Context) (*rod.Page, error) {
	// 惰性登录：构造时不调上游，首次查询/登录态失效时从这里登录取 token。
	if p.token == "" {
		if err := p.login(ctx, p.username, p.password); err != nil {
			return nil, err
		}
	}
	xlbRodMu.Lock()
	defer xlbRodMu.Unlock()
	if xlbRodLogged && xlbRodPage != nil {
		if info, err := xlbRodPage.Info(); err == nil && strings.Contains(info.URL, "xiaolanben.com") {
			return xlbRodPage, nil
		}
		p.resetRodLocked()
	}

	bin := p.xlbChromeBin()
	if bin == "" {
		return nil, fmt.Errorf("未找到 chrome/chromium，小蓝本浏览器签名通道不可用")
	}
	l := launcher.New().Bin(bin).Set("no-sandbox").Set("disable-gpu").Set("ignore-certificate-errors").
		Set("disable-blink-features", "AutomationControlled").Set("headless", "old")
	if pp := strings.TrimSpace(p.proxyURL); pp != "" {
		l = l.Proxy(pp)
	} else {
		l = l.Set("no-proxy-server") // 平台进程可能被注入 HTTP(S)_PROXY，Chrome 继承后 sou 超时
	}
	u, err := l.Launch()
	if err != nil {
		return nil, fmt.Errorf("小蓝本浏览器启动失败: %w", err)
	}
	browser := rod.New().ControlURL(u)
	if err := browser.Connect(); err != nil {
		return nil, fmt.Errorf("小蓝本浏览器连接失败: %w", err)
	}
	page, err := browser.Page(proto.TargetCreateTarget{URL: "https://sou.xiaolanben.com/"})
	if err != nil {
		_ = browser.Close()
		return nil, fmt.Errorf("小蓝本查询页打开失败: %w", err)
	}
	page.Timeout(30 * time.Second).MustSetUserAgent(&proto.NetworkSetUserAgentOverride{UserAgent: xlbUA})
	if err := page.WaitLoad(); err != nil {
		_ = browser.Close()
		return nil, fmt.Errorf("小蓝本查询页加载失败: %w", err)
	}
	time.Sleep(1500 * time.Millisecond)

	// CDP 种登录 cookie（token 非 HttpOnly、login-id HttpOnly、userId 双写）
	if p.token == "" {
		return nil, fmt.Errorf("小蓝本登录态未就绪（构造时登录失败）")
	}
	cookies := []proto.NetworkSetCookie{
		{Name: "token", Value: p.token, Domain: ".xiaolanben.com", Path: "/"},
		{Name: "userId", Value: p.userID, Domain: ".xiaolanben.com", Path: "/"},
		{Name: "user-id", Value: p.userID, Domain: ".xiaolanben.com", Path: "/"},
	}
	if p.loginID != "" {
		cookies = append(cookies, proto.NetworkSetCookie{Name: "login-id", Value: p.loginID, Domain: ".xiaolanben.com", Path: "/", HTTPOnly: true})
	}
	for _, c := range cookies {
		if _, err := c.Call(page); err != nil {
			_ = browser.Close()
			return nil, fmt.Errorf("小蓝本登录态注入失败(%s): %w", c.Name, err)
		}
	}
	// 重导航让前端读取新 cookie 并初始化签名上下文
	_ = page.Navigate("https://sou.xiaolanben.com/")
	_ = page.WaitLoad()
	time.Sleep(2500 * time.Millisecond)

	xlbRodBrowser = browser
	xlbRodPage = page
	xlbRodLogged = true
	return page, nil
}

func (p *xiaolanbenProvider) resetRodLocked() {
	if xlbRodPage != nil {
		_ = xlbRodPage.Close()
	}
	if xlbRodBrowser != nil {
		_ = xlbRodBrowser.Close()
	}
	xlbRodPage = nil
	xlbRodBrowser = nil
	xlbRodLogged = false
}

// xlbFetchInPage 页面内 XHR（前端 hook 自动注入 h_sign）。401/403 时自动重登一次。
func (p *xiaolanbenProvider) xlbFetchInPage(ctx context.Context, path string) (string, error) {
	body, st, err := p.xlbFetchOnce(ctx, path)
	if (st == 401 || st == 403) && err != nil {
		xlbRodMu.Lock()
		p.resetRodLocked()
		xlbRodMu.Unlock()
		body, st, err = p.xlbFetchOnce(ctx, path)
	}
	if err != nil {
		return "", err
	}
	return body, nil
}

func (p *xiaolanbenProvider) xlbFetchOnce(ctx context.Context, path string) (string, int, error) {
	defer lockXlbOp()()
	page, err := p.xlbSignPage(ctx)
	if err != nil {
		return "", 0, err
	}
	code := `(p) => new Promise((resolve) => {
		const c = document.cookie;
		const tk = (c.match(/(?:^|;\s*)token=([^;]+)/)||[])[1];
		const uid = (c.match(/(?:^|;\s*)userId=([^;]+)/)||[])[1] || (c.match(/(?:^|;\s*)user-id=([^;]+)/)||[])[1];
		const xhr = new XMLHttpRequest();
		xhr.open('GET', p);
		if (tk) xhr.setRequestHeader('Authorization', 'encrypt ' + tk);
		if (uid) xhr.setRequestHeader('userId', uid);
		xhr.onload = () => resolve(JSON.stringify({ st: xhr.status, body: xhr.responseText }));
		xhr.onerror = () => resolve(JSON.stringify({ st: 0, body: '' }));
		xhr.send();
	})`
	res, err := page.Eval(code, path)
	if err != nil {
		return "", 0, fmt.Errorf("页面内请求失败: %w", err)
	}
	var out struct {
		St   int    `json:"st"`
		Body string `json:"body"`
	}
	if err := json.Unmarshal([]byte(res.Value.String()), &out); err != nil {
		return "", 0, err
	}
	if out.St == 0 {
		return "", 0, fmt.Errorf("小蓝本网络请求失败")
	}
	if out.St == 401 {
		return "", out.St, fmt.Errorf("小蓝本登录态失效")
	}
	if out.St == 403 {
		return "", out.St, fmt.Errorf("小蓝本验签失败（登录态异常）")
	}
	return out.Body, out.St, nil
}

// ── Provider 接口实现 ──

func (p *xiaolanbenProvider) Search(ctx context.Context, keyword string, limit int) ([]CompanyRef, error) {
	if p.xlbChromeBin() == "" {
		return nil, p.queryBlocked("搜索")
	}
	api := "/api.xiaolanben.com/bluebook/api/v1/es/queryByKeyword?keyword=" + urlQueryEscape(keyword) + "&pageId=1&pageSize=20"
	body, err := p.xlbFetchInPage(ctx, api)
	if err != nil {
		return nil, err
	}
	out := []CompanyRef{}
	seen := map[string]bool{}
	for _, it := range gjson.Parse(body).Get("persons").Array() {
		name := stripHTML(it.Get("company").String())
		eid := it.Get("eid").String()
		if name != "" && eid != "" && !seen[eid] {
			seen[eid] = true
			out = append(out, CompanyRef{ExtID: eid, Name: name})
		}
	}
	for _, it := range gjson.Parse(body).Get("companys.companys").Array() {
		name := stripHTML(it.Get("companyName").String())
		eid := it.Get("eid").String()
		if name != "" && eid != "" && !seen[eid] {
			seen[eid] = true
			out = append(out, CompanyRef{ExtID: eid, Name: name})
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("小蓝本搜索无结果")
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (p *xiaolanbenProvider) Detail(ctx context.Context, extID string) (*CompanyDetail, error) {
	if p.xlbChromeBin() == "" {
		return nil, p.queryBlocked("详情")
	}
	return p.xlbDetail(ctx, extID)
}

func (p *xiaolanbenProvider) Branches(ctx context.Context, extID string, page, size int) ([]CompanyRef, bool, error) {
	if p.xlbChromeBin() == "" {
		return nil, false, p.queryBlocked("分支机构")
	}
	return p.xlbCompanyList(ctx, extID, "investments", page, size)
}

func (p *xiaolanbenProvider) Investments(ctx context.Context, extID string, page, size int) ([]CompanyRef, bool, error) {
	if p.xlbChromeBin() == "" {
		return nil, false, p.queryBlocked("对外投资")
	}
	return p.xlbCompanyList(ctx, extID, "investments", page, size)
}

// GroupCompanies 集团成员（同集团兄弟公司，groupCompanies 数组）。
func (p *xiaolanbenProvider) GroupCompanies(ctx context.Context, extID string, page, size int) ([]CompanyRef, bool, error) {
	if p.xlbChromeBin() == "" {
		return nil, false, p.queryBlocked("集团成员")
	}
	return p.xlbCompanyList(ctx, extID, "groupCompanies", page, size)
}

func (p *xiaolanbenProvider) Domains(ctx context.Context, extID string, page, size int) ([]DomainHit, bool, error) {
	if p.xlbChromeBin() == "" {
		return nil, false, p.queryBlocked("关联域名")
	}
	return p.xlbDomains(ctx, extID, page, size)
}

// xlbDetail 详情：导航详情页，从 __INITIAL_STATE__.companyDetail 提取。
func (p *xiaolanbenProvider) xlbDetail(ctx context.Context, extID string) (*CompanyDetail, error) {
	defer lockXlbOp()()
	page, err := p.xlbSignPage(ctx)
	if err != nil {
		return nil, err
	}
	detailURL := "https://sou.xiaolanben.com/company/" + extID
	if err := page.Navigate(detailURL); err != nil {
		return nil, fmt.Errorf("小蓝本详情页导航失败: %w", err)
	}
	_ = page.WaitLoad()
	time.Sleep(2500 * time.Millisecond) // SSR 数据渲染
	res, err := page.Eval(`() => {
		const s = window.__INITIAL_STATE__ || {};
		const cd = s.companyDetail || {};
		const bi = cd.basicInfo || {};
		const inv = Array.isArray(cd.investments) ? cd.investments : [];
		const ws = Array.isArray(cd.webSites) ? cd.webSites : [];
		const extra = [];
		if (bi.website) extra.push(bi.website);
		if (bi.dom && /^[a-zA-Z0-9][a-zA-Z0-9-]*(\.[a-zA-Z0-9][a-zA-Z0-9-]*)+$/.test(String(bi.dom)) && bi.dom !== bi.website) extra.push(bi.dom);
		const phones = Array.isArray(bi.phones) ? bi.phones : [];
		// 全字段 String 强转：上游字段类型不稳定（openStatus 实测出现过数字型状态码），
		// Go 端解析目标全是 string。
		const str = (v) => v === undefined || v === null ? '' : String(v);
		return JSON.stringify({
			name: str(bi.companyName || bi.name || ''),
			legalPerson: str(bi.realBossName || bi.legalPersonName || ''),
			openStatus: str(bi.companyStatusName || bi.statusTag || ''),
			phone: str(phones[0] || bi.phoneNumber || ''),
			email: str(bi.email || ''),
			websites: ws.map(x => str(x.domain || x.url || x.website || '')).filter(Boolean).concat(extra),
			investments: inv.map(x => ({ n: x.name || x.entName || '', eid: x.eid || x.id || '' })),
		});
	}`)
	if err != nil {
		return nil, fmt.Errorf("小蓝本详情提取失败: %w", err)
	}
	var d struct {
		Name        string   `json:"name"`
		LegalPerson string   `json:"legalPerson"`
		OpenStatus  string   `json:"openStatus"`
		Phone       string   `json:"phone"`
		Email       string   `json:"email"`
		Websites    []string `json:"websites"`
	}
	if err := json.Unmarshal([]byte(res.Value.String()), &d); err != nil {
		return nil, fmt.Errorf("小蓝本详情解析失败: %w", err)
	}
	detail := &CompanyDetail{ExtID: extID, Name: d.Name, LegalPerson: d.LegalPerson,
		OpenStatus: d.OpenStatus, Phone: d.Phone, Email: d.Email}
	for _, w := range d.Websites {
		nd := normalizeDomain(w)
		if nd == "" {
			continue
		}
		detail.Domains = append(detail.Domains, DomainHit{Domain: nd, Site: "小蓝本官网", Evidence: "小蓝本企业详情 webSites"})
	}
	return detail, nil
}

// xlbCompanyList 详情页企业列表（listKey：investments=分支/投资、groupCompanies=集团成员）。
func (p *xiaolanbenProvider) xlbCompanyList(ctx context.Context, extID, listKey string, pageNum, size int) ([]CompanyRef, bool, error) {
	defer lockXlbOp()()
	page, err := p.xlbSignPage(ctx)
	if err != nil {
		return nil, false, err
	}
	detailURL := "https://sou.xiaolanben.com/company/" + extID
	if err := page.Navigate(detailURL); err != nil {
		return nil, false, fmt.Errorf("小蓝本子公司页导航失败: %w", err)
	}
	_ = page.WaitLoad()
	time.Sleep(2500 * time.Millisecond) // SSR 数据渲染
	res, err := page.Eval(`(key) => {
		const s = window.__INITIAL_STATE__ || {};
		const cd = s.companyDetail || {};
		const arr = Array.isArray(cd[key]) ? cd[key] : [];
		return JSON.stringify(arr.map(x => ({ n: x.companyName || x.name || x.entName || x.shortName || '', eid: x.eid || x.id || '' })));
	}`, listKey)
	if err != nil {
		return nil, false, fmt.Errorf("小蓝本子公司提取失败: %w", err)
	}
	var items []struct {
		N   string `json:"n"`
		Eid string `json:"eid"`
	}
	if err := json.Unmarshal([]byte(res.Value.String()), &items); err != nil {
		return nil, false, err
	}
	start := (pageNum - 1) * size
	out := []CompanyRef{}
	for i, it := range items {
		if i < start {
			continue
		}
		if len(out) >= size {
			break
		}
		if it.N != "" && it.Eid != "" {
			out = append(out, CompanyRef{ExtID: it.Eid, Name: it.N})
		}
	}
	return out, start+size < len(items), nil
}

// xlbDomains 关联域名（详情页 webSites）。
func (p *xiaolanbenProvider) xlbDomains(ctx context.Context, extID string, pageNum, size int) ([]DomainHit, bool, error) {
	detail, err := p.xlbDetail(ctx, extID)
	if err != nil {
		return nil, false, err
	}
	start := (pageNum - 1) * size
	out := []DomainHit{}
	for i, d := range detail.Domains {
		if i < start {
			continue
		}
		if len(out) >= size {
			break
		}
		out = append(out, d)
	}
	return out, start+size < len(detail.Domains), nil
}
