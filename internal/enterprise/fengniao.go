package enterprise

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/tidwall/gjson"
)

// fengniaoProvider 风鸟（riskbird.com）适配器。端点对照 enscan_go（MIT）
// internal/riskbird 移植：搜索 newSearch、详情 /api/ent/query、
// 列表 companyInfo/list（extractType 区分类型，需要详情返回的 orderNo 而非 entid）。
// Session config：cookie（必填，风鸟网页 Cookie）。
type fengniaoProvider struct {
	c        *webClient
	mu       sync.Mutex
	orderNos map[string]string // entid -> orderNo 缓存（列表接口的记录键）
}

const fnBase = "https://www.riskbird.com"

// NewFengniaoProvider 使用手动粘贴的网页 Cookie（原路径，向后兼容）。
func NewFengniaoProvider(cookie string, proxyURL string) (Provider, error) {
	cookie = strings.TrimSpace(cookie)
	if cookie == "" {
		return nil, SessionMissing("风鸟会话未配置：请在企业数据源中填写 Cookie")
	}
	c, err := newWebClient(fnBase, proxyURL, 15*time.Second)
	if err != nil {
		return nil, err
	}
	c.headers["Cookie"] = cookie
	c.headers["Referer"] = fnBase + "/ent/"
	c.headers["App-Device"] = "WEB"
	c.headers["Content-Type"] = "application/json"
	return &fengniaoProvider{c: c, orderNos: map[string]string{}}, nil
}

// NewFengniaoAccountProvider 账号密码自动登录：POST /api/auth/login，
// 参数 {"mobile":手机号,"password":明文密码,"type":"password"}（前端未加密、密码登录
// 路径无图形验证码——实测假密码直接返回业务错误 8888，不弹验证码）。
// 登录成功后收集 Set-Cookie 作为会话（与手动粘贴 Cookie 等价）。
func NewFengniaoAccountProvider(mobile, password, proxyURL string) (Provider, error) {
	mobile = strings.TrimSpace(mobile)
	if mobile == "" || password == "" {
		return nil, SessionMissing("风鸟会话未配置：请在企业数据源中填写账号与密码")
	}
	c, err := newWebClient(fnBase, proxyURL, 15*time.Second)
	if err != nil {
		return nil, err
	}
	c.headers["Referer"] = fnBase + "/login"
	c.headers["App-Device"] = "WEB"
	c.headers["Content-Type"] = "application/json"
	p := &fengniaoProvider{c: c, orderNos: map[string]string{}}
	if err := p.login(context.Background(), mobile, password); err != nil {
		return nil, err
	}
	return p, nil
}

// login 调用 /api/auth/login 并把 Set-Cookie 注入 webClient（会话复用）。
func (f *fengniaoProvider) login(ctx context.Context, mobile, password string) error {
	body := fmt.Sprintf(`{"mobile":%q,"password":%q,"type":"password"}`, mobile, password)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fnBase+"/api/auth/login", strings.NewReader(body))
	if err != nil {
		return err
	}
	for k, v := range f.c.headers {
		if strings.EqualFold(k, "Cookie") {
			continue
		}
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := f.c.http.Do(req)
	if err != nil {
		return fmt.Errorf("风鸟登录请求失败: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, webBodyLimit))
	raw := string(data)
	// 业务状态：success=true 或 code=20000 视为成功；8888=账号或密码错误
	if !gjson.Get(raw, "success").Bool() && gjson.Get(raw, "code").String() != "20000" {
		msg := gjson.Get(raw, "msg").String()
		if msg == "" {
			msg = raw
		}
		return fmt.Errorf("风鸟登录失败：%s", strings.TrimSpace(msg))
	}
	// 收集 Set-Cookie 会话（与网页登录等价；手动路径没有的 cookie 都在这里补齐）
	cookies := resp.Cookies()
	if len(cookies) == 0 {
		return fmt.Errorf("风鸟登录成功但未下发会话 Cookie")
	}
	parts := make([]string, 0, len(cookies))
	for _, ck := range cookies {
		parts = append(parts, ck.Name+"="+ck.Value)
	}
	f.c.headers["Cookie"] = strings.Join(parts, "; ")
	return nil
}

func (f *fengniaoProvider) Name() string { return "fengniao" }

func (f *fengniaoProvider) rbState(body, successCode string) (gjson.Result, error) {
	if strings.Contains(body, "login") && gjson.Get(body, "code").String() == "40001" {
		return gjson.Result{}, SessionMissing("风鸟 Cookie 已失效，请更新")
	}
	code := gjson.Get(body, "code").String()
	if code != "" && code != successCode {
		return gjson.Result{}, fmt.Errorf("风鸟错误: %s", strings.TrimSpace(gjson.Get(body, "msg").String()))
	}
	return gjson.Get(body, "data"), nil
}

// Search POST /riskbird-api/newSearch → data.list（ENTNAME + entid）。
func (f *fengniaoProvider) Search(ctx context.Context, keyword string, limit int) ([]CompanyRef, error) {
	body := fmt.Sprintf(`{"searchKey":%q,"pageNo":1,"range":10,"referer":"search","queryType":"1","selectConditionData":"{\"status\":\"\",\"sort_field\":\"\"}"}`, keyword)
	resp, err := f.c.postJSON(ctx, fnBase+"/riskbird-api/newSearch", body, map[string]string{"Xs-Content-Type": ""})
	if err != nil {
		return nil, err
	}
	// newSearch 不带 Xs-Content-Type 头（移植自 enscan），清理空 header 由客户端忽略
	data, err := f.rbState(resp, "20000")
	if err != nil {
		return nil, err
	}
	out := []CompanyRef{}
	for _, item := range data.Get("list").Array() {
		id := firstExistingString(item, "entid", "entId", "id")
		name := stripHTML(firstExistingString(item, "ENTNAME", "entName", "name"))
		if id != "" && name != "" {
			out = append(out, CompanyRef{ExtID: id, Name: name})
		}
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("搜索无结果或会话失效（风鸟）")
	}
	return out, nil
}

// Detail GET /api/ent/query?entId= → basicResult.apiData.list.jbxxInfo + orderNo。
func (f *fengniaoProvider) Detail(ctx context.Context, extID string) (*CompanyDetail, error) {
	body, err := f.c.getJSON(ctx, fnBase+"/api/ent/query?entId="+urlQueryEscape(extID), map[string]string{"Xs-Content-Type": "application/json"})
	if err != nil {
		return nil, err
	}
	root := gjson.Parse(body)
	if code := root.Get("code").String(); code != "" && code != "20000" {
		return nil, fmt.Errorf("风鸟错误: %s", strings.TrimSpace(root.Get("msg").String()))
	}
	r := root.Get("basicResult.apiData.list.jbxxInfo")
	orderNo := root.Get("orderNo").String()
	if orderNo != "" {
		f.mu.Lock()
		f.orderNos[extID] = orderNo
		f.mu.Unlock()
	}
	return &CompanyDetail{
		ExtID:       extID,
		Name:        stripHTML(firstExistingString(r, "entName", "ENTNAME")),
		LegalPerson: stripHTML(firstExistingString(r, "personName", "faren")),
		OpenStatus:  stripHTML(firstExistingString(r, "entStatus", "ENTSTATUS")),
		Phone:       strings.TrimSpace(firstExistingString(r, "telList", "tels")),
		Email:       strings.TrimSpace(firstExistingString(r, "emailList", "emails")),
	}, nil
}

// orderNoOf 列表接口需要 orderNo：优先缓存，未命中则现查详情。
func (f *fengniaoProvider) orderNoOf(ctx context.Context, entID string) (string, error) {
	f.mu.Lock()
	orderNo := f.orderNos[entID]
	f.mu.Unlock()
	if orderNo != "" {
		return orderNo, nil
	}
	if _, err := f.Detail(ctx, entID); err != nil {
		return "", err
	}
	f.mu.Lock()
	orderNo = f.orderNos[entID]
	f.mu.Unlock()
	if orderNo == "" {
		return "", fmt.Errorf("风鸟未返回 orderNo，无法查询列表")
	}
	return orderNo, nil
}

// rbList POST /riskbird-api/companyInfo/list（extractType 区分分支/投资/ICP）。
func (f *fengniaoProvider) rbList(ctx context.Context, extractType, extID string, page, size int) (gjson.Result, int64, error) {
	orderNo, err := f.orderNoOf(ctx, extID)
	if err != nil {
		return gjson.Result{}, 0, err
	}
	body := fmt.Sprintf(`{"filterCnd":"1","page":%d,"size":%d,"orderNo":%q,"extractType":%q,"sortField":""}`, page, size, orderNo, extractType)
	resp, err := f.c.postJSON(ctx, fnBase+"/riskbird-api/companyInfo/list", body, map[string]string{"Xs-Content-Type": "application/json"})
	if err != nil {
		return gjson.Result{}, 0, err
	}
	data, err := f.rbState(resp, "20000")
	return data, data.Get("totalCount").Int(), err
}

func (f *fengniaoProvider) Branches(ctx context.Context, extID string, page, size int) ([]CompanyRef, bool, error) {
	data, total, err := f.rbList(ctx, "companyBranch", extID, page, size)
	if err != nil {
		return nil, false, err
	}
	return fnCompanyRefs(data.Get("apiData"), "brName"), int64(page*size) < total && total > 0, nil
}

func (f *fengniaoProvider) Investments(ctx context.Context, extID string, page, size int) ([]CompanyRef, bool, error) {
	data, total, err := f.rbList(ctx, "companyInvest", extID, page, size)
	if err != nil {
		return nil, false, err
	}
	return fnCompanyRefs(data.Get("apiData"), "entName"), int64(page*size) < total && total > 0, nil
}

// Domains ICP 备案：extractType=propertyIcp（webname/hostname/icpnum）。
func (f *fengniaoProvider) Domains(ctx context.Context, extID string, page, size int) ([]DomainHit, bool, error) {
	data, total, err := f.rbList(ctx, "propertyIcp", extID, page, size)
	if err != nil {
		return nil, false, err
	}
	out := []DomainHit{}
	for _, item := range data.Get("apiData").Array() {
		d := normalizeDomain(item.Get("hostname").String())
		if d == "" {
			continue
		}
		out = append(out, DomainHit{Domain: d, Site: item.Get("webname").String(), ICP: item.Get("icpnum").String()})
	}
	return out, int64(page*size) < total && total > 0 && len(out) > 0, nil
}

func fnCompanyRefs(list gjson.Result, nameKey string) []CompanyRef {
	out := []CompanyRef{}
	for _, item := range list.Array() {
		id := firstExistingString(item, "entid", "entId")
		name := stripHTML(firstExistingString(item, nameKey, "entName", "brName"))
		if id != "" && name != "" {
			out = append(out, CompanyRef{ExtID: id, Name: name})
		}
	}
	return out
}
