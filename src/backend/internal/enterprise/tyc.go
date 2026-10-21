package enterprise

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/tidwall/gjson"
)

// tycProvider 天眼查适配器。端点对照 enscan_go（MIT）internal/tianyancha 移植：
// 搜索/列表走 capi.tianyancha.com XHR（需 Cookie + X-Auth-Token + X-Tycid 头），
// 详情走 cloud-other-information baseinfo/web 纯 JSON 接口。
// Session config：cookie（必填，网页版登录态；auth_token/TYCID 自动从 Cookie 提取）。
type tycProvider struct {
	c      *webClient
	authTk string
	tycid  string
}

const tycBase = "https://www.tianyancha.com"
const tycCapiBase = "https://capi.tianyancha.com"

// parseTycAuth 兼容两种登录态粘贴形态，返回 (auth_token, TYCID, 是否保留 Cookie 头)：
//  1. 网页版完整 Cookie 串（auth_token=…; TYCID=…; …）：原样作为 Cookie 头，auth_token/TYCID 自动提取；
//  2. 请求头 X-Auth-Token 的值（x-auth-token <jwt>、x-auth-token=<jwt> 或裸 jwt）：
//     整体作 X-Auth-Token 头，不再设置 Cookie 头（该形态下本无浏览器会话）。
func parseTycAuth(cookie string) (authTk, tycid string, keepCookie bool) {
	cookie = strings.TrimSpace(cookie)
	if v := cookieParam(cookie, "auth_token"); v != "" {
		return v, cookieParam(cookie, "TYCID"), true
	}
	rest := cookie
	if lower := strings.ToLower(rest); strings.HasPrefix(lower, "x-auth-token") {
		rest = strings.TrimSpace(rest[len("x-auth-token"):])
		rest = strings.TrimSpace(strings.TrimPrefix(rest, "="))
	}
	if strings.HasPrefix(rest, "eyJ") { // JWT 头值形态
		return rest, "", false
	}
	return "", "", true
}

func NewTycProvider(cookie string, proxyURL string) (Provider, error) {
	cookie = strings.TrimSpace(cookie)
	if cookie == "" {
		return nil, SessionMissing("天眼查会话未配置：请在企业数据源中填写 Cookie")
	}
	c, err := newWebClient(tycBase, proxyURL, 15*time.Second)
	if err != nil {
		return nil, err
	}
	authTk, tycid, keepCookie := parseTycAuth(cookie)
	c.headers["Referer"] = tycBase + "/"
	c.headers["Origin"] = tycBase
	c.headers["Version"] = "TYC-Web"
	if keepCookie {
		c.headers["Cookie"] = cookie
	}
	return &tycProvider{c: c, authTk: authTk, tycid: tycid}, nil
}

func (t *tycProvider) Name() string { return "tyc" }

// cookieParam 从 Cookie 串取指定键（大小写不敏感）。
func cookieParam(cookie, key string) string {
	for _, part := range strings.Split(cookie, ";") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 && strings.EqualFold(kv[0], key) {
			return kv[1]
		}
	}
	return ""
}

func (t *tycProvider) capiHeaders() map[string]string {
	return map[string]string{"X-Auth-Token": t.authTk, "X-Tycid": t.tycid}
}

// tycState 校验 capi 业务状态（state=ok；mustlogin=会话失效）。
func tycState(body string) (gjson.Result, error) {
	if strings.Contains(body, `"message":"mustlogin"`) || strings.Contains(body, "请输入中国大陆手机号") {
		return gjson.Result{}, SessionMissing("天眼查 Cookie 已失效，请更新")
	}
	state := gjson.Get(body, "state")
	if state.Exists() && state.String() != "ok" {
		return gjson.Result{}, fmt.Errorf("天眼查错误: state=%s", state.String())
	}
	return gjson.Get(body, "data"), nil
}

// Search POST capi cloud-tempest/web/searchCompanyV4 → data.companyList。
func (t *tycProvider) Search(ctx context.Context, keyword string, limit int) ([]CompanyRef, error) {
	body := fmt.Sprintf(`{"key":%q,"pageNum":1,"pageSize":20,"referer":"search","sortType":"0","word":%q}`, keyword, keyword)
	resp, err := t.c.postJSON(ctx, tycCapiBase+"/cloud-tempest/web/searchCompanyV4", body, t.capiHeaders())
	if err != nil {
		return nil, err
	}
	data, err := tycState(resp)
	if err != nil {
		return nil, err
	}
	cleaned := strings.NewReplacer("<em>", "", "</em>", "").Replace(data.Raw)
	out := []CompanyRef{}
	for _, item := range gjson.Get(cleaned, "companyList").Array() {
		id := firstExistingString(item, "id", "graphId")
		name := stripHTML(firstExistingString(item, "name", "entName"))
		if id != "" && name != "" {
			out = append(out, CompanyRef{ExtID: id, Name: name})
		}
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("搜索无结果或会话失效（天眼查，可能触发验证）")
	}
	return out, nil
}

// Detail GET capi cloud-other-information/companyinfo/baseinfo/web?id= → data。
// 失败不致命：仅缺字段，实体仍可入树。
func (t *tycProvider) Detail(ctx context.Context, extID string) (*CompanyDetail, error) {
	uri := tycCapiBase + "/cloud-other-information/companyinfo/baseinfo/web?id=" + url.QueryEscape(extID) + "&_=" + strconv.FormatInt(time.Now().Unix(), 10)
	body, err := t.c.getJSON(ctx, uri, t.capiHeaders())
	if err != nil {
		return nil, err
	}
	data, err := tycState(body)
	if err != nil {
		return &CompanyDetail{ExtID: extID}, nil
	}
	return &CompanyDetail{
		ExtID:       extID,
		Name:        stripHTML(firstExistingString(data, "name", "entName")),
		LegalPerson: stripHTML(firstExistingString(data, "legalPersonName", "legalPerson")),
		OpenStatus:  stripHTML(firstExistingString(data, "openStatus", "entStatus")),
		Phone:       strings.TrimSpace(firstExistingString(data, "phoneNumber", "telephone")),
		Email:       strings.TrimSpace(firstExistingString(data, "email")),
	}, nil
}

// tycList GET 列表：graphId/id/gid 三参数 + 分页 → data.{rf}，total 多路径。
func (t *tycProvider) tycList(ctx context.Context, path, rf, extID string, page, size int) (gjson.Result, int64, error) {
	uri := fmt.Sprintf("%s%s?_=%d&pageSize=%d&graphId=%s&id=%s&gid=%s&pageNum=%d",
		tycCapiBase, path, time.Now().Unix(), size, extID, extID, extID, page)
	body, err := t.c.getJSON(ctx, uri, t.capiHeaders())
	if err != nil {
		return gjson.Result{}, 0, err
	}
	data, err := tycState(body)
	if err != nil {
		return gjson.Result{}, 0, err
	}
	total := int64(0)
	for _, k := range []string{"itemTotal", "count", "total", "pageBean.total"} {
		if v := data.Get(k); v.Exists() && v.Int() > 0 {
			total = v.Int()
		}
	}
	return data.Get(rf), total, nil
}

func (t *tycProvider) Branches(ctx context.Context, extID string, page, size int) ([]CompanyRef, bool, error) {
	list, total, err := t.tycList(ctx, "/cloud-company-background/company/branchList", "result", extID, page, size)
	if err != nil {
		return nil, false, err
	}
	return tycCompanyRefs(list), int64(page*size) < total && total > 0, nil
}

func (t *tycProvider) Investments(ctx context.Context, extID string, page, size int) ([]CompanyRef, bool, error) {
	// investListV2 走 POST JSON（固定参数移植自 enscan SData）
	uri := tycCapiBase + "/cloud-company-background/company/investListV2?_=" + strconv.FormatInt(time.Now().Unix(), 10)
	body := fmt.Sprintf(`{"gid":%q,"pageSize":%d,"pageNum":%d,"category":"-100","percentLevel":"-100","province":"-100"}`, extID, size, page)
	resp, err := t.c.postJSON(ctx, uri, body, t.capiHeaders())
	if err != nil {
		return nil, false, err
	}
	data, err := tycState(resp)
	if err != nil {
		return nil, false, err
	}
	total := data.Get("total").Int()
	if total == 0 {
		total = data.Get("pageBean.total").Int()
	}
	return tycCompanyRefs(data.Get("result")), int64(page*size) < total && total > 0, nil
}

// Domains ICP 备案：cloud-intellectual-property/intellectualProperty/icpRecordList → data.item。
func (t *tycProvider) Domains(ctx context.Context, extID string, page, size int) ([]DomainHit, bool, error) {
	list, total, err := t.tycList(ctx, "/cloud-intellectual-property/intellectualProperty/icpRecordList", "item", extID, page, size)
	if err != nil {
		return nil, false, err
	}
	out := []DomainHit{}
	for _, item := range list.Array() {
		d := normalizeDomain(firstExistingString(item, "domain", "ym", "homeSite", "webSite"))
		if d == "" {
			continue
		}
		out = append(out, DomainHit{
			Domain: d,
			Site:   firstExistingString(item, "webName", "siteName", "webSiteName"),
			ICP:    firstExistingString(item, "icpNo", "icp", "impNumber"),
		})
	}
	return out, int64(page*size) < total && total > 0 && len(out) > 0, nil
}

func tycCompanyRefs(list gjson.Result) []CompanyRef {
	out := []CompanyRef{}
	for _, item := range list.Array() {
		id := firstExistingString(item, "id", "graphId", "pid")
		name := stripHTML(firstExistingString(item, "name", "entName", "branchName"))
		if id != "" && name != "" {
			out = append(out, CompanyRef{ExtID: id, Name: name})
		}
	}
	return out
}
