package enterprise

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/tidwall/gjson"
)

// kuaichaProvider 快查（kuaicha365.com）适配器。端点对照 enscan_go（MIT）
// internal/kuaicha 移植：搜索 company_search_pc、详情 basic/info、
// 分支/投资 open/app/v1/pc_enterprise/*。Session config：cookie（必填）。
type kuaichaProvider struct {
	c *webClient
}

const kcBase = "https://www.kuaicha365.com"

func NewKuaichaProvider(cookie string, proxyURL string) (Provider, error) {
	cookie = strings.TrimSpace(cookie)
	if cookie == "" {
		return nil, SessionMissing("快查会话未配置：请在企业数据源中填写 Cookie")
	}
	c, err := newWebClient(kcBase, proxyURL, 15*time.Second)
	if err != nil {
		return nil, err
	}
	c.headers["Cookie"] = cookie
	c.headers["Referer"] = kcBase + "/search-result?"
	c.headers["Source"] = "PC"
	return &kuaichaProvider{c: c}, nil
}

func (k *kuaichaProvider) Name() string { return "kuaicha" }

// kcState 校验业务状态（快查 data 包裹；401/302 由客户端层报 HTTP 错误）。
func kcState(body string) (gjson.Result, error) {
	if strings.Contains(body, "请登录") || strings.Contains(body, "请重新登录") {
		return gjson.Result{}, SessionMissing("快查 Cookie 已失效，请更新")
	}
	data := gjson.Get(body, "data")
	if !data.Exists() {
		return gjson.Result{}, fmt.Errorf("响应缺少 data 字段（快查会话可能过期）")
	}
	return data, nil
}

// Search POST /enterprise_info_app/V1/search/company_search_pc → data.list。
func (k *kuaichaProvider) Search(ctx context.Context, keyword string, limit int) ([]CompanyRef, error) {
	body := fmt.Sprintf(`{"search_conditions":[],"keyword":%q,"page":1,"page_size":20}`, keyword)
	resp, err := k.c.postJSON(ctx, kcBase+"/enterprise_info_app/V1/search/company_search_pc", body, nil)
	if err != nil {
		return nil, err
	}
	cleaned := strings.NewReplacer("<em>", "", "</em>", "").Replace(resp)
	data, err := kcState(cleaned)
	if err != nil {
		return nil, err
	}
	out := []CompanyRef{}
	for _, item := range data.Get("list").Array() {
		id := firstExistingString(item, "org_id", "orgId", "id")
		name := stripHTML(firstExistingString(item, "name", "entName", "companyName", "org_name"))
		if id != "" && name != "" {
			out = append(out, CompanyRef{ExtID: id, Name: name})
		}
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("搜索无结果或会话失效（快查）")
	}
	return out, nil
}

// Detail GET /open/app/v1/pc_enterprise/basic/info?org_id= → data。
func (k *kuaichaProvider) Detail(ctx context.Context, extID string) (*CompanyDetail, error) {
	body, err := k.c.getJSON(ctx, kcBase+"/open/app/v1/pc_enterprise/basic/info?org_id="+urlQueryEscape(extID), nil)
	if err != nil {
		return nil, err
	}
	data, err := kcState(body)
	if err != nil {
		return &CompanyDetail{ExtID: extID}, nil
	}
	return &CompanyDetail{
		ExtID:       extID,
		Name:        stripHTML(firstExistingString(data, "name", "org_name")),
		LegalPerson: stripHTML(firstExistingString(data, "legal_person", "frName")),
		OpenStatus:  stripHTML(firstExistingString(data, "state", "openStatus")),
		Phone:       strings.TrimSpace(firstExistingString(data, "telphone", "telephone")),
		Email:       strings.TrimSpace(firstExistingString(data, "email")),
	}, nil
}

// kcList GET open 列表：open/app/v1 路径用 page_size+org_id。
func (k *kuaichaProvider) kcList(ctx context.Context, path, extID string, page, size int, extraQuery string) (gjson.Result, bool, error) {
	uri := fmt.Sprintf("%s%s?page_size=%d&org_id=%s&page=%d%s", kcBase, path, size, urlQueryEscape(extID), page, extraQuery)
	body, err := k.c.getJSON(ctx, uri, nil)
	if err != nil {
		return gjson.Result{}, false, err
	}
	data, err := kcState(body)
	if err != nil {
		return gjson.Result{}, false, err
	}
	return data, data.Get("next_page").Bool(), nil
}

func (k *kuaichaProvider) Branches(ctx context.Context, extID string, page, size int) ([]CompanyRef, bool, error) {
	data, more, err := k.kcList(ctx, "/open/app/v1/pc_enterprise/branch_office/list", extID, page, size, "")
	if err != nil {
		return nil, false, err
	}
	return kcCompanyRefs(data.Get("list"), "org_name", "org_id"), more, nil
}

func (k *kuaichaProvider) Investments(ctx context.Context, extID string, page, size int) ([]CompanyRef, bool, error) {
	data, more, err := k.kcList(ctx, "/open/app/v1/pc_enterprise/invest_abroad/list", extID, page, size, "&is_latest=1")
	if err != nil {
		return nil, false, err
	}
	return kcCompanyRefs(data.Get("list"), "frgn_invest_corp_name", "frgn_invest_corp_id"), more, nil
}

// Domains 快查 ICP 接口 enscan 中亦未启用（注释状态），待平台开放后接入。
func (k *kuaichaProvider) Domains(ctx context.Context, extID string, page, size int) ([]DomainHit, bool, error) {
	return nil, false, fmt.Errorf("快查 ICP 备案接口未开放（enscan 同样未启用），请使用爱企查/天眼查采集域名")
}

func kcCompanyRefs(list gjson.Result, nameKey, idKey string) []CompanyRef {
	out := []CompanyRef{}
	for _, item := range list.Array() {
		id := firstExistingString(item, idKey, "org_id", "id")
		name := stripHTML(firstExistingString(item, nameKey, "name", "entName"))
		if id != "" && name != "" {
			out = append(out, CompanyRef{ExtID: id, Name: name})
		}
	}
	return out
}
