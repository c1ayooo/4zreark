package enterprise

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/tidwall/gjson"
)

// aqcProvider 爱企查适配器。端点与解析逻辑对照 enscan_go（MIT）internal/aiqicha 移植：
// 搜索 advanceFilterAjax（pid 需按 ddw 反混淆）、详情 basicAllDataAjax、
// 分支/投资/ICP 列表 detail/*ajax。Session config：cookie（必填）。
type aqcProvider struct {
	c *webClient
}

const aqcBase = "https://aiqicha.baidu.com"

func NewAqcProvider(cookie string, proxyURL string) (Provider, error) {
	cookie = strings.TrimSpace(cookie)
	if cookie == "" {
		return nil, SessionMissing("爱企查会话未配置：请在企业数据源中填写 Cookie")
	}
	c, err := newWebClient(aqcBase, proxyURL, 15*time.Second)
	if err != nil {
		return nil, err
	}
	c.headers["Cookie"] = cookie
	c.headers["Referer"] = aqcBase + "/"
	return &aqcProvider{c: c}, nil
}

func (a *aqcProvider) Name() string { return "aqc" }

// checkAPI 校验业务状态（status=0 成功）；"百度安全验证" 表示 Cookie 失效/触发风控。
func checkAPI(body string) (gjson.Result, error) {
	if strings.Contains(body, "百度安全验证") {
		return gjson.Result{}, fmt.Errorf("爱企查触发安全验证，请在浏览器完成验证或更新 Cookie")
	}
	r := gjson.Get(body, "status")
	if !r.Exists() {
		return gjson.Result{}, fmt.Errorf("响应不是有效业务 JSON（会话可能过期）")
	}
	if r.Int() != 0 {
		return gjson.Result{}, fmt.Errorf("上游错误: %s", strings.TrimSpace(gjson.Get(body, "message").String()))
	}
	return gjson.Get(body, "data"), nil
}

// Search GET /s/advanceFilterAjax → data.resultList（item: pid 反混淆 + entName）。
func (a *aqcProvider) Search(ctx context.Context, keyword string, limit int) ([]CompanyRef, error) {
	body, err := a.c.getJSON(ctx, "/s/advanceFilterAjax?q="+url.QueryEscape(keyword)+"&p=1&s=10&f={}", nil)
	if err != nil {
		return nil, err
	}
	data, err := checkAPI(body)
	if err != nil {
		return nil, err
	}
	ddw := gjson.Get(body, "ddw").Int()
	cleaned := strings.NewReplacer("<em>", "", "</em>", "").Replace(data.Raw)
	out := []CompanyRef{}
	for _, item := range gjson.Get(cleaned, "resultList").Array() {
		pid := transformAqcPID(item.Get("pid").String(), ddw)
		name := stripHTML(item.Get("entName").String())
		if pid != "" && name != "" {
			out = append(out, CompanyRef{ExtID: pid, Name: name})
		}
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("搜索无结果或会话失效（爱企查）")
	}
	return out, nil
}

// transformAqcPID 爱企查搜索接口返回的 pid 是混淆数字：按响应中的 ddw 选择
// 数字置换表还原（ddw=1/2 两张表，其余值原样返回）。移植自 enscan_go transformNumber。
func transformAqcPID(input string, t int64) string {
	var codes map[rune]rune
	switch t {
	case 1:
		codes = map[rune]rune{'0': '0', '1': '1', '2': '2', '3': '3', '4': '5', '5': '4', '6': '7', '7': '6', '8': '9', '9': '8'}
	case 2:
		codes = map[rune]rune{'0': '0', '1': '1', '2': '2', '3': '3', '4': '6', '5': '8', '6': '9', '7': '4', '8': '5', '9': '7'}
	default:
		return input
	}
	var b strings.Builder
	for _, r := range input {
		if mapped, ok := codes[r]; ok {
			b.WriteRune(mapped)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Detail GET /detail/basicAllDataAjax → data.basicData。
func (a *aqcProvider) Detail(ctx context.Context, extID string) (*CompanyDetail, error) {
	body, err := a.c.getJSON(ctx, "/detail/basicAllDataAjax?pid="+url.QueryEscape(extID), nil)
	if err != nil {
		return nil, err
	}
	data, err := checkAPI(body)
	if err != nil {
		return nil, err
	}
	r := data.Get("basicData")
	return &CompanyDetail{
		ExtID:       extID,
		Name:        stripHTML(r.Get("entName").String()),
		LegalPerson: stripHTML(r.Get("legalPerson").String()),
		OpenStatus:  stripHTML(r.Get("openStatus").String()),
		Phone:       strings.TrimSpace(r.Get("telephone").String()),
		Email:       strings.TrimSpace(r.Get("email").String()),
	}, nil
}

// listPage GET /{path}?size=10&pid={id}&p={page} → data.list（entName+pid 字段）。
// 满页且有数据则认为可能有下一页（翻页上限由采集器控制）。
func (a *aqcProvider) listPage(ctx context.Context, path, extID string, page, size int) ([]CompanyRef, bool, error) {
	body, err := a.c.getJSON(ctx, fmt.Sprintf("/%s?size=%d&pid=%s&p=%d", path, size, url.QueryEscape(extID), page), nil)
	if err != nil {
		return nil, false, err
	}
	data, err := checkAPI(body)
	if err != nil {
		return nil, false, err
	}
	out := []CompanyRef{}
	for _, item := range data.Get("list").Array() {
		name := stripHTML(item.Get("entName").String())
		pid := item.Get("pid").String()
		if pid != "" && name != "" {
			out = append(out, CompanyRef{ExtID: pid, Name: name})
		}
	}
	return out, len(out) >= size, nil
}

func (a *aqcProvider) Branches(ctx context.Context, extID string, page, size int) ([]CompanyRef, bool, error) {
	return a.listPage(ctx, "detail/branchajax", extID, page, size)
}

func (a *aqcProvider) Investments(ctx context.Context, extID string, page, size int) ([]CompanyRef, bool, error) {
	return a.listPage(ctx, "detail/investajax", extID, page, size)
}

// Domains ICP 备案：detail/icpinfoAjax → data.list（domain 为数组字段）。
func (a *aqcProvider) Domains(ctx context.Context, extID string, page, size int) ([]DomainHit, bool, error) {
	body, err := a.c.getJSON(ctx, fmt.Sprintf("/detail/icpinfoAjax?size=%d&pid=%s&p=%d", size, url.QueryEscape(extID), page), nil)
	if err != nil {
		return nil, false, err
	}
	data, err := checkAPI(body)
	if err != nil {
		return nil, false, err
	}
	out := []DomainHit{}
	for _, item := range data.Get("list").Array() {
		site := item.Get("siteName").String()
		icp := item.Get("icpNo").String()
		for _, d := range item.Get("domain").Array() {
			domain := normalizeDomain(d.String())
			if domain == "" {
				continue
			}
			out = append(out, DomainHit{Domain: domain, Site: site, ICP: icp})
		}
		if len(out) > 0 && len(out) >= size {
			break
		}
	}
	return out, len(out) >= size, nil
}
