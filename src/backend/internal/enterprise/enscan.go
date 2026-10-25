package enterprise

import (
	"context"
	"fmt"
	"strings"

	"github.com/c1ayooo/4zreark/scanner/enscan"
)

// ENScanProvider 把 ENScan_GO 二进制（tools/linux/enscan，MIT）包装成本包的
// Provider。与 aqc/tyc 等原生适配器的分工：
//   - 原生适配器覆盖检索/详情/分支/投资/ICP 的分页协议，凭据走 datasource vault；
//   - enscan 的增量是原生源没有的字段：七麦 APP 商店、微博、软著、招聘
//     （由二进制自带的 config.yaml cookies 承载，不走会话托管）。
//
// 因此本适配器只承诺两类能力：
//   1. DigitalAssetsProvider（app/wx_app/wechat/weibo → 数字资产候选）；
//   2. 降级的 Search/Detail/Domains（ICP 线索，单页不分页）。
// Branches/Investments 明确返回不支持错误——BFS 编排对列表失败是容忍的
// （记日志继续），比假实现诚实。
//
// enscan 是按「企业名」同步查询（实测单次 17s+，API 串行），没有独立的
// search→pid 两段协议，所以 ext_id 直接用企业名透传。

// enscanQuerier 是 provider 依赖的最小查询面，测试用 fake 注入。
type enscanQuerier interface {
	IsAvailable() bool
	QueryCompany(ctx context.Context, companyName string, opts *enscan.ENScanQueryOptions) (*enscan.ENScanResult, error)
}

// ENScanProvider ENScan_GO 数据源适配器。
type ENScanProvider struct {
	client enscanQuerier
}

// NewENScanProvider 构造 enscan 适配器；二进制缺失时返回明确错误。
func NewENScanProvider() (*ENScanProvider, error) {
	p := &ENScanProvider{client: enscan.NewENScanScanner()}
	if !p.client.IsAvailable() {
		return nil, SessionMissing("enscan 二进制不可用（先在工具箱下载或放置 tools/linux/enscan）")
	}
	return p, nil
}

func (p *ENScanProvider) Name() string { return "enscan" }

// Search enscan 按企业名直查，没有候选列表协议；返回以企业名本身为 ext_id 的单条引用。
// 查询失败（网络/上游拒绝）返回错误；查到但字段为空不算失败。
func (p *ENScanProvider) Search(ctx context.Context, keyword string, limit int) ([]CompanyRef, error) {
	keyword = strings.TrimSpace(keyword)
	if keyword == "" {
		return nil, fmt.Errorf("检索关键词为空")
	}
	// 用 icp 字段做存在性探测（最便宜的同步查询）。
	if _, err := p.client.QueryCompany(ctx, keyword, &enscan.ENScanQueryOptions{
		Fields: []string{"icp"}, Source: "aqc",
	}); err != nil {
		return nil, err
	}
	return []CompanyRef{{ExtID: keyword, Name: keyword}}, nil
}

// Detail 企业详情：enscan 不提供工商字段，只回填 ICP 域名线索。
func (p *ENScanProvider) Detail(ctx context.Context, extID string) (*CompanyDetail, error) {
	domains, _, err := p.Domains(ctx, extID, 1, 100)
	if err != nil {
		return nil, err
	}
	return &CompanyDetail{ExtID: extID, Name: extID, Domains: domains}, nil
}

// Domains ICP 备案线索（单页，enscan 无分页协议）。
func (p *ENScanProvider) Domains(ctx context.Context, extID string, page, size int) ([]DomainHit, bool, error) {
	if page > 1 {
		return nil, false, nil
	}
	res, err := p.client.QueryCompany(ctx, extID, &enscan.ENScanQueryOptions{
		Fields: []string{"icp"}, Source: "aqc",
	})
	if err != nil {
		return nil, false, err
	}
	hits := make([]DomainHit, 0, len(res.ICPs))
	for _, icp := range res.ICPs {
		if strings.TrimSpace(icp.Domain) == "" {
			continue
		}
		hits = append(hits, DomainHit{
			Domain:   icp.Domain,
			Site:     icp.SiteName,
			ICP:      icp.ICP,
			Evidence: fmt.Sprintf("enscan/%s 备案 %s", icp.CompanyName, icp.ICP),
		})
	}
	if size > 0 && len(hits) > size {
		hits = hits[:size]
	}
	return hits, false, nil
}

// Branches 分支机构：enscan CLI 有 --branch 但输出无分页协议，明确不支持。
func (p *ENScanProvider) Branches(ctx context.Context, extID string, page, size int) ([]CompanyRef, bool, error) {
	return nil, false, fmt.Errorf("enscan 数据源不支持分支机构分页采集（用 aqc/tyc 等原生源）")
}

// Investments 对外投资：同上，明确不支持。
func (p *ENScanProvider) Investments(ctx context.Context, extID string, page, size int) ([]CompanyRef, bool, error) {
	return nil, false, fmt.Errorf("enscan 数据源不支持对外投资分页采集（用 aqc/tyc 等原生源）")
}

// DigitalAssets 数字资产：app/wx_app/wechat/weibo 一次查询带回，映射到名单 kind。
// 七麦（qimai cookie）配置时 app 字段即含商店数据——这是原生源没有的口径。
func (p *ENScanProvider) DigitalAssets(ctx context.Context, extID string, page, size int) ([]DigitalHit, bool, error) {
	if page > 1 {
		return nil, false, nil
	}
	res, err := p.client.QueryCompany(ctx, extID, &enscan.ENScanQueryOptions{
		Fields: []string{"app", "wx_app", "wechat", "weibo"}, Source: "aqc",
	})
	if err != nil {
		return nil, false, err
	}
	hits := make([]DigitalHit, 0, len(res.Apps)+len(res.WxApps)+len(res.Wechats)+len(res.Weibos))
	for _, a := range res.Apps {
		if a.Name == "" {
			continue
		}
		hits = append(hits, DigitalHit{
			Kind: "app", Name: a.Name, Platform: firstNonEmpty(a.Market, "APP"),
			Company: extID, EntityName: extID,
			Evidence: digitalEvidence("app", a.Package, a.Developer),
		})
	}
	for _, w := range res.WxApps {
		if w.Name == "" {
			continue
		}
		hits = append(hits, DigitalHit{
			Kind: "miniapp", Name: w.Name, Platform: "微信小程序",
			Company: extID, EntityName: extID,
			Evidence: digitalEvidence("wx_app", w.AppID, w.Description),
		})
	}
	for _, w := range res.Wechats {
		if w.Name == "" {
			continue
		}
		hits = append(hits, DigitalHit{
			Kind: "official_account", Name: w.Name, Platform: "微信公众号",
			Company: extID, EntityName: extID,
			Evidence: digitalEvidence("wechat", w.WechatID, w.Description),
		})
	}
	for _, wb := range res.Weibos {
		if wb.Name == "" {
			continue
		}
		hits = append(hits, DigitalHit{
			Kind: "newmedia", Name: wb.Name, Platform: "微博",
			Company: extID, EntityName: extID,
			Evidence: digitalEvidence("weibo", wb.URL, wb.Description),
		})
	}
	if size > 0 && len(hits) > size {
		hits = hits[:size]
	}
	return hits, false, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// digitalEvidence 组装候选证据摘要（不含原始响应透传）。
func digitalEvidence(field, id, extra string) string {
	parts := make([]string, 0, 3)
	if id = strings.TrimSpace(id); id != "" {
		parts = append(parts, id)
	}
	if extra = strings.TrimSpace(extra); extra != "" {
		if len([]rune(extra)) > 80 {
			extra = string([]rune(extra)[:80]) + "…"
		}
		parts = append(parts, extra)
	}
	return "enscan/" + field + ": " + strings.Join(parts, " · ")
}
