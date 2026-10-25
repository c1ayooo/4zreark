package enterprise

import (
	"context"
	"errors"
)

// Provider 上游企业信息源适配器。实现方只做协议转换，不做业务编排；
// Session 由服务端持有（datasource vault），前端永远拿不到 Cookie。
type Provider interface {
	Name() string
	// Search 按关键词搜索企业，返回稳定 ext_id 列表。
	Search(ctx context.Context, keyword string, limit int) ([]CompanyRef, error)
	// Detail 企业详情与关联域名（ICP 等）。
	Detail(ctx context.Context, extID string) (*CompanyDetail, error)
	// Branches 分支机构，返回下一页是否存在。
	Branches(ctx context.Context, extID string, page, size int) ([]CompanyRef, bool, error)
	// Investments 对外投资，返回下一页是否存在。
	Investments(ctx context.Context, extID string, page, size int) ([]CompanyRef, bool, error)
	// Domains 关联域名/备案，返回下一页是否存在。
	Domains(ctx context.Context, extID string, page, size int) ([]DomainHit, bool, error)
}

// ErrSessionMissing provider 会话未配置或已失效。
type ErrSessionMissing struct{ msg string }

func (e ErrSessionMissing) Error() string { return e.msg }

func SessionMissing(msg string) error { return ErrSessionMissing{msg: msg} }

// IsSessionMissing 判断是否为会话未配置类错误（HTTP 400 语义）。
func IsSessionMissing(err error) bool {
	var e ErrSessionMissing
	return errors.As(err, &e)
}

// DigitalHit 数字资产线索（APP/小程序/公众号/新媒体）。Kind 取值与 digital_assets 名单一致：
// app / miniapp / official_account / newmedia。
type DigitalHit struct {
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Platform   string `json:"platform,omitempty"`
	Company    string `json:"company,omitempty"`
	EntityName string `json:"entity_name,omitempty"` // 归属企业名
	Evidence   string `json:"evidence,omitempty"`
}

// DigitalAssetsProvider 可选能力接口：数据源支持数字资产采集时实现；
// 调用方用类型断言探测，不要求所有 Provider 实现。
type DigitalAssetsProvider interface {
	// DigitalAssets 企业关联的数字资产，返回下一页是否存在。
	DigitalAssets(ctx context.Context, extID string, page, size int) ([]DigitalHit, bool, error)
}

// GroupCompaniesProvider 可选能力接口：数据源支持枚举同一集团下的成员公司
// （兄弟公司口径，区别于对外投资的控股子公司）。BFS 开启「展开集团成员」时调用。
type GroupCompaniesProvider interface {
	// GroupCompanies 集团成员列表，返回下一页是否存在。
	GroupCompanies(ctx context.Context, extID string, page, size int) ([]CompanyRef, bool, error)
}
