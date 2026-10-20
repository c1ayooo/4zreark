package service

import (
	"context"
	"errors"

	"github.com/c1ayooo/4zreark/repo"
)

// VerifyService 把一个站点的全部入口探一遍，按「任一入口可达即算活着」聚合后写回。
//
// 判定口径（对齐 v2 §8）：
//   - 收到任意 HTTP 响应（403/404/500 也算）→ reachable
//   - 全部入口都连不上 → 失败计数 +1，累计到阈值才进 lost
//   - FakeIP / 公网域名解析到私网 → inconclusive，只落流水，不计失败
type VerifyService struct{}

func NewVerifyService() *VerifyService { return &VerifyService{} }

// EndpointProbe 是单个入口的探测结果。
type EndpointProbe struct {
	Scheme     string `json:"scheme"`
	Port       int    `json:"port"`
	Outcome    string `json:"outcome"`
	ReasonCode string `json:"reason_code"`
	StatusCode int    `json:"status_code"`
	Addr       string `json:"addr"`
	ElapsedMS  int64  `json:"elapsed_ms"`
	Detail     string `json:"detail"`
}

// SiteProbeReport 是一个站点的聚合结果。
type SiteProbeReport struct {
	SiteID     int64           `json:"site_id"`
	Host       string          `json:"host"`
	Verdict    string          `json:"verdict"` // reachable / unreachable / inconclusive
	ReasonCode string          `json:"reason_code"`
	StatusCode int             `json:"status_code"`
	Endpoints  []EndpointProbe `json:"endpoints"`
}

func (s *VerifyService) stores() (*repo.AssetRepo, error) {
	r := repo.Default()
	if r == nil {
		return nil, errors.New("数据层未初始化")
	}
	return repo.NewAssetRepo(), nil
}

// ProbeSite 探测一个站点的全部入口并写回状态。
func (s *VerifyService) ProbeSite(ctx context.Context, siteID int64) (*SiteProbeReport, error) {
	assets, err := s.stores()
	if err != nil {
		return nil, err
	}
	host, err := assets.SiteHost(ctx, siteID)
	if err != nil {
		return nil, err
	}
	endpoints, err := assets.AssetEndpoints(ctx, siteID)
	if err != nil {
		return nil, err
	}
	if len(endpoints) == 0 {
		// 没有入口记录的站点（历史数据缺）不能当成失联
		if err := assets.RecordInconclusive(ctx, siteID, "no_endpoint"); err != nil {
			return nil, err
		}
		return &SiteProbeReport{SiteID: siteID, Host: host, Verdict: "inconclusive",
			ReasonCode: "no_endpoint", Endpoints: []EndpointProbe{}}, nil
	}

	report := &SiteProbeReport{SiteID: siteID, Host: host, Endpoints: make([]EndpointProbe, 0, len(endpoints))}
	worstReason := ""
	for _, ep := range endpoints {
		res := ProbeEndpoint(ctx, report.Host, ep.Port, ep.Scheme)
		report.Endpoints = append(report.Endpoints, EndpointProbe{
			Scheme: ep.Scheme, Port: ep.Port, Outcome: string(res.Outcome),
			ReasonCode: res.ReasonCode, StatusCode: res.StatusCode, Addr: res.Addr,
			ElapsedMS: res.ElapsedMS, Detail: res.Detail,
		})
		if res.Reachable() {
			report.Verdict = "reachable"
			report.StatusCode = res.StatusCode
			report.ReasonCode = res.ReasonCode
			break
		}
		if res.Inconclusive() {
			// 先记下不确定，继续探其他入口：只要有一个通了就算活
			report.Verdict = "inconclusive"
			report.ReasonCode = res.ReasonCode
			continue
		}
		worstReason = res.ReasonCode
	}

	switch report.Verdict {
	case "reachable":
		if err := assets.VerifySite(ctx, siteID, true, report.StatusCode, report.ReasonCode); err != nil {
			return report, err
		}
	case "inconclusive":
		if err := assets.RecordInconclusive(ctx, siteID, report.ReasonCode); err != nil {
			return report, err
		}
	default:
		report.Verdict = "unreachable"
		if worstReason == "" {
			worstReason = "all_endpoints_failed"
		}
		report.ReasonCode = worstReason
		if err := assets.VerifySite(ctx, siteID, false, 0, worstReason); err != nil {
			return report, err
		}
	}
	return report, nil
}

// ProbeHostPort 在站点还没归并出来时直接探一个 host:port（计划展开回落的那条目标）。
func (s *VerifyService) ProbeHostPort(ctx context.Context, host string, port int) ProbeResult {
	scheme := "https"
	if port == 80 || port == 8080 || port == 8000 || port == 8008 {
		scheme = "http"
	}
	return ProbeEndpoint(ctx, host, port, scheme)
}
