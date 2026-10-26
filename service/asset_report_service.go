package service

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/report"
)

// buildAssetDoc 把资产台账组装成信息收集报告。
// 统计走 SQL 全量聚合（AssetReportSummary），清单按模板 MaxRows 截断；
// 截断必须显式告知读者，否则交付件会让人以为资产只有这么多。
func buildAssetDoc(ctx context.Context, assets *repo.AssetRepo, project *repo.Project,
	summary *repo.AssetReportSummary, seeds []*repo.Seed, profile report.Profile,
	delivery models.ReportDelivery, title string) (*report.AssetReport, error) {

	doc := &report.AssetReport{
		Title:       title,
		ProjectName: project.Name,
		ProjectCode: project.Code,
		Region:      project.Region,
		Description: strings.TrimSpace(project.Description),
		GeneratedAt: time.Now().Format("2006-01-02 15:04:05"),
		Range:       assetScopeRange(seeds),
		Profile:     profile,
		Delivery:    deliveryFromModel(delivery),
	}

	seedCount := 0
	for _, s := range seeds {
		if s.Enabled {
			seedCount++
		}
	}

	firstSeen, lastSeen := "—", "—"
	if summary.FirstSeen != nil {
		firstSeen = summary.FirstSeen.Format("2006-01-02 15:04:05")
	}
	if summary.LastSeen != nil {
		lastSeen = summary.LastSeen.Format("2006-01-02 15:04:05")
	}

	doc.Summary = report.AssetSummary{
		Domains:      int(summary.Domains),
		Sites:        int(summary.Sites),
		Reachable:    int(summary.Reachable),
		Lost:         int(summary.Lost),
		Endpoints:    int(summary.Endpoints),
		Records:      int(summary.Records),
		NewWithin7d:  int(summary.NewWithin7),
		WithTech:     int(summary.WithTech),
		WithIcon:     int(summary.WithIcon),
		FirstSeen:    firstSeen,
		LastSeen:     lastSeen,
		SeedCount:    seedCount,
		CollectState: collectStateLabel(project),
	}

	doc.Stats.ByState = nameCounts(summary.ByState, summary.Sites)
	doc.Stats.ByProto = nameCounts(summary.ByProto, summary.Sites)
	doc.Stats.ByDiscovery = nameCounts(summary.ByDiscovery, summary.Sites)
	for _, pc := range summary.Ports {
		doc.PortSummary = append(doc.PortSummary, report.PortCount{Scheme: pc.Scheme, Port: pc.Port, Count: int(pc.Count)})
	}
	for _, tc := range summary.Techs {
		doc.TechSummary = append(doc.TechSummary, report.NameCount{Name: tc.Name, Count: int(tc.Count)})
	}

	domains, err := listReportDomains(ctx, assets, project.ID)
	if err != nil {
		return nil, err
	}
	sites, truncated, err := listReportSites(ctx, assets, project.ID, profile.MaxRows)
	if err != nil {
		return nil, err
	}
	doc.Domains = domains
	doc.Sites = sites
	if truncated {
		doc.Truncated = fmt.Sprintf("按模板「%s」的上限 %d 行截断，完整清单请导出资产页或用 MaxRows 更大的模板。",
			profile.Name, profile.MaxRows)
	}
	doc.HighRisk = reportTopRiskSites(sites, 10)

	doc.Notes = append(doc.Notes, buildAssetNotes(project, summary)...)
	doc.Limitations = assetLimitations(project)
	return doc, nil
}

// listReportDomains 取域名清单（按站点数排序，根域种子排最前）。
func listReportDomains(ctx context.Context, assets *repo.AssetRepo, projectID int64) ([]report.AssetDomainRow, error) {
	page, err := assets.ListAssets(ctx, repo.AssetQuery{
		ProjectID: projectID, Kind: "domain", SiteGroup: true, PageSize: 500,
	})
	if err != nil {
		return nil, fmt.Errorf("读取域名清单失败: %w", err)
	}
	rows, _ := page.Items.([]*repo.DomainRow)
	seedBases := map[string]bool{}
	if seeds, serr := repo.Default().Seeds().ListSeeds(ctx, projectID); serr == nil {
		for _, s := range seeds {
			if s.Kind == "domain" {
				seedBases[strings.ToLower(s.Value)] = true
			}
		}
	}

	out := make([]report.AssetDomainRow, 0, len(rows))
	for _, d := range rows {
		out = append(out, report.AssetDomainRow{
			Host:       d.Host,
			SiteCount:  int(d.SiteCount),
			Reachable:  int(d.ReachableCnt),
			LastSeen:   formatAssetTime(d.LastSeen),
			IsSeedBase: seedBases[strings.ToLower(d.Host)],
		})
	}
	return out, nil
}

// listReportSites 取站点清单（首见时间倒序，即最新发现排前面）。
func listReportSites(ctx context.Context, assets *repo.AssetRepo, projectID int64, maxRows int) ([]report.AssetSiteRow, bool, error) {
	const pageSize = 500
	out := make([]report.AssetSiteRow, 0, pageSize)
	truncated := false
	for page := 1; page <= 40; page++ {
		p, err := assets.ListAssets(ctx, repo.AssetQuery{
			ProjectID: projectID, Kind: "site", SiteGroup: true, PageSize: pageSize, Page: page,
		})
		if err != nil {
			return nil, false, fmt.Errorf("读取站点清单失败: %w", err)
		}
		rows, _ := p.Items.([]*repo.Site)
		for _, s := range rows {
			out = append(out, siteRow(s))
		}
		if len(rows) < pageSize || int64(len(out)) >= p.Total {
			break
		}
	}
	if maxRows > 0 && len(out) > maxRows {
		out = out[:maxRows]
		truncated = true
	}
	return out, truncated, nil
}

func siteRow(s *repo.Site) report.AssetSiteRow {
	scheme, port := s.Protocol, s.Port
	if len(s.Endpoints) > 0 {
		// 入口可能有多个：报告里取 HTTPS 优先的一个，完整端口视图在端口分布章节。
		for _, e := range s.Endpoints {
			if e.Scheme == "https" {
				scheme, port = "https", e.Port
				break
			}
		}
	}
	return report.AssetSiteRow{
		Host:      s.Host,
		IP:        s.IP,
		Title:     s.Title,
		Scheme:    scheme,
		Port:      port,
		Status:    s.HTTPStatus,
		State:     s.State,
		Tech:      strings.Join(s.Tech, ", "),
		Discovery: s.DiscoveryType,
		FirstSeen: s.FirstSeen.Format("2006-01-02"),
		RiskScore: s.RiskScore,
		Priority:  s.Priority,
	}
}

// reportTopRiskSites 取评分最高的若干站点；分数为 0 的不进榜。
func reportTopRiskSites(sites []report.AssetSiteRow, limit int) []report.AssetSiteRow {
	withRisk := make([]report.AssetSiteRow, 0, limit)
	for _, s := range sites {
		if s.RiskScore > 0 {
			withRisk = append(withRisk, s)
		}
	}
	sort.SliceStable(withRisk, func(i, j int) bool { return withRisk[i].RiskScore > withRisk[j].RiskScore })
	if len(withRisk) > limit {
		withRisk = withRisk[:limit]
	}
	return withRisk
}

// nameCounts 把 SQL 聚合结果转成报告用的 NameCount（附占比）。
func nameCounts(rows []repo.NameCount, total int64) []report.NameCount {
	out := make([]report.NameCount, 0, len(rows))
	for _, r := range rows {
		pct := 0
		if total > 0 {
			pct = int(float64(r.Count) * 100 / float64(total))
		}
		out = append(out, report.NameCount{Name: r.Name, Count: int(r.Count), Pct: pct})
	}
	return out
}

func assetScopeRange(seeds []*repo.Seed) string {
	if len(seeds) == 0 {
		return "项目全量资产（未配置种子）"
	}
	kinds := map[string]int{}
	for _, s := range seeds {
		if !s.Enabled {
			continue
		}
		kinds[s.Kind]++
	}
	parts := make([]string, 0, len(kinds))
	labels := map[string]string{"domain": "域名种子", "cidr": "网段种子", "company": "企业种子", "repo": "仓库种子", "dict": "字典种子", "app": "APP 种子"}
	for k, n := range kinds {
		parts = append(parts, fmt.Sprintf("%s %d 条", labels[k], n))
	}
	sort.Strings(parts)
	return "项目全量资产（" + strings.Join(parts, "，") + "）"
}

func collectStateLabel(p *repo.Project) string {
	if p.Paused {
		reason := strings.TrimSpace(p.PauseReason)
		if reason == "" {
			reason = "未填写原因"
		}
		return "采集已暂停：" + reason
	}
	days := p.CycleDays
	if days <= 0 {
		days = 30
	}
	return "采集中，周期 " + strconv.Itoa(days) + " 天"
}

func buildAssetNotes(p *repo.Project, s *repo.AssetReportSummary) []string {
	notes := []string{}
	if s.WithTech > 0 {
		notes = append(notes, fmt.Sprintf("已识别指纹的站点 %d 个，占站点总数 %d%%。", s.WithTech, pct(int(s.WithTech), int(s.Sites))))
	} else {
		notes = append(notes, "站点均未识别出指纹，建议补充指纹扫描后再出报告。")
	}
	if s.Lost > 0 {
		notes = append(notes, fmt.Sprintf("失联站点 %d 个，已在报告中单独标注，未计入可达资产。", s.Lost))
	}
	if s.NewWithin7 > 0 {
		notes = append(notes, fmt.Sprintf("近 7 天新增站点 %d 个，反映最近一轮采集的增量。", s.NewWithin7))
	}
	if s.IPs > 0 {
		notes = append(notes, fmt.Sprintf("资产分布在 %d 个 IP 上，可用于判断 IP 集中度与归属。", s.IPs))
	}
	return notes
}

func assetLimitations(p *repo.Project) []string {
	out := []string{"本报告数据来自平台资产台账，只覆盖已完成采集与归并的目标；未纳入的探测过程不在报告范围内。"}
	if p.Paused {
		out = append(out, "项目当前处于采集暂停状态，本报告反映的是暂停前的资产快照。")
	}
	return out
}

func formatAssetTime(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.Format("2006-01-02 15:04")
}

func pct(part, total int) int {
	if total <= 0 {
		return 0
	}
	return part * 100 / total
}
