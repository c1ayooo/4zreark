package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/internal/httpprobe"
	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/oid"
	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/report"
)

// ReportService 把库里已有的资产与漏洞组装成交付报告。
//
// 渲染层（report 包）与数据层解耦：本服务只负责取数与映射，
// HTML/PDF/Markdown 的排版、证据高亮、分页都在 report 包里。
type ReportService struct{}

func NewReportService() *ReportService { return &ReportService{} }

// ReportGenInput 是一次报告生成请求。
//
// Kind 决定报告类型：vuln（漏洞交付，默认）/ asset（信息收集 · 资产测绘）。
// Template 是模板 ID，两类模板各自独立；为空时按 Kind 取默认模板。
type ReportGenInput struct {
	WorkspaceID string                `json:"workspace_id"`
	ProjectID   int64                 `json:"project_id"`
	Name        string                `json:"name"`
	Title       string                `json:"title"`
	Format      string                `json:"format"`   // html | pdf | markdown（默认 html）
	Kind        string                `json:"kind"`     // vuln | asset
	Template    string                `json:"template"` // 见 report.ListProfiles()
	Delivery    models.ReportDelivery `json:"delivery"`
	CreatedBy   string                `json:"-"`
}

// Generate 生成报告文件并写 vuln_reports 台账。
func (s *ReportService) Generate(ctx context.Context, in ReportGenInput) (*models.VulnReport, error) {
	r := repo.Default()
	if r == nil {
		return nil, errors.New("数据库未就绪")
	}
	store := r.Vulns()

	kind := strings.ToLower(strings.TrimSpace(in.Kind))
	if kind == "" {
		kind = "vuln"
	}
	if kind != "vuln" && kind != "asset" {
		return nil, report.InvalidRequest("kind 只支持 vuln（漏洞交付）/ asset（信息收集）")
	}
	profile, ok := report.LookupProfile(in.Template)
	if !ok {
		return nil, report.InvalidRequest("未知的报告模板: %s", in.Template)
	}
	// 未指定模板时按报告类型取默认，而不是一律回落到漏洞模板。
	if strings.TrimSpace(in.Template) == "" && kind == "asset" {
		profile = report.DefaultAssetProfile()
	}
	if profile.Type != kind {
		return nil, report.InvalidRequest("模板 %s 属于 %s 报告，与 kind=%s 不匹配", profile.ID, profile.Type, kind)
	}
	if kind == "asset" {
		return s.generateAsset(ctx, store, in, profile)
	}

	vulns, err := listAllVulns(ctx, store, in.WorkspaceID)
	if err != nil {
		return nil, err
	}

	title := strings.TrimSpace(in.Title)
	if title == "" {
		title = defaultReportTitle(in.Name)
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = title
	}

	sections := make([]report.VulnSection, 0, len(vulns))
	for i, v := range vulns {
		sections = append(sections, buildVulnSection(i+1, v))
	}
	// 先按严重度排序（模板的最低等级过滤在排序之后做，编号才不会跳号）。
	report.SortVulnsBySeverity(sections)
	sections = report.FilterSectionsBySeverity(sections, profile.MinSeverity)

	// 统计必须与模板实际保留的漏洞一致：简报只留 high+，不能把全量数字写进摘要。
	sevCounts := make(map[string]int64, 5)
	overview := make([]report.OverviewRow, 0, len(sections))
	appendix := make([]report.EvidenceItem, 0, len(sections))
	for i := range sections {
		sections[i].Number = i + 1
		sec := sections[i]
		sevCounts[strings.ToLower(sec.Severity)]++
		if sec.EvidencePacket != nil {
			appendix = append(appendix, *sec.EvidencePacket)
		}
		overview = append(overview, report.OverviewRow{
			Number:        sec.Number,
			Title:         sec.Title,
			Severity:      sec.Severity,
			Status:        sec.Status,
			Target:        sec.Target,
			EvidenceCount: evidenceCount(sec),
		})
	}
	total := int64(len(sections))

	doc := &report.Report{
		Title:       title,
		ProjectName: projectName(ctx, in.ProjectID),
		Description: reportDescription(in, len(sections)),
		GeneratedAt: time.Now().Format("2006-01-02 15:04:05"),
		Range:       fmt.Sprintf("工作区 %s，共 %d 条漏洞", nonEmpty(in.WorkspaceID, "默认"), total),
		Profile:     profile,
		Delivery:    deliveryFromModel(in.Delivery),
		Stats:       buildReportStats(sevCounts, total),
		Overview:    overview,
		Vulns:       sections,
		Remediation: report.BuildRemediation(sections),
		Appendix:    appendix,
		Limitations: []string{
			"本报告基于平台已入库数据生成；未入库的探测过程与人工验证结论不在报告范围内。",
		},
	}
	doc.SummaryConclusion = buildConclusion(doc.Stats)
	doc.AssetOverview = buildAssetOverview(ctx, in.ProjectID)

	return s.render(ctx, store, in, doc, nil, name, formatOf(in.Format))
}

// generateAsset 组装信息收集 / 资产测绘报告。
func (s *ReportService) generateAsset(ctx context.Context, store repo.VulnRepo, in ReportGenInput, profile report.Profile) (*models.VulnReport, error) {
	if in.ProjectID <= 0 {
		return nil, report.InvalidRequest("信息收集报告必须指定 project_id")
	}
	assets := repo.NewAssetRepo()
	project, err := assets.GetProject(ctx, in.ProjectID)
	if err != nil {
		return nil, fmt.Errorf("读取项目失败: %w", err)
	}
	summary, err := assets.AssetReportSummary(ctx, in.ProjectID)
	if err != nil {
		return nil, fmt.Errorf("统计资产失败: %w", err)
	}
	seeds, err := repo.Default().Seeds().ListSeeds(ctx, in.ProjectID)
	if err != nil {
		return nil, fmt.Errorf("读取种子失败: %w", err)
	}

	title := strings.TrimSpace(in.Title)
	if title == "" {
		title = fmt.Sprintf("%s %s-%s", project.Name, profile.CoverSubject, time.Now().Format("20060102"))
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = title
	}

	doc, err := buildAssetDoc(ctx, assets, project, summary, seeds, profile, in.Delivery, title)
	if err != nil {
		return nil, err
	}
	return s.render(ctx, store, in, nil, doc, name, formatOf(in.Format))
}

// formatOf 归一化输出格式。
func formatOf(f string) string {
	f = strings.ToLower(strings.TrimSpace(f))
	switch f {
	case "md", "markdown":
		return "markdown"
	case "pdf":
		return "pdf"
	default:
		return "html"
	}
}

func deliveryFromModel(d models.ReportDelivery) report.DeliveryInfo {
	return report.DeliveryInfo{
		ClientName:     strings.TrimSpace(d.ClientName),
		ReportNo:       strings.TrimSpace(d.ReportNo),
		Classification: strings.TrimSpace(d.Classification),
		Tester:         strings.TrimSpace(d.Tester),
		Contact:        strings.TrimSpace(d.Contact),
	}
}

// render 按格式渲染（漏洞报告走 vulnDoc，资产报告走 assetDoc），写文件并落报告台账。
func (s *ReportService) render(ctx context.Context, store repo.VulnRepo, in ReportGenInput,
	vulnDoc *report.Report, assetDoc *report.AssetReport, name, format string) (*models.VulnReport, error) {

	renderHTML := func() ([]byte, error) {
		if assetDoc != nil {
			return report.RenderAssetHTML(assetDoc)
		}
		return report.RenderHTML(vulnDoc)
	}
	renderMD := func() ([]byte, error) {
		if assetDoc != nil {
			return report.RenderAssetMarkdown(assetDoc)
		}
		return report.RenderMarkdown(vulnDoc)
	}

	outDir := filepath.Join("data", "reports")
	if err := os.MkdirAll(outDir, 0o750); err != nil {
		return nil, fmt.Errorf("创建报告目录失败: %w", err)
	}
	repID := oid.NewObjectID()
	base := repID.Hex()

	var (
		data     []byte
		filePath string
		err      error
	)
	switch format {
	case "markdown":
		data, err = renderMD()
		if err == nil {
			filePath = filepath.Join(outDir, base+".md")
			err = os.WriteFile(filePath, data, 0o600)
		}
	case "pdf":
		data, err = renderHTML()
		if err != nil {
			break
		}
		htmlPath := filepath.Join(outDir, base+".html")
		if werr := os.WriteFile(htmlPath, data, 0o600); werr != nil {
			return nil, fmt.Errorf("写入 HTML 失败: %w", werr)
		}
		pdfPath, perr := report.RenderPDF(data, outDir, base)
		if perr != nil {
			return nil, perr
		}
		if pdfPath == "" {
			// 没有 Chrome：降级为 HTML，保持报告可用。
			filePath = htmlPath
			format = "html"
		} else {
			filePath = pdfPath
		}
	default:
		data, err = renderHTML()
		if err == nil {
			filePath = filepath.Join(outDir, base+".html")
			err = os.WriteFile(filePath, data, 0o600)
		}
		format = "html"
	}
	if err != nil {
		return nil, err
	}

	rep := &models.VulnReport{
		ID:         repID,
		Name:       name,
		Type:       format,
		ReportKind: "vuln",
		FilePath:   filePath,
		CreatedAt:  time.Now(),
		Delivery:   in.Delivery,
	}
	if assetDoc != nil {
		rep.ReportKind = "asset"
		rep.Template = assetDoc.Profile.ID
		rep.Summary = models.ReportSummary{TotalAssets: assetDoc.Summary.Sites}
	} else {
		rep.Template = vulnDoc.Profile.ID
		rep.Summary = summaryFromStats(vulnDoc.Stats)
	}
	if in.WorkspaceID != "" {
		if ws, werr := oid.ObjectIDFromHex(in.WorkspaceID); werr == nil {
			rep.WorkspaceID = ws
		}
	}
	if in.CreatedBy != "" {
		if uid, uerr := oid.ObjectIDFromHex(in.CreatedBy); uerr == nil {
			rep.CreatedBy = uid
		}
	}
	if err := store.CreateReport(ctx, rep); err != nil {
		return nil, err
	}
	return rep, nil
}

// GetFilePath 返回某条报告在磁盘上的路径（下载入口用）。
func (s *ReportService) GetFilePath(ctx context.Context, id string) (string, *models.VulnReport, error) {
	r := repo.Default()
	if r == nil {
		return "", nil, errors.New("数据库未就绪")
	}
	rep, err := r.Vulns().GetReport(ctx, id)
	if err != nil {
		return "", nil, err
	}
	if strings.TrimSpace(rep.FilePath) == "" {
		return "", rep, errors.New("报告没有生成文件")
	}
	return rep.FilePath, rep, nil
}

func listAllVulns(ctx context.Context, store repo.VulnRepo, workspaceID string) ([]*models.Vulnerability, error) {
	const pageSize = 500
	out := make([]*models.Vulnerability, 0, pageSize)
	for page := 1; page <= 40; page++ {
		batch, total, err := store.List(ctx, repo.VulnFilter{
			WorkspaceID: workspaceID, Page: page, PageSize: pageSize,
		})
		if err != nil {
			return nil, err
		}
		out = append(out, batch...)
		if len(batch) < pageSize || int64(len(out)) >= total {
			break
		}
	}
	return out, nil
}

func buildVulnSection(n int, v *models.Vulnerability) report.VulnSection {
	sec := report.VulnSection{
		Number:         n,
		ID:             v.ID.Hex(),
		Title:          v.Name,
		Severity:       string(v.Severity),
		Status:         string(v.Status),
		Type:           v.Type,
		Target:         v.Target,
		Description:    v.Description,
		Recommendation: v.Solution,
		CreatedAt:      formatTime(v.CreatedAt),
	}
	if len(v.CVEID) > 0 {
		sec.Impact = "关联 CVE：" + strings.Join(v.CVEID, "、")
	}
	raw := strings.TrimSpace(v.Evidence)
	if v.Request != "" || v.Response != "" {
		var b strings.Builder
		b.WriteString(httpprobe.RequestMarker + "\n")
		b.WriteString(strings.TrimSpace(v.Request))
		b.WriteString("\n\n" + httpprobe.ResponseMarker + "\n")
		b.WriteString(strings.TrimSpace(v.Response))
		raw = b.String()
	}
	if pkt, ok := report.NewPacketItem(raw, report.RespModeSmart, v.Type, ""); ok {
		sec.EvidencePacket = pkt
	} else {
		sec.Evidence = raw
	}
	return sec
}

func evidenceCount(sec report.VulnSection) int {
	n := len(sec.EvidenceGroups)
	for _, g := range sec.EvidenceGroups {
		n += len(g.Items)
	}
	if sec.EvidencePacket != nil {
		n++
	}
	if sec.Evidence != "" {
		n++
	}
	return n
}

func buildReportStats(sev map[string]int64, total int64) report.Stats {
	bySev := make(map[string]int, len(sev))
	for k, v := range sev {
		bySev[k] = int(v)
	}
	order := []string{"critical", "high", "medium", "low", "info"}
	dist := make([]report.SevCount, 0, len(order))
	for _, s := range order {
		n := bySev[s]
		if n == 0 {
			continue
		}
		pct := 0
		if total > 0 {
			pct = int(float64(n) * 100 / float64(total))
		}
		dist = append(dist, report.SevCount{Severity: s, Count: n, Percent: pct})
	}
	top := "info"
	for _, s := range order {
		if bySev[s] > 0 {
			top = s
			break
		}
	}
	return report.Stats{Total: int(total), BySeverity: bySev, SeverityDist: dist, TopSeverity: top}
}

func summaryFromStats(st report.Stats) models.ReportSummary {
	return models.ReportSummary{
		TotalVulns:    st.Total,
		CriticalCount: st.BySeverity["critical"],
		HighCount:     st.BySeverity["high"],
		MediumCount:   st.BySeverity["medium"],
		LowCount:      st.BySeverity["low"],
		InfoCount:     st.BySeverity["info"],
	}
}

func buildConclusion(st report.Stats) string {
	if st.Total == 0 {
		return "本次评估未发现已入库的安全问题。"
	}
	return fmt.Sprintf("本次评估共发现 %d 个漏洞，其中严重 %d 个、高危 %d 个、中危 %d 个。建议优先处置严重与高危项，并在修复后安排复测。",
		st.Total, st.BySeverity["critical"], st.BySeverity["high"], st.BySeverity["medium"])
}

func buildAssetOverview(ctx context.Context, projectID int64) *report.AssetOverview {
	r := repo.Default()
	if r == nil {
		return nil
	}
	if projectID > 0 {
		p, err := repo.NewAssetRepo().GetProject(ctx, projectID)
		if err != nil {
			return nil
		}
		return &report.AssetOverview{Total: p.AssetCount, Hosts: p.AssetCount, Domains: p.AssetCount}
	}
	o, err := repo.NewAssetRepo().Overview(ctx)
	if err != nil || o == nil {
		return nil
	}
	return &report.AssetOverview{Total: int(o.Assets), Hosts: int(o.Domains), Domains: int(o.Domains)}
}

func projectName(ctx context.Context, projectID int64) string {
	if projectID <= 0 {
		return "4zreark"
	}
	p, err := repo.NewAssetRepo().GetProject(ctx, projectID)
	if err != nil || p == nil || strings.TrimSpace(p.Name) == "" {
		return "4zreark"
	}
	return p.Name
}

func reportDescription(in ReportGenInput, n int) string {
	if in.ProjectID > 0 {
		return fmt.Sprintf("项目级安全评估报告（%d 条漏洞）", n)
	}
	return fmt.Sprintf("工作区安全评估报告（%d 条漏洞）", n)
}

func defaultReportTitle(name string) string {
	if strings.TrimSpace(name) != "" {
		return name
	}
	return "4zreark 安全评估报告"
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format("2006-01-02 15:04:05")
}

func nonEmpty(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}
