package report

import (
	"bytes"
	"fmt"
	"html/template"
	"sort"
	"strings"
)

// AssetReport 是「信息收集 / 资产测绘」报告的数据模型。
// 与漏洞报告（Report）分开：两者的章节、表格与取数口径都不同，
// 强行合到一个结构里只会让两边都变空。
type AssetReport struct {
	Title       string
	ProjectName string
	ProjectCode string
	Region      string
	Description string
	GeneratedAt string
	Range       string // 测试范围：种子 + 项目周期口径

	Profile   Profile
	Delivery  DeliveryInfo
	SectionNo SectionNumbers

	Summary     AssetSummary
	Stats       AssetStats
	Domains     []AssetDomainRow
	Sites       []AssetSiteRow
	TechSummary []NameCount
	PortSummary []PortCount
	HighRisk    []AssetSiteRow
	Limitations []string
	Notes       []string
	// Tasks 任务执行维度：TaskSummary 覆盖项目全部任务，
	// Tasks 明细行按创建时间倒序截断（报告只展示最近的任务）。
	Tasks       []AssetTaskRow
	TaskSummary AssetTaskSummary
	// Truncated 非空时表示清单被模板上限截断，内容是一句给读者看的说明。
	Truncated string
}

// AssetSummary 是执行摘要里的统计口径。
type AssetSummary struct {
	Domains      int
	Sites        int
	Reachable    int
	Lost         int
	Endpoints    int
	Records      int
	NewWithin7d  int
	WithTech     int
	WithIcon     int
	FirstSeen    string
	LastSeen     string
	SeedCount    int
	CollectState string
}

// AssetStats 是资产规模与状态分布。
type AssetStats struct {
	ByState     []NameCount
	ByProto     []NameCount
	ByDiscovery []NameCount
}

type AssetDomainRow struct {
	Host       string
	SiteCount  int
	Reachable  int
	Ports      string
	LastSeen   string
	IsSeedBase bool
}

type AssetSiteRow struct {
	Host      string
	IP        string
	Title     string
	Scheme    string
	Port      int
	Status    int
	State     string
	Tech      string
	Discovery string
	FirstSeen string
	RiskScore int
	Priority  string
}

type NameCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
	// Pct 只在状态分布里使用（占总站点百分比），其他分布留 0。
	Pct int `json:"pct,omitempty"`
}

// AssetTaskRow 任务执行明细行（报告「任务执行」章节）。
type AssetTaskRow struct {
	Name      string
	TaskType  string
	Status    string
	Progress  int
	CreatedAt string
}

// AssetTaskSummary 任务执行概况：Total 为项目全部任务数，
// 其余为按状态的计数（暂停/取消等归入 Other）。
type AssetTaskSummary struct {
	Total     int
	Running   int
	Pending   int
	Completed int
	Failed    int
	Other     int
}

// TaskStatusLabel 任务状态中文标签（markdown/docx/xlsx 渲染共用）。
func TaskStatusLabel(s string) string {
	switch s {
	case "pending":
		return "排队中"
	case "running":
		return "运行中"
	case "completed":
		return "已完成"
	case "failed":
		return "失败"
	case "paused":
		return "已暂停"
	case "cancelled":
		return "已取消"
	}
	return s
}

type PortCount struct {
	Scheme string
	Port   int
	Count  int
}

// ── 渲染 ──

// RenderAssetHTML 渲染信息收集报告为自包含 HTML。
func RenderAssetHTML(r *AssetReport) ([]byte, error) {
	r.normalize()
	tmpl, err := template.New("asset-report").Funcs(template.FuncMap{
		"stateClass":      assetStateClass,
		"stateLabel":      assetStateLabel,
		"safeURL":         func(s string) template.URL { return template.URL(s) },
		"taskStatusLabel": TaskStatusLabel,
		"add":             func(a, b int) int { return a + b },
	}).Parse(assetTemplate)
	if err != nil {
		return nil, fmt.Errorf("解析资产报告模板失败: %w", err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, r); err != nil {
		return nil, fmt.Errorf("渲染资产报告失败: %w", err)
	}
	return buf.Bytes(), nil
}

// RenderAssetMarkdown 渲染信息收集报告为 Markdown。
func RenderAssetMarkdown(r *AssetReport) ([]byte, error) {
	r.normalize()
	p := r.Profile
	no := r.SectionNo

	var b strings.Builder
	b.WriteString("# " + r.Title + "\n\n")
	b.WriteString("| 项目 | " + r.ProjectName + " |\n")
	b.WriteString("| 项目编码 | " + r.ProjectCode + " |\n")
	if r.Region != "" {
		b.WriteString("| 区域 | " + r.Region + " |\n")
	}
	b.WriteString("| 报告类型 | " + p.CoverSubject + " |\n")
	b.WriteString("| 交付模板 | " + p.Name + " |\n")
	if r.Delivery.ClientName != "" {
		b.WriteString("| 客户名称 | " + r.Delivery.ClientName + " |\n")
	}
	if r.Delivery.ReportNo != "" {
		b.WriteString("| 报告编号 | " + r.Delivery.ReportNo + " |\n")
	}
	if r.Delivery.Classification != "" {
		b.WriteString("| 密级 | " + r.Delivery.Classification + " |\n")
	}
	if r.Delivery.Tester != "" {
		b.WriteString("| 测试人员 | " + r.Delivery.Tester + " |\n")
	}
	if r.Delivery.Contact != "" {
		b.WriteString("| 联系方式 | " + r.Delivery.Contact + " |\n")
	}
	if r.Description != "" {
		b.WriteString("| 项目描述 | " + r.Description + " |\n")
	}
	b.WriteString("| 测试范围 | " + r.Range + " |\n")
	b.WriteString("| 生成时间 | " + r.GeneratedAt + " |\n")
	b.WriteString("| 生成引擎 | 4zreark |\n\n")

	b.WriteString("## " + no.Summary + "执行摘要\n\n")
	b.WriteString(fmt.Sprintf("本次测绘共覆盖 **%d** 个域名（其中根域种子 %d 个）、**%d** 个站点、**%d** 个入口，采集原始记录 %d 条。\n\n",
		r.Summary.Domains, r.Summary.SeedCount, r.Summary.Sites, r.Summary.Endpoints, r.Summary.Records))
	for _, note := range r.Notes {
		b.WriteString("- " + note + "\n")
	}
	b.WriteString("\n")

	b.WriteString("## " + no.Scope + "测试范围与采集口径\n\n")
	b.WriteString("| 项目 | 说明 |\n|---|---|\n")
	b.WriteString("| 测试范围 | " + r.Range + " |\n")
	b.WriteString("| 采集状态 | " + r.Summary.CollectState + " |\n")
	b.WriteString("| 首见时间 | " + r.Summary.FirstSeen + " |\n")
	b.WriteString("| 最近观测 | " + r.Summary.LastSeen + " |\n\n")
	if p.ShowLimitations && len(r.Limitations) > 0 {
		b.WriteString("**范围限制与授权边界：**\n\n")
		for _, lim := range r.Limitations {
			b.WriteString("- " + lim + "\n")
		}
		b.WriteString("\n")
	}

	b.WriteString("## " + no.Stats + "资产统计\n\n")
	b.WriteString("| 指标 | 数量 |\n|---|---|\n")
	b.WriteString(fmt.Sprintf("| 站点总数 | %d |\n", r.Summary.Sites))
	b.WriteString(fmt.Sprintf("| 可达站点 | %d |\n", r.Summary.Reachable))
	b.WriteString(fmt.Sprintf("| 失联站点 | %d |\n", r.Summary.Lost))
	b.WriteString(fmt.Sprintf("| 无指纹站点 | %d |\n", maxInt(r.Summary.Sites-r.Summary.WithTech, 0)))
	b.WriteString(fmt.Sprintf("| 近 7 天新增 | %d |\n\n", r.Summary.NewWithin7d))
	writeCountTable(&b, "状态分布", "状态", r.Stats.ByState, assetStateLabel)
	writeCountTable(&b, "协议分布", "协议", r.Stats.ByProto, nil)
	writeCountTable(&b, "发现来源", "来源", r.Stats.ByDiscovery, nil)

	if len(r.PortSummary) > 0 {
		b.WriteString(fmt.Sprintf("**端口 / 服务分布（TOP %d）：**\n\n", len(r.PortSummary)))
		b.WriteString("| 协议 | 端口 | 站点数 |\n|---|---|---|\n")
		for _, pc := range r.PortSummary {
			b.WriteString(fmt.Sprintf("| %s | %d | %d |\n", pc.Scheme, pc.Port, pc.Count))
		}
		b.WriteString("\n")
	}
	if len(r.TechSummary) > 0 {
		b.WriteString(fmt.Sprintf("**指纹 / 技术栈 TOP %d：**\n\n", len(r.TechSummary)))
		b.WriteString("| 技术 | 站点数 |\n|---|---|\n")
		for _, t := range r.TechSummary {
			b.WriteString(fmt.Sprintf("| %s | %d |\n", t.Name, t.Count))
		}
		b.WriteString("\n")
	}

	if len(r.Domains) > 0 {
		b.WriteString("## " + no.Domains + "域名清单\n\n")
		b.WriteString("| 域名 | 根域种子 | 站点数 | 可达 | 端口 | 最近观测 |\n|---|---|---|---|---|---|\n")
		for _, d := range r.Domains {
			seed := ""
			if d.IsSeedBase {
				seed = "是"
			}
			b.WriteString(fmt.Sprintf("| %s | %s | %d | %d | %s | %s |\n",
				d.Host, seed, d.SiteCount, d.Reachable, d.Ports, d.LastSeen))
		}
		b.WriteString("\n")
	}

	if len(r.Sites) > 0 {
		b.WriteString("## " + no.Sites + "站点清单\n\n")
		b.WriteString("| 主机 | IP | 入口 | 状态 | 标题 | 指纹 | 来源 | 首见 |\n|---|---|---|---|---|---|---|---|\n")
		for _, s := range r.Sites {
			b.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s | %s | %s | %s |\n",
				s.Host, s.IP, siteEntry(s), assetStateLabel(s.State), s.Title, s.Tech, s.Discovery, s.FirstSeen))
		}
		b.WriteString("\n")
	}
	if r.Truncated != "" {
		b.WriteString("> " + r.Truncated + "\n\n")
	}

	if r.TaskSummary.Total > 0 {
		b.WriteString("## " + no.Tasks + "任务执行\n\n")
		b.WriteString(fmt.Sprintf("项目累计 **%d** 个扫描任务：运行中 %d、排队中 %d、已完成 %d、失败 %d、其他 %d。\n\n",
			r.TaskSummary.Total, r.TaskSummary.Running, r.TaskSummary.Pending,
			r.TaskSummary.Completed, r.TaskSummary.Failed, r.TaskSummary.Other))
		if len(r.Tasks) > 0 {
			b.WriteString("| 任务 | 类型 | 状态 | 进度 | 创建时间 |\n|---|---|---|---|---|\n")
			for _, t := range r.Tasks {
				b.WriteString(fmt.Sprintf("| %s | %s | %s | %d%% | %s |\n",
					t.Name, t.TaskType, TaskStatusLabel(t.Status), t.Progress, t.CreatedAt))
			}
			b.WriteString("\n")
			if r.TaskSummary.Running+r.TaskSummary.Pending > 0 {
				b.WriteString("> 存在未完成任务：本报告基于当前已落库数据生成，未完成任务的新增结果不在其中。\n\n")
			}
		}
	}

	b.WriteString("\n---\n\n*本报告由 4zreark 自动生成（交付模板：" + p.Name + "）。资产数据来自平台资产台账，可按站点 / 原始记录回溯。*\n")
	return []byte(b.String()), nil
}

func writeCountTable(b *strings.Builder, title, col string, rows []NameCount, label func(string) string) {
	if len(rows) == 0 {
		return
	}
	b.WriteString("**" + title + "：**\n\n")
	b.WriteString("| " + col + " | 数量 |\n|---|---|\n")
	for _, r := range rows {
		name := r.Name
		if label != nil {
			name = label(name)
		}
		b.WriteString(fmt.Sprintf("| %s | %d |\n", name, r.Count))
	}
	b.WriteString("\n")
}

func (r *AssetReport) normalize() {
	if strings.TrimSpace(r.Profile.ID) == "" {
		r.Profile = assetProfiles["asset-full"]
	}
	r.SectionNo = r.Profile.SectionNumbers()
}

// SortNameCounts 按数量降序、名称升序排序，保证报告输出稳定。
func SortNameCounts(rows []NameCount) {
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Count != rows[j].Count {
			return rows[i].Count > rows[j].Count
		}
		return rows[i].Name < rows[j].Name
	})
}

// SortPortCounts 端口分布排序：先协议，再端口号。
func SortPortCounts(rows []PortCount) {
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Scheme != rows[j].Scheme {
			return rows[i].Scheme < rows[j].Scheme
		}
		return rows[i].Port < rows[j].Port
	})
}

// TruncateSites 按模板上限裁剪站点清单，返回是否被截断。
func TruncateSites(rows []AssetSiteRow, max int) ([]AssetSiteRow, bool) {
	if max <= 0 || len(rows) <= max {
		return rows, false
	}
	return rows[:max], true
}

func assetStateClass(s string) string {
	switch strings.ToLower(s) {
	case "reachable", "active", "alive":
		return "st-reachable"
	case "lost", "archived":
		return "st-lost"
	default:
		return "st-pending"
	}
}

func assetStateLabel(s string) string {
	switch strings.ToLower(s) {
	case "reachable", "active", "alive":
		return "可达"
	case "lost":
		return "失联"
	case "archived":
		return "已归档"
	case "pending":
		return "待验证"
	case "":
		return "未知"
	default:
		return s
	}
}

func siteEntry(s AssetSiteRow) string {
	if s.Scheme == "" {
		if s.Port > 0 {
			return fmt.Sprintf(":%d", s.Port)
		}
		return ""
	}
	if s.Port > 0 {
		return fmt.Sprintf("%s:%d", s.Scheme, s.Port)
	}
	return s.Scheme
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
