package report

import (
	"fmt"

	"github.com/xuri/excelize/v2"
)

// XLSX 渲染：信息收集报告按「概览/资产统计/域名清单/站点清单/任务执行」分表，
// 漏洞报告按「概览/漏洞清单」分表。清单行数沿用报告数据本身的截断口径，
// 超长文本写单元格前截到 500 字符，避免撑爆 Excel 单元格。

const xlsxCellCap = 500

func xlsxCell(s string) string {
	if len(s) <= xlsxCellCap {
		return s
	}
	r := []rune(s)
	if len(r) <= xlsxCellCap {
		return s
	}
	return string(r[:xlsxCellCap]) + "…"
}

func sevLabel(s string) string {
	switch s {
	case "critical":
		return "严重"
	case "high":
		return "高危"
	case "medium":
		return "中危"
	case "low":
		return "低危"
	case "info":
		return "信息"
	}
	return s
}

func setKV(f *excelize.File, sheet string, rows [][2]string) {
	for i, kv := range rows {
		_ = f.SetCellValue(sheet, fmt.Sprintf("A%d", i+1), kv[0])
		_ = f.SetCellValue(sheet, fmt.Sprintf("B%d", i+1), kv[1])
	}
	_ = f.SetColWidth(sheet, "A", "A", 22)
	_ = f.SetColWidth(sheet, "B", "B", 60)
}

func setTable(f *excelize.File, sheet string, header []string, rows [][]string) error {
	for i, h := range header {
		cell, _ := excelize.CoordinatesToCellName(i+1, 1)
		_ = f.SetCellValue(sheet, cell, h)
	}
	for r, row := range rows {
		for c, v := range row {
			cell, _ := excelize.CoordinatesToCellName(c+1, r+2)
			_ = f.SetCellValue(sheet, cell, xlsxCell(v))
		}
	}
	for i := range header {
		col, _ := excelize.ColumnNumberToName(i + 1)
		_ = f.SetColWidth(sheet, col, col, 18)
	}
	return nil
}

// RenderAssetXlsx 渲染信息收集报告为 Excel 工作簿。
func RenderAssetXlsx(r *AssetReport) ([]byte, error) {
	r.normalize()
	f := excelize.NewFile()
	defer f.Close()

	ov := f.GetSheetName(0)
	_ = f.SetSheetName(ov, "概览")
	setKV(f, "概览", [][2]string{
		{"报告标题", r.Title},
		{"项目", r.ProjectName},
		{"项目编码", r.ProjectCode},
		{"区域", r.Region},
		{"交付模板", r.Profile.Name},
		{"测试范围", r.Range},
		{"采集状态", r.Summary.CollectState},
		{"域名数", fmt.Sprint(r.Summary.Domains)},
		{"根域种子", fmt.Sprint(r.Summary.SeedCount)},
		{"站点数", fmt.Sprint(r.Summary.Sites)},
		{"可达 / 失联", fmt.Sprintf("%d / %d", r.Summary.Reachable, r.Summary.Lost)},
		{"入口 / 原始记录", fmt.Sprintf("%d / %d", r.Summary.Endpoints, r.Summary.Records)},
		{"近 7 天新增", fmt.Sprint(r.Summary.NewWithin7d)},
		{"首见 / 最近观测", r.Summary.FirstSeen + " ~ " + r.Summary.LastSeen},
		{"生成时间", r.GeneratedAt},
		{"任务执行", fmt.Sprintf("共 %d：运行中 %d · 排队 %d · 完成 %d · 失败 %d · 其他 %d",
			r.TaskSummary.Total, r.TaskSummary.Running, r.TaskSummary.Pending,
			r.TaskSummary.Completed, r.TaskSummary.Failed, r.TaskSummary.Other)},
	})

	_, _ = f.NewSheet("资产统计")
	setTable(f, "资产统计", []string{"指标", "数量"}, [][]string{
		{"站点总数", fmt.Sprint(r.Summary.Sites)},
		{"可达站点", fmt.Sprint(r.Summary.Reachable)},
		{"失联站点", fmt.Sprint(r.Summary.Lost)},
		{"近 7 天新增", fmt.Sprint(r.Summary.NewWithin7d)},
	})
	statRows := [][]string{}
	for _, s := range r.Stats.ByState {
		statRows = append(statRows, []string{"状态：" + assetStateLabel(s.Name), fmt.Sprint(s.Count)})
	}
	for _, s := range r.Stats.ByProto {
		statRows = append(statRows, []string{"协议：" + s.Name, fmt.Sprint(s.Count)})
	}
	for _, s := range r.Stats.ByDiscovery {
		statRows = append(statRows, []string{"来源：" + s.Name, fmt.Sprint(s.Count)})
	}
	if len(statRows) > 0 {
		start := 7
		for i, row := range statRows {
			_ = f.SetCellValue("资产统计", fmt.Sprintf("A%d", start+i), row[0])
			_ = f.SetCellValue("资产统计", fmt.Sprintf("B%d", start+i), row[1])
		}
	}

	_, _ = f.NewSheet("域名清单")
	domRows := make([][]string, 0, len(r.Domains))
	for _, d := range r.Domains {
		seed := ""
		if d.IsSeedBase {
			seed = "是"
		}
		domRows = append(domRows, []string{d.Host, seed, fmt.Sprint(d.SiteCount), fmt.Sprint(d.Reachable), d.Ports, d.LastSeen})
	}
	_ = setTable(f, "域名清单", []string{"域名", "根域种子", "站点数", "可达", "端口", "最近观测"}, domRows)

	_, _ = f.NewSheet("站点清单")
	siteRows := make([][]string, 0, len(r.Sites))
	for _, s := range r.Sites {
		entry := s.Scheme
		if s.Port > 0 {
			entry = fmt.Sprintf("%s:%d", s.Scheme, s.Port)
		}
		siteRows = append(siteRows, []string{s.Host, s.IP, entry, assetStateLabel(s.State), s.Title, s.Tech, s.Discovery, s.FirstSeen})
	}
	_ = setTable(f, "站点清单", []string{"主机", "IP", "入口", "状态", "标题", "指纹", "来源", "首见"}, siteRows)

	_, _ = f.NewSheet("高危站点")
	hrRows := make([][]string, 0, len(r.HighRisk))
	for _, s := range r.HighRisk {
		entry := s.Scheme
		if s.Port > 0 {
			entry = fmt.Sprintf("%s:%d", s.Scheme, s.Port)
		}
		hrRows = append(hrRows, []string{s.Host, entry, fmt.Sprint(s.RiskScore), s.Priority, s.Title})
	}
	_ = setTable(f, "高危站点", []string{"主机", "入口", "评分", "优先级", "标题"}, hrRows)

	_, _ = f.NewSheet("任务执行")
	taskRows := make([][]string, 0, len(r.Tasks))
	for _, t := range r.Tasks {
		taskRows = append(taskRows, []string{t.Name, t.TaskType, TaskStatusLabel(t.Status), fmt.Sprintf("%d%%", t.Progress), t.CreatedAt})
	}
	_ = setTable(f, "任务执行", []string{"任务", "类型", "状态", "进度", "创建时间"}, taskRows)

	buf, err := f.WriteToBuffer()
	if err != nil {
		return nil, fmt.Errorf("生成 XLSX 失败: %w", err)
	}
	return buf.Bytes(), nil
}

// RenderVulnXlsx 渲染漏洞报告为 Excel 工作簿（概览 + 漏洞清单）。
func RenderVulnXlsx(r *Report) ([]byte, error) {
	r.normalize()
	f := excelize.NewFile()
	defer f.Close()

	ov := f.GetSheetName(0)
	_ = f.SetSheetName(ov, "概览")
	setKV(f, "概览", [][2]string{
		{"报告标题", r.Title},
		{"项目", r.ProjectName},
		{"测试范围", r.Range},
		{"漏洞总数", fmt.Sprint(r.Stats.Total)},
		{"严重度分布", r.Stats.StatusSummary},
		{"风险等级", r.Stats.TopSeverity},
		{"总体结论", r.SummaryConclusion},
		{"生成时间", r.GeneratedAt},
	})

	_, _ = f.NewSheet("漏洞清单")
	rows := make([][]string, 0, len(r.Vulns))
	for _, v := range r.Vulns {
		rows = append(rows, []string{
			fmt.Sprint(v.Number), v.Title, sevLabel(v.Severity), v.Status, v.Target,
			v.Impact, v.Recommendation, v.CreatedAt,
		})
	}
	_ = setTable(f, "漏洞清单", []string{"编号", "标题", "严重度", "状态", "目标", "影响", "修复建议", "发现时间"}, rows)

	buf, err := f.WriteToBuffer()
	if err != nil {
		return nil, fmt.Errorf("生成 XLSX 失败: %w", err)
	}
	return buf.Bytes(), nil
}
