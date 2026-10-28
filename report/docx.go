package report

import (
	"bytes"
	"fmt"

	"github.com/fumiama/go-docx"
)

// DOCX 渲染：纯 Go 生成（无外部二进制依赖）。信息收集报告输出封面段 + 执行摘要 +
// 域名/站点/任务三张表；漏洞报告输出摘要 + 漏洞清单表。中文正文 Word 默认字体即可，
// 不做样式花活——交付件要的是可读、可编辑。

const docxTableWidth = 9360 // twips，约 A4 可用宽度

type docxTableSpec struct {
	header []string
	rows   [][]string
}

func writeDocxTable(f *docx.Docx, spec docxTableSpec) {
	tbl := f.AddTable(len(spec.rows)+1, len(spec.header), docxTableWidth, nil)
	for c, h := range spec.header {
		p := tbl.TableRows[0].TableCells[c].AddParagraph()
		run := p.AddText(h)
		run.Bold()
	}
	for r, row := range spec.rows {
		for c, v := range row {
			p := tbl.TableRows[r+1].TableCells[c].AddParagraph()
			p.AddText(xlsxCell(v))
		}
	}
}

func docxHeading(f *docx.Docx, text string) {
	p := f.AddParagraph()
	run := p.AddText(text)
	run.Bold()
	run.Size("28")
}

func docxPara(f *docx.Docx, text string) {
	p := f.AddParagraph()
	p.AddText(text)
}

// RenderAssetDocx 渲染信息收集报告为 Word 文档。
func RenderAssetDocx(r *AssetReport) ([]byte, error) {
	r.normalize()
	f := docx.New()

	p := f.AddParagraph()
	t := p.AddText(r.Title)
	t.Bold()
	t.Size("36")
	docxPara(f, fmt.Sprintf("项目：%s（%s）  模板：%s  生成时间：%s",
		r.ProjectName, r.ProjectCode, r.Profile.Name, r.GeneratedAt))
	if r.Delivery.ClientName != "" {
		docxPara(f, "客户："+r.Delivery.ClientName)
	}
	if r.Delivery.Classification != "" {
		docxPara(f, "密级："+r.Delivery.Classification)
	}
	docxPara(f, "测试范围："+r.Range)

	docxHeading(f, "执行摘要")
	docxPara(f, fmt.Sprintf("本次测绘共覆盖 %d 个域名（根域种子 %d）、%d 个站点、%d 个入口，采集原始记录 %d 条。采集状态：%s。",
		r.Summary.Domains, r.Summary.SeedCount, r.Summary.Sites, r.Summary.Endpoints,
		r.Summary.Records, r.Summary.CollectState))
	for _, note := range r.Notes {
		docxPara(f, "- "+note)
	}

	docxHeading(f, "任务执行")
	docxPara(f, fmt.Sprintf("项目累计 %d 个扫描任务：运行中 %d、排队中 %d、已完成 %d、失败 %d、其他 %d。",
		r.TaskSummary.Total, r.TaskSummary.Running, r.TaskSummary.Pending,
		r.TaskSummary.Completed, r.TaskSummary.Failed, r.TaskSummary.Other))
	if len(r.Tasks) > 0 {
		rows := make([][]string, 0, len(r.Tasks))
		for _, t := range r.Tasks {
			rows = append(rows, []string{t.Name, t.TaskType, TaskStatusLabel(t.Status),
				fmt.Sprintf("%d%%", t.Progress), t.CreatedAt})
		}
		writeDocxTable(f, docxTableSpec{
			header: []string{"任务", "类型", "状态", "进度", "创建时间"}, rows: rows,
		})
		docxPara(f, "注：存在未完成任务时，本报告基于当前已落库数据生成。")
	}

	docxHeading(f, "域名清单")
	if len(r.Domains) > 0 {
		rows := make([][]string, 0, len(r.Domains))
		for _, d := range r.Domains {
			seed := ""
			if d.IsSeedBase {
				seed = "是"
			}
			rows = append(rows, []string{d.Host, seed, fmt.Sprint(d.SiteCount),
				fmt.Sprint(d.Reachable), d.Ports, d.LastSeen})
		}
		writeDocxTable(f, docxTableSpec{
			header: []string{"域名", "根域种子", "站点数", "可达", "端口", "最近观测"}, rows: rows,
		})
	} else {
		docxPara(f, "（暂无域名资产。）")
	}

	docxHeading(f, "站点清单")
	if len(r.Sites) > 0 {
		rows := make([][]string, 0, len(r.Sites))
		for _, s := range r.Sites {
			entry := s.Scheme
			if s.Port > 0 {
				entry = fmt.Sprintf("%s:%d", s.Scheme, s.Port)
			}
			rows = append(rows, []string{s.Host, s.IP, entry, assetStateLabel(s.State),
				s.Title, s.Tech, s.Discovery, s.FirstSeen})
		}
		writeDocxTable(f, docxTableSpec{
			header: []string{"主机", "IP", "入口", "状态", "标题", "指纹", "来源", "首见"}, rows: rows,
		})
	} else {
		docxPara(f, "（该项目暂无站点资产。）")
	}

	docxHeading(f, "限制与说明")
	for _, lim := range r.Limitations {
		docxPara(f, "- "+lim)
	}
	if r.Truncated != "" {
		docxPara(f, r.Truncated)
	}

	var buf bytes.Buffer
	if _, err := f.WriteTo(&buf); err != nil {
		return nil, fmt.Errorf("生成 DOCX 失败: %w", err)
	}
	return buf.Bytes(), nil
}

// RenderVulnDocx 渲染漏洞报告为 Word 文档（执行摘要 + 漏洞清单 + 明细）。
func RenderVulnDocx(r *Report) ([]byte, error) {
	r.normalize()
	f := docx.New()

	p := f.AddParagraph()
	t := p.AddText(r.Title)
	t.Bold()
	t.Size("36")
	docxPara(f, fmt.Sprintf("项目：%s  生成时间：%s", r.ProjectName, r.GeneratedAt))
	if r.Range != "" {
		docxPara(f, "测试范围："+r.Range)
	}

	docxHeading(f, "执行摘要")
	docxPara(f, fmt.Sprintf("共收录漏洞 %d 个，风险等级：%s。%s",
		r.Stats.Total, r.Stats.TopSeverity, r.Stats.StatusSummary))
	if r.SummaryConclusion != "" {
		docxPara(f, r.SummaryConclusion)
	}
	for _, item := range r.SummaryItems {
		docxPara(f, "- "+item)
	}

	docxHeading(f, "漏洞清单")
	if len(r.Vulns) > 0 {
		rows := make([][]string, 0, len(r.Vulns))
		for _, v := range r.Vulns {
			rows = append(rows, []string{fmt.Sprint(v.Number), v.Title, sevLabel(v.Severity),
				v.Status, v.Target, v.CreatedAt})
		}
		writeDocxTable(f, docxTableSpec{
			header: []string{"编号", "标题", "严重度", "状态", "目标", "发现时间"}, rows: rows,
		})
	} else {
		docxPara(f, "（工作区内暂无符合条件的漏洞。）")
	}

	docxHeading(f, "漏洞明细")
	for _, v := range r.Vulns {
		docxPara(f, fmt.Sprintf("%d. [%s] %s", v.Number, sevLabel(v.Severity), v.Title))
		docxPara(f, "目标："+v.Target)
		if v.Impact != "" {
			docxPara(f, "影响："+v.Impact)
		}
		if v.Recommendation != "" {
			docxPara(f, "修复建议："+v.Recommendation)
		}
		if v.CreatedAt != "" {
			docxPara(f, "发现时间："+v.CreatedAt)
		}
	}

	var buf bytes.Buffer
	if _, err := f.WriteTo(&buf); err != nil {
		return nil, fmt.Errorf("生成 DOCX 失败: %w", err)
	}
	return buf.Bytes(), nil
}
