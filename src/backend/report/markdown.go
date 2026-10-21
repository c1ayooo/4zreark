package report

import (
	"fmt"
	"strings"
)

// RenderMarkdown 渲染项目/会话级报告为自包含 Markdown（请求包全量、截图 base64 嵌入，可直接复制粘贴或渲染器打开）。
// 章节与证据按 Report.Profile 裁剪，与 HTML 渲染保持同一套交付口径。
func RenderMarkdown(r *Report) ([]byte, error) {
	r.normalize()
	p := r.Profile
	no := r.SectionNo

	var b strings.Builder
	b.WriteString("# " + r.Title + "\n\n")
	b.WriteString("| 项目 | " + r.ProjectName + " |\n")
	if p.CoverSubject != "" {
		b.WriteString("| 报告类型 | " + p.CoverSubject + " |\n")
	}
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
	if r.Stats.Total > 0 {
		b.WriteString("| 风险等级 | " + r.Stats.TopSeverity + " |\n")
	}
	b.WriteString(fmt.Sprintf("| 发现漏洞 | %d 个（严重 %d / 高危 %d / 中危 %d / 低危 %d） |\n",
		r.Stats.Total,
		r.Stats.BySeverity["critical"],
		r.Stats.BySeverity["high"],
		r.Stats.BySeverity["medium"],
		r.Stats.BySeverity["low"],
	))
	b.WriteString("| 生成时间 | " + r.GeneratedAt + " |\n")
	b.WriteString("| 生成引擎 | 4zreark |\n\n")

	// 执行摘要
	b.WriteString("## " + no.Summary + "执行摘要\n\n")
	if r.SummaryConclusion != "" {
		b.WriteString("> " + r.SummaryConclusion + "\n\n")
	}
	b.WriteString(fmt.Sprintf("本次测试共发现 **%d** 个漏洞，涉及 %d 个测试会话。\n\n",
		r.Stats.Total, r.Stats.Conversations))
	for _, item := range r.SummaryItems {
		b.WriteString("- " + item + "\n")
	}
	b.WriteString("\n")

	// 测试范围
	b.WriteString("## " + no.Scope + "测试范围与评级标准\n\n")
	b.WriteString("| 项目 | 说明 |\n|---|---|\n")
	b.WriteString("| 测试范围 | " + r.Range + " |\n")
	b.WriteString(fmt.Sprintf("| 测试会话 | %d 个 |\n\n", r.Stats.Conversations))
	if p.ShowRatingStandard {
		b.WriteString("| 等级 | 判定标准 |\n|---|---|\n")
		b.WriteString("| critical | 可直接导致系统失陷、核心数据泄露或具备无条件的远程利用能力 |\n")
		b.WriteString("| high | 可获取敏感数据或关键权限，或需较少前置条件即可显著影响机密性/完整性/可用性 |\n")
		b.WriteString("| medium | 需一定前置条件或组合利用，影响范围与程度有限 |\n")
		b.WriteString("| low | 信息泄露类、影响轻微，可作为进一步攻击的辅助条件 |\n")
		b.WriteString("| info | 安全观察项，不构成直接风险 |\n\n")
	}
	if p.ShowLimitations && len(r.Limitations) > 0 {
		b.WriteString("**范围限制与授权边界：**\n\n")
		for _, lim := range r.Limitations {
			b.WriteString("- " + lim + "\n")
		}
		b.WriteString("\n")
	}

	// 资产概览
	if p.ShowAssetOverview && r.AssetOverview != nil && r.AssetOverview.Total > 0 {
		b.WriteString("## " + no.Stats + "资产概览\n\n")
		b.WriteString(fmt.Sprintf("纳入资产共 **%d** 条，涉及主机 %d 台、域名 %d 个。\n\n", r.AssetOverview.Total, r.AssetOverview.Hosts, r.AssetOverview.Domains))
		if len(r.AssetOverview.Services) > 0 {
			b.WriteString("| 协议 | 端口 | 资产数 |\n|---|---|---|\n")
			for _, svc := range r.AssetOverview.Services {
				b.WriteString(fmt.Sprintf("| %s | %d | %d |\n", svc.Protocol, svc.Port, svc.Count))
			}
			b.WriteString("\n")
		}
	}

	// 漏洞总览
	if p.ShowOverview && len(r.Overview) > 0 {
		b.WriteString("## " + no.Vulns + "漏洞总览\n\n")
		b.WriteString("| # | 漏洞标题 | 等级 | 状态 | 目标 |\n|---|---|---|---|---|\n")
		for _, o := range r.Overview {
			b.WriteString(fmt.Sprintf("| #%d | %s | %s | %s | %s |\n", o.Number, o.Title, o.Severity, o.Status, o.Target))
		}
		b.WriteString("\n")
	}

	// 漏洞明细
	b.WriteString("## " + no.Details + "漏洞明细\n\n")
	for _, v := range r.Vulns {
		b.WriteString(fmt.Sprintf("### #%d %s\n\n", v.Number, v.Title))
		b.WriteString(fmt.Sprintf("- **严重程度:** %s\n- **状态:** %s\n- **类型:** %s\n- **目标:** %s\n- **发现时间:** %s\n\n",
			v.Severity, v.Status, v.Type, v.Target, v.CreatedAt))
		if v.Description != "" {
			b.WriteString("**漏洞描述：**\n\n" + v.Description + "\n\n")
		}
		if v.Preconditions != "" {
			b.WriteString("**前置条件：**\n\n" + v.Preconditions + "\n\n")
		}
		if v.ReproductionSteps != "" {
			b.WriteString("**复现步骤：**\n\n" + v.ReproductionSteps + "\n\n")
		}
		if p.ShowEvidence {
			// POC / 请求包
			if v.EvidencePacket != nil {
				ep := v.EvidencePacket
				b.WriteString("**POC / 证据（" + ep.Title + "）：**\n\n")
				if ep.ReqText != "" {
					b.WriteString("**请求：**\n\n```http\n" + ep.ReqText + "\n```\n\n")
				}
				// 响应统一按 smart 节选呈现（含省略标注）；markdown 无 HTML details 展开能力，
				// 不再回退全量——完整响应见交付包证据附件，按证据 ID 复核。
				if ep.RespText != "" {
					b.WriteString("**响应：**\n\n```http\n" + ep.RespText + "\n```\n\n")
				}
			} else if v.Evidence != "" {
				b.WriteString("**证据 / POC：**\n\n```\n" + v.Evidence + "\n```\n\n")
			}
			if v.PoCScript != "" {
				b.WriteString("**一键验证脚本：**\n\n```\n" + v.PoCScript + "\n```\n\n")
			}
			// 证据包（含截图/报文对比）
			for _, eg := range v.EvidenceGroups {
				for _, it := range eg.Items {
					if it.Kind == "screenshot" && it.ImageSrc != "" {
						b.WriteString(fmt.Sprintf("![%s](%s)\n\n", it.Title, it.ImageSrc))
					} else if it.Kind == "http" {
						if it.ReqText != "" {
							b.WriteString("**" + it.Title + " — 请求：**\n\n```http\n" + it.ReqText + "\n```\n\n")
						}
						if it.RespText != "" {
							b.WriteString("**" + it.Title + " — 响应：**\n\n```http\n" + it.RespText + "\n```\n\n")
						}
					} else if it.Content != "" {
						b.WriteString("**" + it.Title + "：**\n\n```\n" + it.Content + "\n```\n\n")
					}
				}
			}
		}
		if v.Impact != "" {
			b.WriteString("**影响：**\n\n" + v.Impact + "\n\n")
		}
		if v.Recommendation != "" {
			b.WriteString("**修复建议：**\n\n" + v.Recommendation + "\n\n")
		}
		if v.RetestNotes != "" {
			b.WriteString("**复测方式：**\n\n" + v.RetestNotes + "\n\n")
		}
		b.WriteString("---\n\n")
	}

	// 修复优先级
	if p.ShowRemediation && len(r.Remediation) > 0 {
		b.WriteString("## " + no.Remediation + "修复优先级建议\n\n")
		for _, g := range r.Remediation {
			b.WriteString("### " + g.Priority + "\n\n")
			b.WriteString(g.Hint + "\n\n")
			for _, it := range g.Items {
				b.WriteString(fmt.Sprintf("- %s #%d %s\n", it.Severity, it.Number, it.Title))
			}
			b.WriteString("\n")
		}
	}

	// 事实与线索
	if p.ShowFacts && (len(r.Facts) > 0 || len(r.Tentative) > 0) {
		b.WriteString("## " + no.Facts + "事实与未确认线索\n\n")
		if len(r.Facts) > 0 {
			b.WriteString("| 关键项 | 摘要 | 分类 | 置信度 |\n|---|---|---|---|\n")
			for _, f := range r.Facts {
				b.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n", f.Key, f.Summary, f.Category, f.Confidence))
			}
			b.WriteString("\n")
		}
		if len(r.Tentative) > 0 {
			b.WriteString("**未确认线索（tentative，不进漏洞结论）：**\n\n")
			b.WriteString("| 关键项 | 摘要 | 分类 |\n|---|---|---|\n")
			for _, f := range r.Tentative {
				b.WriteString(fmt.Sprintf("| %s | %s | %s |\n", f.Key, f.Summary, f.Category))
			}
			b.WriteString("\n")
		}
	}

	// 工具统计
	if p.ShowToolStats && len(r.ToolStats) > 0 {
		b.WriteString("## " + no.Tools + "工具执行统计\n\n")
		b.WriteString("| 工具 | 调用次数 | 成功 | 平均耗时 |\n|---|---|---|---|\n")
		for _, ts := range r.ToolStats {
			b.WriteString(fmt.Sprintf("| %s | %d | %d | %dms |\n", ts.Name, ts.Calls, ts.OKCount, ts.AvgMs))
		}
		b.WriteString("\n")
	}

	// 攻击链（无链路数据或模板不启用时整章省略）
	if p.ShowAttackChains && len(r.AttackChains) > 0 {
		b.WriteString("## " + no.Chains + "攻击链\n\n")
		for _, c := range r.AttackChains {
			b.WriteString("**" + c.ConversationTitle + "**\n\n")
			for i, n := range c.Nodes {
				if n.Risk > 0 {
					b.WriteString(fmt.Sprintf("%d. %s（%s · risk %d）\n", i+1, n.Label, n.Type, n.Risk))
				} else {
					b.WriteString(fmt.Sprintf("%d. %s（%s）\n", i+1, n.Label, n.Type))
				}
			}
			if len(c.Edges) > 0 {
				parts := make([]string, 0, len(c.Edges))
				for _, e := range c.Edges {
					parts = append(parts, e[0]+" → "+e[1])
				}
				b.WriteString("\n链路关系：" + strings.Join(parts, "；") + "\n")
			}
			b.WriteString("\n")
		}
	}

	// 附录：证据索引
	// minimal 档只出索引表（条目已在组装层裁剪为空），smart/full 档在表后附详情全文。
	if p.ShowAppendix && len(r.Appendix) > 0 {
		b.WriteString("## 附录：证据索引\n\n")
		b.WriteString("| # | 证据 ID | 标题 | 来源工具 | 时间 |\n|---|---|---|---|---|\n")
		for i, it := range r.Appendix {
			title := it.Title
			if it.Label != "" {
				title += " · " + it.Label
			}
			b.WriteString(fmt.Sprintf("| %d | %s | %s | %s | %s |\n", i+1, it.ID, title, it.SourceTool, it.CreatedAt))
		}
		b.WriteString("\n")
		hasDetail := false
		for _, it := range r.Appendix {
			if it.ImageSrc != "" || it.Content != "" || it.ReqText != "" {
				hasDetail = true
				break
			}
		}
		if hasDetail {
			b.WriteString("**证据详情：**\n\n")
			for _, it := range r.Appendix {
				b.WriteString(fmt.Sprintf("**%s %s** （%s · %s · %s）\n\n", it.Title, it.Label, it.SourceTool, it.CreatedAt, it.ID))
				if it.Kind == "screenshot" && it.ImageSrc != "" {
					b.WriteString(fmt.Sprintf("![%s](%s)\n\n", it.Title, it.ImageSrc))
				} else if it.ReqText != "" || it.RespText != "" {
					if it.ReqText != "" {
						b.WriteString("```http\n" + it.ReqText + "\n```\n\n")
					}
					if it.RespText != "" {
						b.WriteString("```http\n" + it.RespText + "\n```\n\n")
					}
				} else if it.Content != "" {
					b.WriteString("```\n" + it.Content + "\n```\n\n")
				}
			}
		}
	}

	b.WriteString("\n---\n\n*本报告由 4zreark 自动生成（交付模板：" + p.Name + "）。证据数据包存于平台证据库，可按证据 ID 复核。*\n")

	return []byte(b.String()), nil
}
