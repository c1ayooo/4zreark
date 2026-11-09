package service

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/internal/browser"
	"github.com/c1ayooo/4zreark/repo"
)

// 提交哨兵发现导出（Markdown / PDF）。
//
// Markdown 直接拼装，交付给文档系统或人工阅读；PDF 走「HTML → chrome 无头
// 打印」链路（report.RenderPDF 同款做法）：中文渲染交给系统字体，不引入
// 纯 Go PDF 库的 CJK 字体内嵌问题。找不到浏览器时返回明确错误而不是
// 静默降级——调用方（handler）会把提示透给前端，用户可改用 Markdown 导出。

// VulnClassLabels 是 vuln_class 枚举的中文展示名（导出与通知共用）。
var VulnClassLabels = map[string]string{
	"OOB_READ":         "越界读",
	"OOB_WRITE":        "越界写",
	"UAF":              "释放后使用",
	"DOUBLE_FREE":      "双重释放",
	"BUFFER_OVERFLOW":  "缓冲区溢出",
	"INTEGER_OVERFLOW": "整数溢出",
	"NULL_DEREF":       "空指针解引用",
	"TYPE_CONFUSION":   "类型混淆",
	"RACE":             "竞态条件",
	"SQLI":             "SQL注入",
	"CMDI":             "命令注入",
	"RCE":              "远程代码执行",
	"INJECTION":        "其它注入",
	"SSRF":             "服务端请求伪造",
	"XXE":              "XML外部实体",
	"PATH_TRAVERSAL":   "路径穿越",
	"DESERIALIZATION":  "反序列化",
	"AUTH_BYPASS":      "认证绕过",
	"PRIV_ESC":         "权限提升",
	"INFO_LEAK":        "信息泄露",
	"DOS":              "拒绝服务",
	"OTHER":            "其它",
}

// VulnClassLabel 取中文展示名，未登记的枚举原样返回。
func VulnClassLabel(class string) string {
	if l, ok := VulnClassLabels[strings.ToUpper(strings.TrimSpace(class))]; ok {
		return l
	}
	return class
}

var severityLabels = map[string]string{
	"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "提示",
}

func severityLabel(s string) string {
	if l, ok := severityLabels[strings.ToLower(strings.TrimSpace(s))]; ok {
		return l
	}
	return s
}

// findingStatusLabel 与前端 finding 状态枚举对齐。
var findingStatusLabel = map[string]string{
	"open": "待处理", "confirmed": "已确认", "ignored": "已忽略", "resolved": "已处置",
}

func findingStatus(s string) string {
	if l, ok := findingStatusLabel[strings.ToLower(strings.TrimSpace(s))]; ok {
		return l
	}
	return s
}

// ExportFindingsLimit 是单次导出的发现条数上限：导出是给人看的报告，
// 超过这个量级说明筛选太宽，应让用户收窄条件而不是生成几百页 PDF。
const ExportFindingsLimit = 500

// ExportSentinelFindings 按筛选条件导出发现报告。
// format 仅支持 md / pdf；返回文件名、MIME 与内容字节。
func ExportSentinelFindings(ctx context.Context, filter repo.FindingFilter, format string) (string, string, []byte, error) {
	format = strings.ToLower(strings.TrimSpace(format))
	if format != "md" && format != "pdf" {
		return "", "", nil, fmt.Errorf("不支持的导出格式 %q（仅支持 md / pdf）", format)
	}

	rows, err := repo.Default().Sentinel().ListFindingsForExport(ctx, filter, ExportFindingsLimit)
	if err != nil {
		return "", "", nil, fmt.Errorf("查询导出数据失败: %w", err)
	}

	desc := filterDescription(filter)
	name := "sentinel-findings-" + time.Now().Format("20060102-1504")
	if format == "md" {
		return name + ".md", "text/markdown; charset=utf-8", []byte(buildFindingsMarkdown(rows, desc)), nil
	}

	html := buildFindingsHTML(rows, desc)
	pdf, err := htmlToPDF(html)
	if err != nil {
		return "", "", nil, err
	}
	return name + ".pdf", "application/pdf", pdf, nil
}

// filterDescription 生成筛选条件的人读描述，写进报告头。
func filterDescription(f repo.FindingFilter) string {
	parts := make([]string, 0, 5)
	if len(f.VulnClasses) > 0 {
		cls := make([]string, 0, len(f.VulnClasses))
		for _, c := range f.VulnClasses {
			cls = append(cls, VulnClassLabel(c))
		}
		parts = append(parts, "类型："+strings.Join(cls, "/"))
	}
	if f.MinSeverity != "" {
		parts = append(parts, "严重度≥"+severityLabel(f.MinSeverity))
	}
	if f.Severity != "" {
		parts = append(parts, "严重度="+severityLabel(f.Severity))
	}
	if f.Status != "" {
		parts = append(parts, "状态："+findingStatus(f.Status))
	}
	if f.RepoID != "" {
		parts = append(parts, "仓库限定")
	}
	if len(parts) == 0 {
		return "全部发现"
	}
	return strings.Join(parts, "，")
}

func truncateText(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n]) + "…"
}

func snippetsOf(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var out []string
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}
	return out
}

// buildFindingsMarkdown 拼装 Markdown 报告。每条发现一个二级标题，
// 三段式说明（攻击路径/影响/修复依据）与摘录片段原样保留，便于二次加工。
func buildFindingsMarkdown(rows []*repo.FindingExportRow, filterDesc string) string {
	var b strings.Builder
	b.WriteString("# 提交哨兵 · 漏洞发现报告\n\n")
	b.WriteString(fmt.Sprintf("- 生成时间：%s\n- 筛选条件：%s\n- 发现条数：%d\n\n",
		time.Now().Format("2006-01-02 15:04"), filterDesc, len(rows)))
	if len(rows) == 0 {
		b.WriteString("_当前筛选条件下没有发现。_\n")
		return b.String()
	}

	for i, r := range rows {
		b.WriteString(fmt.Sprintf("## %d. %s\n\n", i+1, truncateText(r.Title, 120)))
		b.WriteString("| 字段 | 值 |\n|---|---|\n")
		b.WriteString(fmt.Sprintf("| 漏洞类型 | %s（%s） |\n", VulnClassLabel(r.VulnClass), r.VulnClass))
		b.WriteString(fmt.Sprintf("| 严重度 | %s（%s） |\n", severityLabel(r.Severity), r.Severity))
		b.WriteString(fmt.Sprintf("| 状态 | %s |\n", findingStatus(r.Status)))
		b.WriteString(fmt.Sprintf("| 仓库 | %s |\n", r.RepoFullName))
		sha := r.SHA
		if len(sha) > 10 {
			sha = sha[:10]
		}
		b.WriteString(fmt.Sprintf("| 来源提交 | `%s` %s |\n", sha, truncateText(r.Subject, 80)))
		b.WriteString(fmt.Sprintf("| 发现时间 | %s |\n", r.CreatedAt.Format("2006-01-02 15:04")))
		if r.Model != "" {
			b.WriteString(fmt.Sprintf("| 判定模型 | %s（置信度 %.0f%%） |\n", r.Model, r.Confidence*100))
		}
		b.WriteString("\n")

		if r.Detail != "" {
			fmt.Fprintf(&b, "**说明**：%s\n\n", truncateText(r.Detail, 800))
		}
		// 判定详情：优先三段式，旧判定退回 reasoning。
		if r.AttackPath != "" || r.Impact != "" || r.FixEvidence != "" {
			if r.AttackPath != "" {
				fmt.Fprintf(&b, "**攻击路径**：%s\n\n", r.AttackPath)
			}
			if r.Impact != "" {
				fmt.Fprintf(&b, "**影响**：%s\n\n", r.Impact)
			}
			if r.FixEvidence != "" {
				fmt.Fprintf(&b, "**修复依据**：%s\n\n", r.FixEvidence)
			}
		} else if r.Reasoning != "" {
			fmt.Fprintf(&b, "**判定依据**：%s\n\n", truncateText(r.Reasoning, 800))
		}

		if snips := snippetsOf(r.Snippets); len(snips) > 0 {
			b.WriteString("**关键代码摘录**：\n\n")
			for _, snip := range snips {
				fmt.Fprintf(&b, "```diff\n%s\n```\n\n", strings.Trim(snip, "\n"))
			}
		}
		b.WriteString("---\n\n")
	}
	return b.String()
}

// buildFindingsHTML 渲染打印友好的自包含 HTML（内嵌 CSS），供 chrome 转 PDF。
func buildFindingsHTML(rows []*repo.FindingExportRow, filterDesc string) string {
	var b strings.Builder
	b.WriteString(`<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><style>
body { font-family: "Noto Sans CJK SC", "WenQuanYi Micro Hei", "Microsoft YaHei", sans-serif;
       font-size: 12px; color: #1f2328; margin: 32px 40px; line-height: 1.65; }
h1 { font-size: 20px; border-bottom: 2px solid #1f2328; padding-bottom: 8px; }
h2 { font-size: 15px; margin-top: 28px; background: #f6f8fa; padding: 6px 10px;
     border-left: 4px solid #0969da; }
.meta { color: #59636e; font-size: 11px; }
table { border-collapse: collapse; margin: 8px 0; width: 100%; }
td { border: 1px solid #d1d9e0; padding: 3px 8px; font-size: 11px; }
td.k { background: #f6f8fa; color: #59636e; width: 90px; white-space: nowrap; }
.sev-critical { color: #cf222e; font-weight: 700; }
.sev-high { color: #bc4c00; font-weight: 700; }
.sev-medium { color: #9a6700; font-weight: 600; }
.sev-low { color: #0550ae; }
.sev-info { color: #59636e; }
pre { background: #f6f8fa; border: 1px solid #d1d9e0; border-radius: 4px;
      padding: 8px; font-size: 10.5px; white-space: pre-wrap; word-break: break-all; }
.section { margin: 6px 0; }
.label { font-weight: 600; }
hr { border: none; border-top: 1px solid #d1d9e0; margin: 20px 0; }
</style></head><body>`)
	b.WriteString("<h1>提交哨兵 · 漏洞发现报告</h1>")
	b.WriteString(fmt.Sprintf(`<p class="meta">生成时间：%s　|　筛选条件：%s　|　发现条数：%d</p>`,
		time.Now().Format("2006-01-02 15:04"), filterDesc, len(rows)))
	if len(rows) == 0 {
		b.WriteString(`<p class="meta">当前筛选条件下没有发现。</p></body></html>`)
		return b.String()
	}

	for i, r := range rows {
		sha := r.SHA
		if len(sha) > 10 {
			sha = sha[:10]
		}
		b.WriteString(fmt.Sprintf("<h2>%d. %s</h2>", i+1, htmlEscape(truncateText(r.Title, 120))))
		b.WriteString("<table>")
		b.WriteString(fmt.Sprintf("<tr><td class='k'>漏洞类型</td><td>%s（%s）</td></tr>",
			htmlEscape(VulnClassLabel(r.VulnClass)), htmlEscape(r.VulnClass)))
		b.WriteString(fmt.Sprintf("<tr><td class='k'>严重度</td><td class='sev-%s'>%s（%s）</td></tr>",
			htmlEscape(strings.ToLower(r.Severity)), htmlEscape(severityLabel(r.Severity)), htmlEscape(r.Severity)))
		b.WriteString(fmt.Sprintf("<tr><td class='k'>状态</td><td>%s</td></tr>", htmlEscape(findingStatus(r.Status))))
		b.WriteString(fmt.Sprintf("<tr><td class='k'>仓库 / 提交</td><td>%s　<code>%s</code> %s</td></tr>",
			htmlEscape(r.RepoFullName), htmlEscape(sha), htmlEscape(truncateText(r.Subject, 80))))
		b.WriteString(fmt.Sprintf("<tr><td class='k'>发现时间</td><td>%s</td></tr>",
			r.CreatedAt.Format("2006-01-02 15:04")))
		if r.Model != "" {
			b.WriteString(fmt.Sprintf("<tr><td class='k'>判定模型</td><td>%s（置信度 %.0f%%）</td></tr>",
				htmlEscape(r.Model), r.Confidence*100))
		}
		b.WriteString("</table>")

		if r.Detail != "" {
			fmt.Fprintf(&b, "<div class='section'><span class='label'>说明：</span>%s</div>",
				htmlEscape(truncateText(r.Detail, 800)))
		}
		if r.AttackPath != "" || r.Impact != "" || r.FixEvidence != "" {
			if r.AttackPath != "" {
				fmt.Fprintf(&b, "<div class='section'><span class='label'>攻击路径：</span>%s</div>", htmlEscape(r.AttackPath))
			}
			if r.Impact != "" {
				fmt.Fprintf(&b, "<div class='section'><span class='label'>影响：</span>%s</div>", htmlEscape(r.Impact))
			}
			if r.FixEvidence != "" {
				fmt.Fprintf(&b, "<div class='section'><span class='label'>修复依据：</span>%s</div>", htmlEscape(r.FixEvidence))
			}
		} else if r.Reasoning != "" {
			fmt.Fprintf(&b, "<div class='section'><span class='label'>判定依据：</span>%s</div>",
				htmlEscape(truncateText(r.Reasoning, 800)))
		}
		for _, snip := range snippetsOf(r.Snippets) {
			fmt.Fprintf(&b, "<pre>%s</pre>", htmlEscape(strings.Trim(snip, "\n")))
		}
		b.WriteString("<hr>")
	}
	b.WriteString("</body></html>")
	return b.String()
}

func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&#34;", "'", "&#39;")
	return r.Replace(s)
}

// htmlToPDF 用 chrome 无头把自包含 HTML 转成 PDF 字节（report.RenderPDF 同款
// 探测与参数；找不到浏览器返回明确错误，由 handler 透传给前端）。
func htmlToPDF(html string) ([]byte, error) {
	bin := browser.FindChrome()
	if bin == "" {
		return nil, fmt.Errorf("未检测到可用浏览器（chrome/chromium），无法导出 PDF；可改用 Markdown 导出，或部署浏览器后重试")
	}

	dir, err := os.MkdirTemp("", "zre-export-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	htmlPath := filepath.Join(dir, "report.html")
	pdfPath := filepath.Join(dir, "report.pdf")
	if err := os.WriteFile(htmlPath, []byte(html), 0o600); err != nil {
		return nil, err
	}

	// file:// 必须拼绝对路径；保持真实 HOME 以免 fontconfig 扫不到中文字体。
	absHTML, err := filepath.Abs(htmlPath)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(bin,
		"--headless", "--disable-gpu", "--no-sandbox",
		"--no-first-run", "--disable-crashpad", "--disable-dev-shm-usage",
		"--no-pdf-header-footer",
		"--run-all-compositor-stages-before-draw",
		"--virtual-time-budget=10000",
		"--print-to-pdf="+pdfPath,
		"file://"+absHTML)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("chrome 转 PDF 失败: %w: %s", err, string(out))
	}
	return os.ReadFile(pdfPath)
}
