// Package report 渗透测试报告引擎：从现有库（项目/漏洞/证据/攻击链/工具执行）
// 组装数据，渲染自包含 HTML 报告；系统存在 chrome/chromium 时自动转 PDF。
package report

import (
	"bytes"
	"fmt"
	"html/template"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/c1ayooo/4zreark/internal/browser"
	"github.com/c1ayooo/4zreark/internal/httpprobe"
)

// ── 数据模型（组装层，与 DB 结构解耦） ──

type Report struct {
	Title             string
	ProjectName       string
	Description       string
	GeneratedAt       string
	Range             string // 测试范围（时间窗/目标）
	Profile           Profile
	Delivery          DeliveryInfo
	SectionNo         SectionNumbers
	Stats             Stats
	SummaryItems      []string      // 风险总览要点（模板渲染 top 风险）
	SummaryConclusion string        // 结论性总体评价（规则生成，甲方报告执行摘要首段）
	Overview          []OverviewRow // 漏洞总览表（项目整体报告才有；锚点跳转明细）
	Vulns             []VulnSection
	Remediation       []RemediationGroup // 修复优先级路线（按严重度三档归组）
	AssetOverview     *AssetOverview     // 资产概览（项目级报告）
	AttackChains      []ChainSection
	Facts             []FactItem
	Tentative         []FactItem // 未确认线索（confidence=tentative 的黑板条目，不构成正式漏洞）
	Limitations       []string   // 范围限制与授权边界（scope exclude/说明/未配置提示）
	FactsNote         string     // 事实章节为空时的占位说明（如会话报告指向项目报告）
	AssetNote         string     // 资产概览为空时的占位说明
	ToolStats         []ToolStat
	Appendix          []EvidenceItem // 附录：全量证据索引
}

// RemediationGroup 修复优先级分档
type RemediationGroup struct {
	Priority string // 立即处置 / 尽快修复 / 计划内修复
	Hint     string // 建议时限说明
	Items    []RemediationItem
}

type RemediationItem struct {
	Number   int
	Title    string
	Severity string
}

// AssetOverview 资产概览（一页：总量/主机/域名 + 端口服务分布）
type AssetOverview struct {
	Total    int
	Hosts    int
	Domains  int
	Services []AssetServiceCount
}

type AssetServiceCount struct {
	Protocol string
	Port     int
	Count    int
}

// OverviewRow 漏洞总览表行：项目整体报告的导航入口，锚点跳转到漏洞明细
type OverviewRow struct {
	Number        int
	Title         string
	Severity      string
	Status        string
	Target        string
	EvidenceCount int
}

type Stats struct {
	Total         int
	BySeverity    map[string]int
	SeverityDist  []SevCount // 严重度分布（有序，供摘要页 CSS 条形图）
	ByStatus      map[string]int
	StatusSummary string // 状态分布一句话（组装层拼好，如 "待处理 3 · 已确认 2"）
	TopSeverity   string // 风险等级（按最高严重度）
	Conversations int
	FactCount     int
	ToolCalls     int
}

// SevCount 严重度分布行（Percent 为占总量百分比，条形图宽）
type SevCount struct {
	Severity string
	Count    int
	Percent  int
}

type VulnSection struct {
	Number            int
	ID                string
	Title             string
	Severity          string
	Status            string
	Type              string
	Target            string
	Description       string
	Preconditions     string
	ReproductionSteps string
	PoCScript         string        // 一键验证脚本（选填，与 SRC 导出同源）
	Evidence          string        // 漏洞自身的 POC/证据字段（非报文格式时按文本渲染）
	EvidencePacket    *EvidenceItem // Evidence 字段是原始报文/curl 时转为完整报文卡
	Impact            string
	Recommendation    string
	RetestNotes       string
	CreatedAt         string
	EvidenceGroups    []EvidenceGroup // 证据包（含数据包对比组）
}

// EvidenceGroup 越权/多包对比组：GroupKey 非空且多条 → 报告渲染对比卡
type EvidenceGroup struct {
	GroupKey string
	Title    string
	Items    []EvidenceItem
}

type EvidenceItem struct {
	ID         string
	Kind       string // text | http | screenshot
	Title      string
	Label      string
	GroupKey   string
	SourceTool string
	CreatedAt  string
	SortOrder  int `json:"-"` // 组内排序（组装层从证据库透传）
	// http 报文（kind=http 时填充）：请求永远全量；RespText 按响应策略呈现，
	// RespFull 存完整响应（HTML details 展开用），RespOmitted 为 smart 节选省略的字节数；
	// RespHTML/RespFullHTML 为转义+关键区域高亮后的渲染版（pktPre 直接输出）
	ReqText      string
	RespText     string
	RespFull     string        `json:"-"`
	RespOmitted  int           `json:"-"`
	ProofHint    string        `json:"-"` // agent 标注的证明位置（透传自证据库）
	RespHTML     template.HTML `json:"-"` // 转义+关键区域高亮后的渲染版（pktPre 直接输出）
	RespFullHTML template.HTML `json:"-"`
	// text 类全文
	Content string
	// screenshot 类：data URI（base64 嵌入，自包含 HTML/PDF 直接呈现）
	ImageSrc string
}

type ChainSection struct {
	ConversationTitle string
	Nodes             []ChainNode
	Edges             [][2]string // label → label
}

type ChainNode struct {
	Type  string // tool / vulnerability / target / exploit
	Label string
	Risk  int
}

type FactItem struct {
	Key        string
	Category   string
	Summary    string
	Confidence string
}

type ToolStat struct {
	Name    string
	Calls   int
	OKCount int
	AvgMs   int64
}

// ── 渲染 ──

// RenderHTML 组装并渲染自包含 HTML（内嵌 CSS，打印分页友好）
func RenderHTML(r *Report) ([]byte, error) {
	r.normalize()
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"severityClass": severityClass,
		"seq":           func(i int) int { return i + 1 },
		// 截图 data URI 由组装层构造（标准 base64 编码，无用户可控字符），
		// html/template 的 URL 过滤默认拦 data: scheme，需显式声明安全
		"safeURL": func(s string) template.URL { return template.URL(s) },
	}).Parse(reportTemplate)
	if err != nil {
		return nil, fmt.Errorf("解析报告模板失败: %w", err)
	}
	// 报文分组已在组装层完成（VulnSection.EvidenceGroups）
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, r); err != nil {
		return nil, fmt.Errorf("渲染报告失败: %w", err)
	}
	return buf.Bytes(), nil
}

// RenderPDF 用系统 chrome/chromium 无头转 PDF，输出文件名与调用方 HTML 报告同名（<base>.pdf）；
// 找不到浏览器返回 ("", nil)（调用方回退 HTML）。
func RenderPDF(htmlBytes []byte, outDir, base string) (string, error) {
	bin := findChrome()
	if bin == "" {
		return "", nil
	}
	if err := os.MkdirAll(outDir, 0o750); err != nil {
		return "", err
	}
	// 临时 HTML 用点前缀的独立名字，避免与调用方已保存的 <base>.html 正式文件互相覆盖
	htmlPath := filepath.Join(outDir, "."+base+".pdf-tmp.html")
	pdfPath := filepath.Join(outDir, base+".pdf")
	if err := os.WriteFile(htmlPath, htmlBytes, 0o600); err != nil {
		return "", err
	}
	defer os.Remove(htmlPath) // PDF 生成后删临时 HTML（正式 HTML 由调用方另行保存）

	// 临时 HTML 必须转绝对路径再拼 file:// URL：outDir 可能是相对路径（如 "data/reports"），
	// 直接 "file://"+htmlPath 会得到 file://data/reports/...（缺斜杠、非绝对路径），
	// Chrome 把 "data" 当主机名解析失败 → 渲染出 ERR_INVALID_URL 错误页，PDF 打不开。
	absHTML, err := filepath.Abs(htmlPath)
	if err != nil {
		return "", fmt.Errorf("解析 HTML 绝对路径失败: %w", err)
	}

	// 保持真实 HOME：覆盖成临时目录会让 fontconfig 扫不到用户字体（~/.fonts），
	// 中文整体渲染成豆腐块。--no-first-run/--disable-crashpad/--disable-dev-shm-usage
	// 抑制首跑向导与崩溃上报写 HOME 的需求；WSL2 下 --user-data-dir 全新 profile 初始化会挂死，勿用。
	cmd := exec.Command(bin,
		"--headless", "--disable-gpu", "--no-sandbox",
		"--no-first-run", "--disable-crashpad", "--disable-dev-shm-usage",
		// 关闭浏览器默认打印页眉页脚：会带生成日期与临时 HTML 的 file:// 路径，交付件不可泄露
		"--no-pdf-header-footer",
		"--run-all-compositor-stages-before-draw",
		"--virtual-time-budget=10000",
		"--print-to-pdf="+pdfPath,
		"file://"+absHTML)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("chrome 转 PDF 失败: %w: %s", err, string(out))
	}
	if _, err := os.Stat(pdfPath); err != nil {
		return "", fmt.Errorf("PDF 未生成: %w", err)
	}
	return pdfPath, nil
}

// findChrome 浏览器探测委托给 browser 包（截图/PDF 共用同一探测逻辑）
func findChrome() string { return browser.FindChrome() }

func severityClass(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return "sev-critical"
	case "high":
		return "sev-high"
	case "medium":
		return "sev-medium"
	case "low":
		return "sev-low"
	default:
		return "sev-info"
	}
}

// SeverityRank 报告排序：严重度降序
func SeverityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	default:
		return 1
	}
}

// SortVulnsBySeverity 漏洞按严重度降序（同级按时间）
func SortVulnsBySeverity(vs []VulnSection) {
	sort.SliceStable(vs, func(i, j int) bool {
		ri, rj := SeverityRank(vs[i].Severity), SeverityRank(vs[j].Severity)
		if ri != rj {
			return ri > rj
		}
		return vs[i].CreatedAt < vs[j].CreatedAt
	})
}

// NewPacketItem 把漏洞自带 POC/证据文本转为完整报文卡：
// 内容是 http_probe 归档格式（=== REQUEST ===/=== RESPONSE ===）或 curl 命令时转为
// kind=http 的证据项（请求/响应切分，响应按 respMode 策略并高亮关键区域）；普通文本返回 ok=false。
// proofHint 为 agent 标注的证明位置（子串/正则，可空）。
func NewPacketItem(content, respMode, vulnType, proofHint string) (*EvidenceItem, bool) {
	c := strings.TrimSpace(content)
	if c == "" {
		return nil, false
	}
	hasMarker := strings.Contains(c, httpprobe.RequestMarker) || strings.Contains(c, httpprobe.ResponseMarker)
	if !hasMarker {
		transcript, ok := CurlToTranscript(c)
		if !ok {
			return nil, false
		}
		c = transcript
	}
	req, shown, full, omitted := ShapePacket(c, respMode)
	return &EvidenceItem{
		Kind:         "http",
		Title:        "POC 报文",
		Content:      c,
		ReqText:      req,
		RespText:     shown,
		RespFull:     full,
		RespOmitted:  omitted,
		RespHTML:     HighlightResponse(shown, req, vulnType, proofHint),
		RespFullHTML: HighlightResponse(full, req, vulnType, proofHint),
	}, true
}
