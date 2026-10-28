package report

import (
	"errors"
	"fmt"
	"strings"
)

// ErrInvalidRequest 表示报告参数不合法（API 层应返回 400）。
var ErrInvalidRequest = errors.New("报告参数不合法")

// InvalidRequest 构造一个带上下文的参数错误。
func InvalidRequest(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidRequest, fmt.Sprintf(format, args...))
}

// Profile 是一套交付模板：决定报告保留哪些章节、行数上限与封面口径。
// 同一份库内数据用不同 Profile 渲染，产出面向不同接收方的格式，
// 避免为「SRC 报送 / 客户交付 / 内部摘要」各写一套取数逻辑。
//
// Type 区分两类报告：
//
//	vuln  漏洞交付报告（Report + reportTemplate）
//	asset 信息收集 / 资产测绘报告（AssetReport + assetTemplate）
type Profile struct {
	ID          string   `json:"id"`
	Type        string   `json:"type"` // vuln | asset
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Formats     []string `json:"formats"`

	// MinSeverity 为空表示全等级；否则只保留不低于该等级的漏洞（vuln brief=high）。
	MinSeverity string `json:"min_severity,omitempty"`
	// MaxRows 限制清单章节的输出行数（资产报告用；0 = 不限制）。
	MaxRows int `json:"max_rows,omitempty"`

	ShowRatingStandard bool `json:"show_rating_standard"`
	ShowAssetOverview  bool `json:"show_asset_overview"`
	ShowOverview       bool `json:"show_overview"`
	ShowEvidence       bool `json:"show_evidence"`
	ShowRemediation    bool `json:"show_remediation"`
	ShowFacts          bool `json:"show_facts"`
	ShowToolStats      bool `json:"show_tool_stats"`
	ShowAttackChains   bool `json:"show_attack_chains"`
	ShowAppendix       bool `json:"show_appendix"`
	ShowLimitations    bool `json:"show_limitations"`

	// CoverSubject 是封面主标题的后缀，默认「渗透测试报告」。
	CoverSubject string `json:"cover_subject"`
}

// DeliveryInfo 是报告交付信息（封面与页脚），全部可选。
type DeliveryInfo struct {
	ClientName     string `json:"client_name,omitempty"`
	ReportNo       string `json:"report_no,omitempty"`
	Classification string `json:"classification,omitempty"`
	Tester         string `json:"tester,omitempty"`
	Contact        string `json:"contact,omitempty"`
}

// SectionNumbers 是当前模板下各章节的中文序号前缀（如「三、」）；未启用的章节为空。
// 字段名与章节语义绑定，两种报告各按自己的启用集合编号，隐藏章节不占号。
type SectionNumbers struct {
	Summary     string
	Scope       string
	Stats       string
	Domains     string
	Sites       string
	Tasks       string
	Vulns       string
	Details     string
	Remediation string
	Facts       string
	Tools       string
	Chains      string
}

var cnSectionNumbers = []string{"一", "二", "三", "四", "五", "六", "七", "八", "九", "十"}

func sectionPrefix(idx int) string {
	if idx >= 0 && idx < len(cnSectionNumbers) {
		return cnSectionNumbers[idx] + "、"
	}
	return ""
}

// SectionNumbers 按报告类型与启用章节顺序连续编号。
func (p Profile) SectionNumbers() SectionNumbers {
	if p.Type == "asset" {
		return p.assetSections()
	}
	return p.vulnSections()
}

func (p Profile) vulnSections() SectionNumbers {
	var out SectionNumbers
	next := 0
	pick := func(enabled bool) string {
		if !enabled {
			return ""
		}
		s := sectionPrefix(next)
		next++
		return s
	}
	out.Summary = pick(true)
	out.Scope = pick(true)
	out.Stats = pick(p.ShowAssetOverview)
	out.Vulns = pick(p.ShowOverview)
	out.Details = pick(true)
	out.Remediation = pick(p.ShowRemediation)
	out.Facts = pick(p.ShowFacts)
	out.Tools = pick(p.ShowToolStats)
	out.Chains = pick(p.ShowAttackChains)
	return out
}

func (p Profile) assetSections() SectionNumbers {
	var out SectionNumbers
	next := 0
	pick := func(enabled bool) string {
		if !enabled {
			return ""
		}
		s := sectionPrefix(next)
		next++
		return s
	}
	out.Summary = pick(true)
	out.Scope = pick(true)
	out.Stats = pick(true)
	out.Domains = pick(true)
	out.Sites = pick(true)
	out.Tasks = pick(true)
	return out
}

var vulnProfiles = map[string]Profile{
	"standard": {
		ID:                 "standard",
		Type:               "vuln",
		Name:               "客户交付版",
		Description:        "完整甲方交付格式：执行摘要、范围与评级、资产概览、漏洞明细、证据报文、修复优先级、事实与工具统计。",
		Formats:            []string{"html", "pdf", "markdown", "docx", "xlsx"},
		ShowRatingStandard: true,
		ShowAssetOverview:  true,
		ShowOverview:       true,
		ShowEvidence:       true,
		ShowRemediation:    true,
		ShowFacts:          true,
		ShowToolStats:      true,
		ShowAttackChains:   true,
		ShowAppendix:       true,
		ShowLimitations:    true,
		CoverSubject:       "渗透测试报告",
	},
	"src": {
		ID:                 "src",
		Type:               "vuln",
		Name:               "SRC 报送版",
		Description:        "面向 SRC 平台报送：保留漏洞总览、复现与证据、修复建议，去掉黑板事实、工具统计、攻击链与全量证据附录。",
		Formats:            []string{"html", "pdf", "markdown", "docx", "xlsx"},
		ShowRatingStandard: true,
		ShowAssetOverview:  true,
		ShowOverview:       true,
		ShowEvidence:       true,
		ShowRemediation:    true,
		ShowFacts:          false,
		ShowToolStats:      false,
		ShowAttackChains:   false,
		ShowAppendix:       false,
		ShowLimitations:    true,
		CoverSubject:       "安全测试报告",
	},
	"brief": {
		ID:                 "brief",
		Type:               "vuln",
		Name:               "内部简报版",
		Description:        "只保留高危及以上漏洞：一页概览 + 明细要点 + 修复优先级，不输出报文证据、事实与工具统计。",
		Formats:            []string{"html", "pdf", "markdown", "docx", "xlsx"},
		MinSeverity:        "high",
		ShowRatingStandard: false,
		ShowAssetOverview:  true,
		ShowOverview:       true,
		ShowEvidence:       false,
		ShowRemediation:    true,
		ShowFacts:          false,
		ShowToolStats:      false,
		ShowAttackChains:   false,
		ShowAppendix:       false,
		ShowLimitations:    true,
		CoverSubject:       "高危漏洞摘要",
	},
}

// 资产测绘模板：三档都输出域名与站点清单，差别在行数上限与是否带指纹/证据细节。
var assetProfiles = map[string]Profile{
	"asset-full": {
		ID:                 "asset-full",
		Type:               "asset",
		Name:               "资产测绘完整版",
		Description:        "信息收集交付格式：域名清单、站点清单、端口服务与指纹分布、首见时间与来源，全部站点逐条列出。",
		Formats:            []string{"html", "pdf", "markdown", "docx", "xlsx"},
		MaxRows:            500,
		ShowRatingStandard: true,
		ShowAssetOverview:  true,
		ShowOverview:       true,
		ShowEvidence:       true,
		ShowRemediation:    false,
		ShowFacts:          false,
		ShowToolStats:      false,
		ShowAttackChains:   false,
		ShowAppendix:       false,
		ShowLimitations:    true,
		CoverSubject:       "信息收集报告",
	},
	"asset-src": {
		ID:                 "asset-src",
		Type:               "asset",
		Name:               "SRC 资产报送版",
		Description:        "面向 SRC 报送：域名与站点清单收敛到 200 行，保留端口服务与指纹分布，省略评级标准说明。",
		Formats:            []string{"html", "pdf", "markdown", "docx", "xlsx"},
		MaxRows:            200,
		ShowRatingStandard: false,
		ShowAssetOverview:  true,
		ShowOverview:       true,
		ShowEvidence:       true,
		ShowRemediation:    false,
		ShowFacts:          false,
		ShowToolStats:      false,
		ShowAttackChains:   false,
		ShowAppendix:       false,
		ShowLimitations:    true,
		CoverSubject:       "资产测绘报告",
	},
	"asset-brief": {
		ID:                 "asset-brief",
		Type:               "asset",
		Name:               "内部资产简报",
		Description:        "内部快速摸底：只出域名清单与高危站点，端口服务与指纹分布合并进统计，最多 100 行。",
		Formats:            []string{"html", "pdf", "markdown", "docx", "xlsx"},
		MaxRows:            100,
		ShowRatingStandard: false,
		ShowAssetOverview:  true,
		ShowOverview:       false,
		ShowEvidence:       false,
		ShowRemediation:    false,
		ShowFacts:          false,
		ShowToolStats:      false,
		ShowAttackChains:   false,
		ShowAppendix:       false,
		ShowLimitations:    true,
		CoverSubject:       "资产简报",
	},
}

var profileOrder = []string{"standard", "src", "brief", "asset-full", "asset-src", "asset-brief"}

// DefaultProfile 返回默认模板（客户交付版）。
func DefaultProfile() Profile { return vulnProfiles["standard"] }

// DefaultAssetProfile 返回默认的信息收集模板（资产测绘完整版）。
func DefaultAssetProfile() Profile { return assetProfiles["asset-full"] }

// LookupProfile 按 ID 取模板；空 ID 视为默认模板。第二个返回值表示是否命中。
func LookupProfile(id string) (Profile, bool) {
	id = strings.ToLower(strings.TrimSpace(id))
	if id == "" {
		return DefaultProfile(), true
	}
	if p, ok := vulnProfiles[id]; ok {
		return p, true
	}
	if p, ok := assetProfiles[id]; ok {
		return p, true
	}
	return Profile{}, false
}

// ListProfiles 返回全部内置模板，顺序稳定，供前端下拉使用。
func ListProfiles() []Profile {
	out := make([]Profile, 0, len(profileOrder))
	for _, id := range profileOrder {
		if p, ok := vulnProfiles[id]; ok {
			out = append(out, p)
			continue
		}
		if p, ok := assetProfiles[id]; ok {
			out = append(out, p)
		}
	}
	return out
}

// ProfilesByType 返回某一类报告可用的模板。
func ProfilesByType(t string) []Profile {
	out := make([]Profile, 0, 3)
	for _, p := range ListProfiles() {
		if p.Type == t {
			out = append(out, p)
		}
	}
	return out
}

// MinSeverityRank 返回模板要求的最低严重度档位；0 表示不限。
func (p Profile) MinSeverityRank() int {
	if strings.TrimSpace(p.MinSeverity) == "" {
		return 0
	}
	return SeverityRank(p.MinSeverity)
}

// FilterSectionsBySeverity 按模板最低等级裁剪漏洞明细。
func FilterSectionsBySeverity(vs []VulnSection, min string) []VulnSection {
	rank := SeverityRank(min)
	if rank <= 1 {
		return vs
	}
	out := make([]VulnSection, 0, len(vs))
	for _, v := range vs {
		if SeverityRank(v.Severity) >= rank {
			out = append(out, v)
		}
	}
	return out
}

// normalize 为直接调用渲染层、未经过 Service 的调用补默认模板。
func (r *Report) normalize() {
	if strings.TrimSpace(r.Profile.ID) == "" {
		r.Profile = DefaultProfile()
	}
	r.SectionNo = r.Profile.SectionNumbers()
}
