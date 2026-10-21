// Package componentprofile 组件档案层：把指纹识别出的产品（13k+）
// 与可用的测试方法论（技能 / 知识条目 / 检测路径 / CVE）连起来。
//
// 设计（见 docs/组件方法论自动采集与指纹驱动检索方案.md）：
//   - L1 精确层：本包 component_profiles + component_edges 查表，零 embedding 成本；
//   - 档案由挖掘任务自动生成（指纹规则→产品词典、技能目录→技能边、知识条目→知识边），
//     权威边由 configs/component-profile-seeds 种子文件声明，不写死在 Go 代码里；
//   - L2 向量兜底与 L3 联网兜底由消费方（knowledge/multiagent）在档案未命中时走原路径。
package componentprofile

import "time"

// Edge 的 kind 取值。
const (
	KindSkill     = "skill"     // target = 技能名（skills/<dir>）
	KindKnowledge = "knowledge" // target = 知识条目 id（knowledge_base_items.id）
	KindTemplate  = "template"  // target = nuclei 模板 id（P2 采集）
	KindCVE       = "cve"       // target = CVE 编号（P2 采集）
	KindPath      = "path"      // target = 探测路径（P2 采集）
)

// Edge 的 review 状态：
//   - reviewed：人工/种子确认，可注入；
//   - auto：规则高置信挖掘（技能名派生），可注入；
//   - unreviewed：规则低置信挖掘（描述/正文派生），只落库不注入，待审核；
//   - rejected：人工否决，永不注入。
const (
	ReviewReviewed   = "reviewed"
	ReviewAuto       = "auto"
	ReviewUnreviewed = "unreviewed"
	ReviewRejected   = "rejected"
)

// Injectable 判断边是否可进入注入路径（reviewed/auto）。
func (e Edge) Injectable() bool {
	return e.Review == ReviewReviewed || e.Review == ReviewAuto
}

// Edge 一条「组件 → 方法论」边。
type Edge struct {
	Product  string  `json:"product"`
	Kind     string  `json:"kind"`
	Target   string  `json:"target"`
	Score    float64 `json:"score"`
	Source   string  `json:"source"`   // 挖掘来源：seed/skill-name/skill-desc/knowledge-title/…
	Evidence string  `json:"evidence"` // 命中依据（可审计）
	Review   string  `json:"review"`
}

// Profile 一个组件的档案（产品词典条目）。
type Profile struct {
	Product        string   `json:"product"` // 规范化键（小写、连字符分隔、去版本）
	DisplayName    string   `json:"display_name"`
	Vendor         string   `json:"vendor"`
	Category       string   `json:"category"` // 指纹规则分类（Java-Framework/CMS/Web servers…）
	Tokens         []string `json:"tokens"`   // 规范化键的 token 集合（GIN 检索用）
	Aliases        []string `json:"aliases"`  // 其他来源的原始名（小写）
	DetectionPaths []string `json:"detection_paths"`
	CVEKeys        []string `json:"cve_keys"`
	Confidence     float64  `json:"confidence"`
	Sources        []string `json:"sources"`
	UpdatedAt      time.Time
}

// Match 一次组件查询结果：命中的档案 + 它的全部边。
type Match struct {
	Profile   Profile
	Edges     []Edge
	MatchedBy string // exact / alias / token
}

// Skills 返回可注入的技能名（去重、按分数降序）。
func (m *Match) Skills() []string {
	if m == nil {
		return nil
	}
	seen := make(map[string]bool)
	var out []string
	for _, e := range m.Edges {
		if e.Kind != KindSkill || !e.Injectable() || seen[e.Target] {
			continue
		}
		seen[e.Target] = true
		out = append(out, e.Target)
	}
	return out
}

// KnowledgeTargets 返回可注入的知识条目 id。
func (m *Match) KnowledgeTargets() []string {
	if m == nil {
		return nil
	}
	seen := make(map[string]bool)
	var out []string
	for _, e := range m.Edges {
		if e.Kind != KindKnowledge || !e.Injectable() || seen[e.Target] {
			continue
		}
		seen[e.Target] = true
		out = append(out, e.Target)
	}
	return out
}

// TemplateTargets 返回可注入的 nuclei 模板 id（按分数降序，最多 max 条）。
func (m *Match) TemplateTargets(max int) []string {
	if m == nil {
		return nil
	}
	seen := make(map[string]bool)
	var out []string
	for _, e := range m.Edges {
		if e.Kind != KindTemplate || !e.Injectable() || seen[e.Target] {
			continue
		}
		seen[e.Target] = true
		out = append(out, e.Target)
		if max > 0 && len(out) >= max {
			break
		}
	}
	return out
}

// Stats 挖掘统计。
type Stats struct {
	Profiles         int `json:"profiles"`
	SkillEdges       int `json:"skill_edges"`
	KnowledgeEdge    int `json:"knowledge_edges"`
	TemplateEdges    int `json:"template_edges"`
	CVEEdges         int `json:"cve_edges"`
	PathEdges        int `json:"path_edges"`
	ProductsWithEdge int `json:"products_with_edge"`
}
