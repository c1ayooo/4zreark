package report

import (
	"fmt"
	"strings"

	"github.com/c1ayooo/4zreark/internal/httpprobe"
)

// ── 响应呈现策略 ──
// 请求是证明漏洞的关键：永远全量。
// 响应按需呈现：状态行+响应头+体前段足以看到"结果"；完整内容走 HTML 展开或交付包证据附件。

const (
	RespModeSmart = "smart" // 默认：响应体超过阈值时节选
	RespModeFull  = "full"  // 全量呈现（合规交付需要完整响应时）
	// RespModeMinimal 轻量报告：大纲 + 漏洞说明 + 证明漏洞存在的数据包。
	// 附录只出索引（不 dump 全文），漏洞明细只保留对比组与截图，
	// 独立证据卡（探测过程噪音）不渲染。
	RespModeMinimal = "minimal"
)

const (
	respBodyFullLimit = 4 * 1024 // 响应 ≤4KB 全量呈现
	respBodyShowLen   = 3 * 1024 // 超过阈值时节选前 3KB
)

// ShapePacket 按 respMode 切分并整形报文。
// req 永远全量；响应在 smart 模式且超长时节选前 3KB 并附省略标注，
// full（或响应本身不长）时全量。full 返回完整响应（HTML 展开区/交付包附件用），
// omitted 为 smart 模式省略的字节数（0 表示未省略）。
func ShapePacket(content, respMode string) (req, shown, full string, omitted int) {
	req, resp := SplitTranscript(content)
	if respMode == RespModeFull || len(resp) <= respBodyFullLimit {
		return req, resp, resp, 0
	}
	head := safeCut(resp, respBodyShowLen)
	omitted = len(resp) - len(head)
	shown = head + fmt.Sprintf("\n\n…（响应共 %s，此处节选前 %s；完整响应见可展开区域或交付包证据附件，可按证据 ID 复核）",
		humanSize(len(resp)), humanSize(len(head)))
	return req, shown, resp, omitted
}

// safeCut 在不切断 UTF-8 多字节字符的前提下截取前 n 字节
func safeCut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := s[:n]
	for i := 0; i < 3 && len(cut) > 0; i++ {
		if r := cut[len(cut)-1]; r < 0x80 || r >= 0xC0 {
			break
		}
		cut = cut[:len(cut)-1] // 回退 UTF-8 续字节
	}
	return cut
}

func humanSize(n int) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := int64(n) / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	units := []string{"KB", "MB", "GB", "TB", "PB"}
	return fmt.Sprintf("%.1f %s", float64(n)/float64(div), units[exp])
}

// ── 修复优先级归组（甲方报告"修复优先级建议"章节） ──

// BuildRemediation 按严重度把已编号漏洞归入三档修复优先级：
// 立即处置（critical）/ 尽快修复（high）/ 计划内修复（medium 及以下）。
func BuildRemediation(vs []VulnSection) []RemediationGroup {
	tiers := []struct {
		match func(sev string) bool
		group RemediationGroup
	}{
		{func(s string) bool { return SeverityRank(s) == SeverityRank("critical") },
			RemediationGroup{Priority: "立即处置", Hint: "可直接导致系统失陷或核心数据泄露，建议 24~48 小时内完成修复与复测"}},
		{func(s string) bool { return SeverityRank(s) == SeverityRank("high") },
			RemediationGroup{Priority: "尽快修复", Hint: "可被组合利用造成显著影响，建议 7 个工作日内修复"}},
		{func(s string) bool { return SeverityRank(s) <= SeverityRank("medium") },
			RemediationGroup{Priority: "计划内修复", Hint: "纳入常规版本计划，建议 30 天内完成"}},
	}
	groups := make([]RemediationGroup, 0, len(tiers))
	for _, tier := range tiers {
		g := tier.group
		for _, v := range vs {
			if tier.match(v.Severity) {
				g.Items = append(g.Items, RemediationItem{Number: v.Number, Title: v.Title, Severity: v.Severity})
			}
		}
		if len(g.Items) > 0 {
			groups = append(groups, g)
		}
	}
	return groups
}

// BuildEvidenceGroups 把平铺证据组织成报告视图：
// 有 GroupKey 的按组聚合（组内按 SortOrder/时间排），多条渲染对比卡；
// 无组的各自成独立组（单条渲染普通卡）。
func BuildEvidenceGroups(items []EvidenceItem) []EvidenceGroup {
	groups := []EvidenceGroup{}
	byKey := map[string]*EvidenceGroup{}
	var order []string
	for _, it := range items {
		key := it.GroupKey
		if key == "" {
			key = "__solo__" + it.ID
		}
		g, ok := byKey[key]
		if !ok {
			g = &EvidenceGroup{GroupKey: key, Title: groupTitle(key, it)}
			byKey[key] = g
			order = append(order, key)
		}
		g.Items = append(g.Items, it)
	}
	for _, key := range order {
		g := byKey[key]
		// 组内排序：sort_order → 时间
		for i := 1; i < len(g.Items); i++ {
			for j := i; j > 0; j-- {
				a, b := g.Items[j-1], g.Items[j]
				if a.SortOrderValue() > b.SortOrderValue() || (a.SortOrderValue() == b.SortOrderValue() && a.CreatedAt > b.CreatedAt) {
					g.Items[j-1], g.Items[j] = b, a
				} else {
					break
				}
			}
		}
		groups = append(groups, *g)
	}
	return groups
}

// SortOrderValue 组内排序值
func (e EvidenceItem) SortOrderValue() int { return e.SortOrder }

// Wide 组内存在超长报文时不宜双栏对比：半栏宽度读长报文可用性差，
// 且分页时另一栏会留大片空白面板，模板据此改纵向全宽堆叠渲染。
func (g EvidenceGroup) Wide() bool {
	const wideThreshold = 8 * 1024
	for _, it := range g.Items {
		if len(it.ReqText)+len(it.RespText)+len(it.Content) > wideThreshold {
			return true
		}
	}
	return false
}

func groupTitle(key string, first EvidenceItem) string {
	if key == "" || strings.HasPrefix(key, "__solo__") {
		return ""
	}
	if first.Label != "" {
		return first.Title
	}
	return key
}

// SplitTranscript 把 http_probe 归档的完整数据包切成请求/响应两段，全量返回不截断。
// 结构：=== REQUEST ===\n<req>\n=== RESPONSE ===\n<resp>
// 非标准结构（save_evidence 手工归档的报文）：整体当响应。
func SplitTranscript(content string) (req, resp string) {
	iReq := strings.Index(content, httpprobe.RequestMarker)
	iResp := strings.Index(content, httpprobe.ResponseMarker)
	if iResp < 0 {
		return "", strings.TrimSpace(content)
	}
	resp = strings.TrimSpace(content[iResp+len(httpprobe.ResponseMarker):])
	if iReq >= 0 && iReq < iResp {
		req = strings.TrimSpace(content[iReq+len(httpprobe.RequestMarker) : iResp])
	}
	return req, resp
}
