package githubleak

import (
	"fmt"
	"sort"
	"strings"

	"github.com/c1ayooo/4zreark/internal/lz"

	)

// notifyNewFindings 本轮新命中聚合为一条 IM 通知（notifier 统一漏斗 → 机器人广播）。
// 条目按「仓库×密钥值」聚合去重（重复出现是研判信号而非噪音），通知内直显具体
// 键值对（与个人订阅推送同口径，无需回 GitHub 打开链接），无明文时回退首尾脱敏
// 锚点；最多展示 10 条（likely 级优先），全量仍以监控页为准；通知失败只记日志。
func (s *Service) notifyNewFindings(run RunRecord, inserted []Candidate) {
	s.mu.Lock()
	publish := s.notify
	enabled := s.settings.ResolveNotifyEnabled()
	s.mu.Unlock()
	if publish == nil || !enabled || run.Status == "rate_limited" || len(inserted) == 0 {
		return
	}
	likely := 0
	values := make(map[string]struct{}, len(inserted))
	for _, c := range inserted {
		values[c.Fingerprint] = struct{}{}
		if c.Confidence == "likely" {
			likely++
		}
	}
	entries := buildHitEntries(inserted)
	// likely（强特征）排前
	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].confidence == "likely" && entries[j].confidence != "likely"
	})
	truncated := len(entries) > 10
	if truncated {
		entries = entries[:10]
	}
	items := make([]AlertItem, 0, len(entries))
	for _, e := range entries {
		items = append(items, e.alertItem())
	}
	summary := fmt.Sprintf("新增 %d 条命中（高危 %d / 可疑 %d）· 独立值 %d 个 · %s",
		len(inserted), likely, len(inserted)-likely, len(values), ruleSummary(inserted))
	if truncated {
		summary += "；已按仓库×密钥值去重，仅展示前 10 条，其余见监控页"
	}
	publish(Event{
		Kind:      KindGithubLeakFound,
		Level:     levelFor(likely),
		Title:     "GitHub 泄露监控发现新命中",
		Summary:   summary,
		Items:     items,
		Footer:    "处置入口：资产管理 → 信息收集 → GitHub 泄露监控",
		DedupKey:  "githubleak:" + run.ID,
		Broadcast: true,
	})
	s.logger.Info("GitHub leak monitor 新命中通知已发布", lz.Int("count", len(inserted)), lz.String("run_id", run.ID))
}

// hitEntry 通知条目聚合单元：同仓库同值多条命中并为一条；跨仓库同值以
// repoShare 互指——同值多仓库是模板/合集的典型特征，直接展示给研判者。
type hitEntry struct {
	cand       Candidate
	paths      int
	repoShare  int
	confidence string
}

// buildHitEntries 按「仓库×密钥值」（指纹为全局 HMAC，同值必同指纹）聚合本轮
// 新命中，保持首现顺序；同组 likely 优先升级，避免降级样本淹没强特征。
func buildHitEntries(inserted []Candidate) []hitEntry {
	repoSets := make(map[string]map[string]struct{}, len(inserted))
	for _, c := range inserted {
		set, ok := repoSets[c.Fingerprint]
		if !ok {
			set = make(map[string]struct{}, 1)
			repoSets[c.Fingerprint] = set
		}
		set[c.Repository] = struct{}{}
	}
	index := make(map[string]int, len(inserted))
	entries := make([]hitEntry, 0, len(inserted))
	for _, c := range inserted {
		k := c.Repository + "\x00" + c.Fingerprint
		if i, ok := index[k]; ok {
			e := &entries[i]
			e.paths++
			if c.Confidence == "likely" {
				e.confidence = "likely"
			}
			continue
		}
		index[k] = len(entries)
		entries = append(entries, hitEntry{
			cand:       c,
			paths:      1,
			repoShare:  len(repoSets[c.Fingerprint]),
			confidence: c.Confidence,
		})
	}
	return entries
}

// alertItem 单条通知渲染：仓库·类型为主行；Sub 首行为具体键值对（明文直显），
// 其后收敛重复处数与同值跨仓库数；无明文时主行缀密钥值首尾锚点（同锚点即同值，
// 不同锚点即同仓库的不同 key）。
func (e hitEntry) alertItem() AlertItem {
	tag := "可疑"
	if e.confidence == "likely" {
		tag = "高危"
	}
	text := e.cand.Repository + " · " + e.cand.SecretType
	sub := keyValueLine(e.cand)
	if sub == "" {
		if anchor := valueAnchor(e.cand.MaskedExcerpt); anchor != "" {
			text += " · " + anchor
		}
	}
	sub += fmt.Sprintf("%s:%d", e.cand.Path, e.cand.Line)
	if e.paths > 1 {
		sub += fmt.Sprintf(" 等%d处", e.paths)
	}
	if e.repoShare > 1 {
		sub += fmt.Sprintf(" · 同值%d仓库", e.repoShare)
	}
	return AlertItem{Tag: tag, Text: text, Link: e.cand.HTMLURL, Sub: sub}
}

// keyValueLine 通知内直显的具体键值对：前缀取源码赋值字段名（SecretKey，强特征
// 命中无字段名时回退 "key"）；多行凭据（私钥块）取首行。超长值不发截断串——
// 检测层对赋值值有 512 字节硬上限（扫描器与 credibleAssignedValue 双闸），合法
// 命中不可能超过；超出即提取缺陷（贪婪正则/边界错位），返回空串交回锚点渲染，
// 由研判者从监控页/链接核对原文。与个人订阅推送（handler/robot info_collect_alert）
// 同为明文直显口径。
func keyValueLine(c Candidate) string {
	value := strings.TrimSpace(c.SecretValue)
	if value == "" {
		return ""
	}
	if i := strings.IndexByte(value, '\n'); i >= 0 {
		value = strings.TrimRight(value[:i], "\r")
	}
	// 与检测层 credibleAssignedValue 的值长度上限一致。
	const maxValueBytes = 512
	if len(value) > maxValueBytes {
		return ""
	}
	// 审计 H4：通知渠道（邮件/Webhook）不再携带明文，只发首末 4 字符锚点，
	// 与 masked_excerpt 的 <redacted:类型|v:首4…末4> 同一比对语义。
	if label := strings.TrimSpace(c.SecretKey); label != "" {
		return label + ": " + maskSecretAnchor(value)
	}
	return "key: " + maskSecretAnchor(value)
}

// maskSecretAnchor 把凭据值缩成首末 4 字符锚点；太短没有锚点价值，全掩码。
func maskSecretAnchor(value string) string {
	const keep = 4
	r := []rune(value)
	if len(r) <= keep*2 {
		return strings.Repeat("*", len(r))
	}
	return string(r[:keep]) + "…" + string(r[len(r)-keep:])
}

// valueAnchor 从脱敏摘录 <redacted:类型|v:首4…末4> 中提取密钥值首尾锚点，
// 供通知侧比对是否同一把 key；防御性标记（无预览段）返回空串。
func valueAnchor(maskedExcerpt string) string {
	i := strings.Index(maskedExcerpt, "|v:")
	if i < 0 {
		return ""
	}
	anchor := maskedExcerpt[i+3:]
	if j := strings.Index(anchor, ">"); j >= 0 {
		anchor = anchor[:j]
	}
	return anchor
}

// ruleSummary 去重规则名：单条直书，多条列前 2 条 + 等N，避免多规则轮次误报单一规则。
func ruleSummary(items []Candidate) string {
	seen := make(map[string]struct{})
	names := make([]string, 0, 2)
	for _, c := range items {
		if c.RuleName == "" {
			continue
		}
		if _, ok := seen[c.RuleName]; ok {
			continue
		}
		seen[c.RuleName] = struct{}{}
		names = append(names, c.RuleName)
	}
	switch len(names) {
	case 0:
		return "-"
	case 1, 2:
		return "规则 " + strings.Join(names, "、")
	default:
		return fmt.Sprintf("规则 %s、%s 等 %d 条", names[0], names[1], len(names))
	}
}

func levelFor(likely int) string {
	if likely > 0 {
		return "critical"
	}
	return "medium"
}
