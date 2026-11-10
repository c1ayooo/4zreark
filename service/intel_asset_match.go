package service

// 情报×资产匹配引擎：新漏洞情报到达后，自动找出现网资产里「可能受影响」的站点。
//
// 匹配依据（保守策略，宁缺毋滥）：
//   - CVE 维度的情报（vuln_intel.cve 非空）；
//   - 产品关系来自本地 PoC 库：nuclei 模板的 template_id/tags 里带 CVE 编号，
//     与指纹规则名做 token 归一求交（复用 componentprofile.MineCVEEdges）；
//   - 资产侧取 fingerprint_hits 命中该指纹规则的站点。
//
// 命中三件事：站点资产事件（asset_events, event_type=intel_match，进变更时间线）、
// 汇总通知（notify）、KV 台账（已处理的情报 key 不重复打扰）。
// 不自动创建漏洞记录——「指纹相似」不是「漏洞存在」，人工确认走漏洞工作台。

import (
	"context"
	"log"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/internal/componentprofile"
	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service/notify"
)

const (
	intelMatchDoneKey     = "intel.asset_match.done"
	intelMatchDoneCap     = 2000
	intelMatchDefaultDays = 7
)

// MatchedSite 是一条「情报命中资产」。
type MatchedSite struct {
	SiteID   int64  `json:"site_id"`
	Host     string `json:"host"`
	Project  int64  `json:"project"`
	Product  string `json:"product"`  // 指纹规则展示名
	Evidence string `json:"evidence"` // 匹配依据摘要
}

// IntelAssetMatch 是一条情报的匹配结果。
type IntelAssetMatch struct {
	IntelKey  string        `json:"intel_key"`
	Title     string        `json:"title"`
	CVE       string        `json:"cve"`
	Severity  string        `json:"severity"`
	SourceURL string        `json:"source_url,omitempty"`
	Sites     []MatchedSite `json:"sites"`
}

// IntelAssetMatchService 情报资产匹配器。
type IntelAssetMatchService struct {
	mu sync.Mutex
}

func NewIntelAssetMatchService() *IntelAssetMatchService { return &IntelAssetMatchService{} }

// MatchRecent 匹配最近 days 天内入库、且尚未处理过的 CVE 情报。
// force=true 时忽略台账重新匹配（仍然回写台账）。返回本轮匹配到的条数。
func (s *IntelAssetMatchService) MatchRecent(ctx context.Context, days int, force bool) (int, []IntelAssetMatch, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	r := repo.Default()
	if r == nil {
		return 0, nil, errRepoUnavailable
	}
	if days <= 0 {
		days = intelMatchDefaultDays
	}

	done := s.loadDone(ctx, r)

	// 情报候选：按时间倒序扫最近若干页，取带 CVE 且未处理过的。
	candidates, err := s.recentIntelWithCVE(ctx, r, days, done)
	if err != nil {
		return 0, nil, err
	}
	if len(candidates) == 0 {
		return 0, nil, nil
	}

	// CVE → 指纹产品（展示名）索引：从 PoC 库挖边。
	index, err := s.cveProductIndex(ctx, r)
	if err != nil {
		return 0, nil, err
	}

	matches := make([]IntelAssetMatch, 0, 4)
	for _, row := range candidates {
		products := index[row.CVE]
		if len(products) == 0 {
			continue
		}
		sites, err := s.sitesForProducts(ctx, r, products)
		if err != nil {
			log.Printf("[intel-match] 查询指纹命中站点失败: %v", err)
			continue
		}
		if len(sites) == 0 {
			continue
		}
		m := IntelAssetMatch{
			IntelKey:  row.UniqueKey,
			Title:     row.Title,
			CVE:       row.CVE,
			Severity:  row.Severity,
			SourceURL: row.SourceURL,
			Sites:     sites,
		}
		if err := s.recordMatches(ctx, r, m); err != nil {
			log.Printf("[intel-match] 写入资产事件失败 (intel=%s): %v", row.UniqueKey, err)
			continue
		}
		matches = append(matches, m)
	}

	// 回写台账（cap 防无限膨胀）。
	if len(matches) > 0 {
		for _, m := range matches {
			done[m.IntelKey] = struct{}{}
		}
		s.saveDone(ctx, r, done)
	}
	return len(matches), matches, nil
}

// recentIntelWithCVE 拉最近 days 天的情报，过滤出带 CVE 且未处理过的。
func (s *IntelAssetMatchService) recentIntelWithCVE(ctx context.Context, r *repo.Repo, days int, done map[string]struct{}) ([]*repo.IntelRow, error) {
	since := time.Now().AddDate(0, 0, -days)
	var out []*repo.IntelRow
	for page := 1; page <= 5; page++ {
		rows, _, err := r.Intels().List(ctx, repo.IntelFilter{Page: page, PageSize: 200})
		if err != nil {
			return nil, err
		}
		if len(rows) == 0 {
			break
		}
		stop := false
		for _, row := range rows {
			if row == nil || row.CreatedAt.Before(since) {
				stop = true // 列表按时间倒序，越过分界线就不用再翻页
				break
			}
			if row.CVE == "" {
				continue
			}
			if _, ok := done[row.UniqueKey]; ok {
				continue
			}
			out = append(out, row)
		}
		if stop || len(rows) < 200 {
			break
		}
	}
	return out, nil
}

// cveProductIndex 从 PoC 库挖「CVE → 指纹规则展示名」索引。
// 与 component_service 同一套口径：nuclei 模板 tech tokens × 指纹规则名。
func (s *IntelAssetMatchService) cveProductIndex(ctx context.Context, r *repo.Repo) (map[string][]string, error) {
	rules, err := r.Fingerprints().ListRules(ctx, false)
	if err != nil {
		return nil, err
	}
	profiles := make([]componentprofile.Profile, 0, len(rules))
	seen := map[string]string{} // normalized key → 展示名
	for _, rule := range rules {
		name := strings.TrimSpace(rule.Name)
		if name == "" {
			continue
		}
		key := componentprofile.Normalize(name)
		if key == "" {
			continue
		}
		if _, ok := seen[key]; !ok {
			seen[key] = name
		}
		profiles = append(profiles, componentprofile.Profile{
			Product: key, DisplayName: name, Category: rule.Category,
			Tokens: componentprofile.MatchTokens(key),
		})
	}

	var templates []componentprofile.TemplateIndexEntry
	pocs, _, err := r.Pocs().List(ctx, repo.POCFilter{Type: "nuclei", Page: 1, PageSize: 500})
	if err != nil {
		return nil, err
	}
	for _, p := range pocs {
		if p == nil || len(p.CVEID) == 0 {
			continue
		}
		tech := strings.TrimSpace(p.TemplateID)
		for _, tag := range p.Tags {
			tech += " " + tag
		}
		templates = append(templates, componentprofile.TemplateIndexEntry{
			ID: p.TemplateID, Tech: tech, CVEs: p.CVEID,
		})
	}

	index := map[string][]string{}
	for _, e := range componentprofile.MineCVEEdges(templates, profiles) {
		display, ok := seen[e.Product]
		if !ok {
			display = e.Product
		}
		if !containsString(index[e.Target], display) {
			index[e.Target] = append(index[e.Target], display)
		}
	}
	return index, nil
}

// sitesForProducts 查命中这些指纹产品的站点。
func (s *IntelAssetMatchService) sitesForProducts(ctx context.Context, r *repo.Repo, products []string) ([]MatchedSite, error) {
	rules, err := r.Fingerprints().ListRules(ctx, false)
	if err != nil {
		return nil, err
	}
	want := map[string]string{} // normalized key → 展示名
	for _, p := range products {
		want[componentprofile.Normalize(p)] = p
	}
	var ruleIDs []string
	ruleName := map[string]string{}
	for _, rule := range rules {
		key := componentprofile.Normalize(strings.TrimSpace(rule.Name))
		if _, ok := want[key]; ok {
			ruleIDs = append(ruleIDs, rule.ID)
			ruleName[rule.ID] = rule.Name
		}
	}
	if len(ruleIDs) == 0 {
		return nil, nil
	}
	sites, err := repo.NewAssetRepo().ListSitesForRules(ctx, ruleIDs, 200)
	if err != nil {
		return nil, err
	}
	out := make([]MatchedSite, 0, len(sites))
	for _, st := range sites {
		product := want[componentprofile.Normalize(strings.TrimSpace(ruleName[st.RuleID]))]
		if product == "" {
			product = ruleName[st.RuleID]
		}
		out = append(out, MatchedSite{
			SiteID: st.SiteID, Host: st.Host, Project: st.ProjectID,
			Product:  product,
			Evidence: "指纹命中: " + ruleName[st.RuleID],
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Project != out[j].Project {
			return out[i].Project < out[j].Project
		}
		return out[i].Host < out[j].Host
	})
	return out, nil
}

// recordMatches 给每个命中站点写一条资产事件（变更时间线可见）。
func (s *IntelAssetMatchService) recordMatches(ctx context.Context, r *repo.Repo, m IntelAssetMatch) error {
	assets := repo.NewAssetRepo()
	title := "情报命中: " + m.CVE
	for _, st := range m.Sites {
		err := assets.InsertEvent(ctx, st.Project, st.SiteID, nil, "intel_match", title, nil, map[string]any{
			"cve":        m.CVE,
			"intel_key":  m.IntelKey,
			"intel":      m.Title,
			"severity":   m.Severity,
			"source_url": m.SourceURL,
			"product":    st.Product,
			"evidence":   st.Evidence,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// --- 已处理台账（KV） ---

func (s *IntelAssetMatchService) loadDone(ctx context.Context, r *repo.Repo) map[string]struct{} {
	out := map[string]struct{}{}
	var keys []string
	if found, err := r.Settings().Get(ctx, intelMatchDoneKey, &keys); err == nil && found {
		for _, k := range keys {
			out[k] = struct{}{}
		}
	}
	return out
}

func (s *IntelAssetMatchService) saveDone(ctx context.Context, r *repo.Repo, done map[string]struct{}) {
	keys := make([]string, 0, len(done))
	for k := range done {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > intelMatchDoneCap {
		keys = keys[len(keys)-intelMatchDoneCap:]
	}
	_ = r.Settings().Set(ctx, intelMatchDoneKey, keys)
}

// NotifyMatches 汇总通知本轮匹配结果。
func NotifyMatches(matches []IntelAssetMatch) {
	if len(matches) == 0 {
		return
	}
	m := notify.GetGlobalManager()
	if m == nil {
		return
	}
	var body strings.Builder
	body.WriteString("本轮情报资产匹配命中 ")
	body.WriteString(strconv.Itoa(len(matches)))
	body.WriteString(" 条情报、")
	siteTotal := 0
	for _, mt := range matches {
		siteTotal += len(mt.Sites)
	}
	body.WriteString(strconv.Itoa(siteTotal))
	body.WriteString(" 个站点：\n")
	for i, mt := range matches {
		if i >= 10 {
			body.WriteString("...\n")
			break
		}
		body.WriteString("· " + mt.CVE + "（" + mt.Title + "）→ " + strconv.Itoa(len(mt.Sites)) + " 个站点\n")
	}
	m.SendAsync(&notify.NotifyMessage{
		Level:   notify.NotifyLevelWarning,
		Title:   "情报资产匹配提醒",
		Content: body.String(),
		Source:  "vuln-intel",
	})
}

func containsString(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
