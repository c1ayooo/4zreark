package repo

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/internal/fpscore"
	"github.com/jackc/pgx/v5"
)

// 指纹评分域：按项目列出资产，用指纹命中（规则 + 技术栈）算出 0-100 分，
// 支持按分类 / 单个指纹 / 分档 / 分数区间筛选与排序。
//
// 与 risk_score 的区别：risk_score 综合漏洞实证、开放端口、HTTP 卫生；
// 这里只看「这个资产是什么」，用来回答「优先测哪些资产」。

// fpScoreCandidateLimit 是单次计算的上限。评分要全量算完才能排序，
// 超大项目只取最近发现的一批，并在响应里标 truncated。
const fpScoreCandidateLimit = 20000

// FpScoreQuery 是指纹评分列表的参数。空值取缺省（不分项目、按分倒序）。
type FpScoreQuery struct {
	ProjectID   int64  // 0 = 全部项目
	Category    string // 分类匹配（规则分类或技术栈反推，大小写/分隔符不敏感）
	Fingerprint string // 指纹/技术名精确匹配（规则名或技术栈串）
	Level       string // "" | high | medium | low | none
	MinScore    int    // 0 = 不限
	MaxScore    int    // 0 = 不限
	Q           string // 主机名模糊
	Sort        string // "" | score（缺省）| host | assets
	Page        int
	PageSize    int
}

// FpScore 是一行的评分结果。Matches 保留全部命中，调用方可自行截断展示。
type FpScore struct {
	ID          int64           `json:"id"`
	Host        string          `json:"host"`
	Value       string          `json:"value"`
	IP          string          `json:"ip"`
	Title       string          `json:"title"`
	HTTPStatus  int             `json:"http_status"`
	State       string          `json:"state"`
	ProjectID   int64           `json:"project_id"`
	ProjectName string          `json:"project_name"`
	Tech        []string        `json:"technology_stack"`
	Categories  []string        `json:"categories"`
	Score       int             `json:"score"`
	Level       string          `json:"level"`
	LevelLabel  string          `json:"level_label"`
	Matches     []fpscore.Match `json:"matches"`
	LastSeen    time.Time       `json:"last_seen"`
}

// FpScoreFacet 是筛选维度上的资产计数。
type FpScoreFacet struct {
	Name     string `json:"name"`
	Label    string `json:"label"`
	AssetCnt int64  `json:"asset_count"`
}

// FpScoreBand 是分档计数，前端据此画可点击的分布卡片。
type FpScoreBand struct {
	Level string `json:"level"`
	Label string `json:"label"`
	Count int64  `json:"count"`
	Min   int    `json:"min"`
	Max   int    `json:"max"`
}

// FpScoreFacets 是当前筛选条件下的分布统计（不含 Level / MinScore / MaxScore，
// 否则用户切到某一档后其它档的计数会全部归零，失去导航意义）。
type FpScoreFacets struct {
	Bands        []FpScoreBand  `json:"bands"`
	Categories   []FpScoreFacet `json:"categories"`
	Fingerprints []FpScoreFacet `json:"fingerprints"`
	Total        int64          `json:"total"`
	Scored       int64          `json:"scored"`
	AvgScore     int            `json:"avg_score"`
}

// FpScorePage 是一次查询的结果。
type FpScorePage struct {
	Items       []*FpScore    `json:"items"`
	Total       int64         `json:"total"`
	Page        int           `json:"page"`
	PageSize    int           `json:"page_size"`
	Facets      FpScoreFacets `json:"facets"`
	ProjectID   int64         `json:"project_id"`
	Category    string        `json:"category"`
	Fingerprint string        `json:"fingerprint"`
	Level       string        `json:"level"`
	Truncated   bool          `json:"truncated"`
	// ScoredCount 是实际参与评分的候选数；Truncated 为 true 时它就是计算上限。
	ScoredCount int64 `json:"scored_count"`
}

// fpScoreRow 是扫描用的中间结构：JSONB 先落成字节，再交给 fpscore 解析。
type fpScoreRow struct {
	ID          int64
	Host        string
	Value       string
	IP          string
	Title       string
	HTTPStatus  int
	State       string
	ProjectID   int64
	ProjectName string
	Tech        []byte
	RuleNames   []byte // [["name","category"], ...]
	LastSeen    time.Time
}

const fpScoreSelect = `s.id, s.host, s.value, coalesce(s.ip::text,''), coalesce(s.title,''),
	s.http_status, s.state, s.project_id, p.name, s.tech,
	coalesce((SELECT jsonb_agg(jsonb_build_array(r.name, r.category))
	            FROM fingerprint_hits h
	            JOIN fingerprint_rules r ON r.id = h.rule_id
	           WHERE h.site_id = s.id AND r.enabled), '[]'::jsonb),
	s.last_seen`

const fpScoreFrom = `FROM sites s JOIN projects p ON p.id = s.project_id`

func (a *AssetRepo) buildFpScoreWhere(q FpScoreQuery) *whereBuilder {
	w := newWhereBuilder(1)
	if q.ProjectID > 0 {
		w.parts = append(w.parts, "s.project_id = "+w.ph())
		w.args = append(w.args, q.ProjectID)
	}
	if fp := strings.TrimSpace(q.Fingerprint); fp != "" {
		// 规则名大小写不敏感等值；技术栈串按 JSONB 元素等值比较
		w.parts = append(w.parts, "(EXISTS (SELECT 1 FROM fingerprint_hits hh "+
			"JOIN fingerprint_rules rr ON rr.id = hh.rule_id "+
			"WHERE hh.site_id = s.id AND rr.enabled AND lower(rr.name) = "+w.ph()+") "+
			"OR EXISTS (SELECT 1 FROM jsonb_array_elements_text(s.tech) t "+
			"WHERE lower(t) = "+w.ph()+"))")
		lower := strings.ToLower(fp)
		w.args = append(w.args, lower, lower)
	}
	if kw := strings.TrimSpace(q.Q); kw != "" {
		w.parts = append(w.parts, "(s.host ILIKE "+w.ph()+" OR s.value ILIKE "+w.ph()+")")
		pattern := "%" + kw + "%"
		w.args = append(w.args, pattern, pattern)
	}
	return w
}

// ListFpScores 是指纹评分列表：取候选行 → 评分 → 过滤 → 排序 → 切页。
//
// 分数依赖命中的指纹集合而不是已落库的列，所以必须先算后排序；这是与
// sort=risk 一致的显式代价（候选集已被 project / 指纹筛选收窄，量可控）。
func (a *AssetRepo) ListFpScores(ctx context.Context, q FpScoreQuery) (*FpScorePage, error) {
	if a == nil || a.r == nil {
		return nil, errUninitialized()
	}
	// 兜底归一化：service 层已经按 HTTP 口径收过一遍，这里再兜一次，
	// 是为了让内部调用（MCP、测试、脚本）拿到同样的口径。
	q.Level = normalizeFpLevel(q.Level)
	q.MinScore, q.MaxScore = normalizeFpScoreRange(q.MinScore, q.MaxScore)
	if q.Page < 1 {
		q.Page = 1
	}
	if q.PageSize < 1 {
		q.PageSize = 20
	}
	if q.PageSize > 500 {
		q.PageSize = 500
	}

	w := a.buildFpScoreWhere(q)

	var candidates int64
	if err := a.r.pool.QueryRow(ctx,
		"SELECT count(*) "+fpScoreFrom+" WHERE "+w.String(), w.args...).Scan(&candidates); err != nil {
		return nil, fmt.Errorf("统计指纹评分资产失败: %w", err)
	}

	// 候选超过计算上限时，先按有指纹的站点排序再截断：保证被算的一定是
	// 最该看的那批，而不是「最近发现」这个与评分无关的顺序。
	truncated := candidates > fpScoreCandidateLimit
	order := "s.last_seen DESC, s.id DESC"
	if truncated {
		order = "s.tech <> '[]'::jsonb DESC, s.last_seen DESC, s.id DESC"
	}
	args := append(append([]any{}, w.args...), fpScoreCandidateLimit)
	stmt := fmt.Sprintf("SELECT %s %s WHERE %s ORDER BY %s LIMIT $%d",
		fpScoreSelect, fpScoreFrom, w.String(), order, len(args))
	rows, err := a.r.pool.Query(ctx, stmt, args...)
	if err != nil {
		return nil, fmt.Errorf("查询指纹评分资产失败: %w", err)
	}
	defer rows.Close()

	scored, err := scanFpScores(rows)
	if err != nil {
		return nil, err
	}

	page := &FpScorePage{
		Total:       candidates,
		Page:        q.Page,
		PageSize:    q.PageSize,
		ProjectID:   q.ProjectID,
		Category:    strings.TrimSpace(q.Category),
		Fingerprint: strings.TrimSpace(q.Fingerprint),
		Level:       q.Level,
		Truncated:   truncated,
		ScoredCount: int64(len(scored)),
		Facets:      buildFpScoreFacets(scored),
	}
	page.Items, page.Total = paginateFpScores(scored, q)
	return page, nil
}

func scanFpScores(rows pgx.Rows) ([]*FpScore, error) {
	out := make([]*FpScore, 0, 128)
	for rows.Next() {
		var r fpScoreRow
		if err := rows.Scan(&r.ID, &r.Host, &r.Value, &r.IP, &r.Title, &r.HTTPStatus, &r.State,
			&r.ProjectID, &r.ProjectName, &r.Tech, &r.RuleNames, &r.LastSeen); err != nil {
			return nil, fmt.Errorf("解析指纹评分资产失败: %w", err)
		}
		out = append(out, buildFpScore(r))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("遍历指纹评分资产失败: %w", err)
	}
	return out, nil
}

// buildFpScore 是「观测到的指纹 → 分值」的唯一转换点。
func buildFpScore(r fpScoreRow) *FpScore {
	hits := make([]fpscore.Hit, 0, 8)
	var tech []string
	if len(r.Tech) > 0 && string(r.Tech) != "null" {
		_ = json.Unmarshal(r.Tech, &tech)
	}
	for _, t := range tech {
		if t = strings.TrimSpace(t); t != "" {
			hits = append(hits, fpscore.Hit{Name: t, Source: fpscore.SourceTech})
		}
	}
	var pairs [][2]string
	if len(r.RuleNames) > 0 && string(r.RuleNames) != "null" {
		_ = json.Unmarshal(r.RuleNames, &pairs)
	}
	for _, p := range pairs {
		name := strings.TrimSpace(p[0])
		if name == "" {
			continue
		}
		hits = append(hits, fpscore.Hit{Name: name, Category: p[1], Source: fpscore.SourceRule})
	}

	res := fpscore.Compute(hits)
	if tech == nil {
		tech = []string{}
	}
	return &FpScore{
		ID:          r.ID,
		Host:        r.Host,
		Value:       r.Value,
		IP:          r.IP,
		Title:       r.Title,
		HTTPStatus:  r.HTTPStatus,
		State:       r.State,
		ProjectID:   r.ProjectID,
		ProjectName: r.ProjectName,
		Tech:        tech,
		Categories:  res.Categories,
		Score:       res.Score,
		Level:       res.Level,
		LevelLabel:  fpscore.LevelLabel(res.Level),
		Matches:     res.Matches,
		LastSeen:    r.LastSeen,
	}
}

// paginateFpScores 应用分数/档位筛选、排序并切页，返回当前页与筛选后的总数。
func paginateFpScores(scored []*FpScore, q FpScoreQuery) ([]*FpScore, int64) {
	filtered := make([]*FpScore, 0, len(scored))
	for _, s := range scored {
		if q.Category != "" && !hasCategory(s.Categories, q.Category) {
			continue
		}
		if q.Level != "" && s.Level != q.Level {
			continue
		}
		if q.MinScore > 0 && s.Score < q.MinScore {
			continue
		}
		if q.MaxScore > 0 && s.Score > q.MaxScore {
			continue
		}
		filtered = append(filtered, s)
	}

	switch strings.ToLower(strings.TrimSpace(q.Sort)) {
	case "host":
		sort.SliceStable(filtered, func(i, j int) bool { return filtered[i].Host < filtered[j].Host })
	case "assets":
		// 命中指纹数量多的排在前面，用于「暴露面最广」视角
		sort.SliceStable(filtered, func(i, j int) bool {
			return len(filtered[i].Matches) > len(filtered[j].Matches)
		})
	default:
		sortFpScores(filtered)
	}

	total := int64(len(filtered))
	offset := (q.Page - 1) * q.PageSize
	if offset >= len(filtered) {
		return []*FpScore{}, total
	}
	end := offset + q.PageSize
	if end > len(filtered) {
		end = len(filtered)
	}
	return filtered[offset:end], total
}

// sortFpScores 按分数倒序；同分时主机名升序，保证分页稳定。
func sortFpScores(rows []*FpScore) {
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Score != rows[j].Score {
			return rows[i].Score > rows[j].Score
		}
		return rows[i].Host < rows[j].Host
	})
}

// buildFpScoreFacets 在候选集（已按项目/分类/指纹/关键词收窄）上统计分布。
func buildFpScoreFacets(scored []*FpScore) FpScoreFacets {
	bands := []FpScoreBand{
		{Level: fpscore.LevelHigh, Label: fpscore.LevelLabel(fpscore.LevelHigh), Min: fpscore.HighMin, Max: fpscore.MaxScore},
		{Level: fpscore.LevelMedium, Label: fpscore.LevelLabel(fpscore.LevelMedium), Min: fpscore.MediumMin, Max: fpscore.HighMin - 1},
		{Level: fpscore.LevelLow, Label: fpscore.LevelLabel(fpscore.LevelLow), Min: fpscore.LowMin, Max: fpscore.MediumMin - 1},
		{Level: fpscore.LevelNone, Label: fpscore.LevelLabel(fpscore.LevelNone), Min: 0, Max: 0},
	}
	bandIdx := map[string]int{
		fpscore.LevelHigh: 0, fpscore.LevelMedium: 1, fpscore.LevelLow: 2, fpscore.LevelNone: 3,
	}
	categoryCnt := map[string]int64{}
	fingerprintCnt := map[string]int64{}
	sum := 0
	scoredCnt := int64(0)

	for _, s := range scored {
		bands[bandIdx[s.Level]].Count++
		sum += s.Score
		if s.Score > 0 {
			scoredCnt++
		}
		seenCat := map[string]bool{}
		for _, c := range s.Categories {
			key := fpscore.CategoryKey(c)
			if key == "" || seenCat[key] {
				continue
			}
			seenCat[key] = true
			categoryCnt[key]++
		}
		seenFp := map[string]bool{}
		for _, m := range s.Matches {
			key := strings.ToLower(m.Name)
			if !seenFp[key] {
				seenFp[key] = true
				fingerprintCnt[m.Name]++
			}
		}
	}

	facets := FpScoreFacets{
		Bands:        bands,
		Categories:   topFpFacets(categoryCnt, 100, fpscore.CategoryLabel),
		Fingerprints: topFpFacets(fingerprintCnt, 30, nil),
		Total:        int64(len(scored)),
		Scored:       scoredCnt,
	}
	if len(scored) > 0 {
		facets.AvgScore = (sum + len(scored)/2) / len(scored)
	}
	return facets
}

func topFpFacets(counts map[string]int64, limit int, labelFn func(string) string) []FpScoreFacet {
	out := make([]FpScoreFacet, 0, len(counts))
	for name, cnt := range counts {
		label := name
		if labelFn != nil {
			label = labelFn(name)
		}
		out = append(out, FpScoreFacet{Name: name, Label: label, AssetCnt: cnt})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].AssetCnt != out[j].AssetCnt {
			return out[i].AssetCnt > out[j].AssetCnt
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// hasCategory 判断资产是否落在某个分类下。分类大小写与分隔符写法
// 可能因上游而异，用与评分同一套归一化口径比较。
func hasCategory(categories []string, want string) bool {
	target := fpscore.CategoryKey(want)
	if target == "" {
		return false
	}
	for _, c := range categories {
		if fpscore.CategoryKey(c) == target {
			return true
		}
	}
	return false
}

func normalizeFpLevel(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "high", "medium", "low", "none":
		return strings.ToLower(strings.TrimSpace(level))
	}
	return ""
}

// normalizeFpScoreRange 把分数区间收口到 0..100；两端都给且反了就交换。
func normalizeFpScoreRange(min, max int) (int, int) {
	if min < 0 {
		min = 0
	}
	if max < 0 {
		max = 0
	}
	if min > fpscore.MaxScore {
		min = fpscore.MaxScore
	}
	if max > fpscore.MaxScore {
		max = fpscore.MaxScore
	}
	if min > 0 && max > 0 && min > max {
		min, max = max, min
	}
	return min, max
}
