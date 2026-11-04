package repo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// 指纹域：规则（条件树）+ 命中（规则 → 站点）。
//
// 规则有两种形态，同一个匹配器都能执行：
//   dsl_version=1：rules 是扁平数组 [{type,key,pattern,operator}]，语义是「全部命中」（AND）
//   dsl_version=2：condition_tree 是条件树，支持 and / or / not 嵌套
// 老规则不迁移、不改写，只在读取时折算成等价的 AND 树。

// Condition 是指纹条件树。叶子字段为 type/key/op/value，组合节点只用 and / or / not 之一。
type Condition struct {
	And []*Condition `json:"and,omitempty"`
	Or  []*Condition `json:"or,omitempty"`
	Not *Condition   `json:"not,omitempty"`

	// 叶子：header / body / title / server / status / icon_hash
	Type  string `json:"type,omitempty"`
	Key   string `json:"key,omitempty"`
	Op    string `json:"op,omitempty"` // contains / equals / regex / prefix
	Value string `json:"value,omitempty"`
}

// IsLeaf 判断是不是叶子节点。
func (c *Condition) IsLeaf() bool {
	return c != nil && len(c.And) == 0 && len(c.Or) == 0 && c.Not == nil && c.Type != ""
}

// LegacyMatch 是老规则里的扁平匹配项。
type LegacyMatch struct {
	Type     string `json:"type" bson:"type"`
	Key      string `json:"key,omitempty" bson:"key,omitempty"`
	Pattern  string `json:"pattern" bson:"pattern"`
	Operator string `json:"operator" bson:"operator"`
}

// FpRule 是一条指纹规则。
type FpRule struct {
	ID         string        `json:"id"`
	Name       string        `json:"name"`
	Category   string        `json:"category"`
	Version    string        `json:"version"`
	Enabled    bool          `json:"enabled"`
	DSLVersion int           `json:"dsl_version"`
	Condition  *Condition    `json:"condition_tree,omitempty"`
	Legacy     []LegacyMatch `json:"rules,omitempty"`
	// Expression 是 reconkit 引擎使用的表达式（与条件树二选一）。
	Expression string    `json:"expression,omitempty"`
	Source     string    `json:"source"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// FpRuleFilter 是指纹库列表条件（名称模糊 + 分类/来源精确 + 启用态）。
type FpRuleFilter struct {
	Keyword  string
	Category string
	Source   string
	Enabled  *bool
	Page     int
	PageSize int
}

// FpHit 是一条命中记录。
type FpHit struct {
	RuleID     string         `json:"rule_id"`
	RuleName   string         `json:"rule_name"`
	Category   string         `json:"category"`
	ObservedAt time.Time      `json:"observed_at"`
	RecordID   *int64         `json:"record_id"`
	Evidence   map[string]any `json:"evidence"`
}

// FingerprintRepo 是指纹规则与命中的唯一数据入口。
type FingerprintRepo interface {
	ListRules(ctx context.Context, enabledOnly bool) ([]*FpRule, error)
	// ListRulesFiltered 供旧的扁平规则列表使用（分类精确 + 名称模糊 + 分页）。
	ListRulesFiltered(ctx context.Context, category, keyword string, page, pageSize int) ([]*FpRule, int64, error)
	// ListRulesPage 供指纹库页面使用：覆盖 expression 规则，按名称/分类/来源/启用态过滤。
	ListRulesPage(ctx context.Context, f FpRuleFilter) ([]*FpRule, int64, error)
	GetRuleByName(ctx context.Context, name string) (*FpRule, error)
	UpsertRule(ctx context.Context, r *FpRule) error
	SetRuleEnabled(ctx context.Context, name string, enabled bool) error
	DeleteRule(ctx context.Context, name string) error
	DeleteRuleByID(ctx context.Context, id string) error

	// SaveHits 覆盖写：命中集合以本次匹配结果为准。
	SaveHits(ctx context.Context, siteID int64, ruleIDs []string, recordID *int64, evidence map[string]any) error
	// PruneHits 删除「本次评估过、但这次没再命中」的规则，避免指纹变了以后命中表老化。
	// universe 是本轮实际参与判定的规则全集：清理必须限定在它里面，否则会把
	// 另一条写入路径（扫描器引擎按名称写的命中）的记录一起删掉。
	PruneHits(ctx context.Context, siteID int64, keep, universe []string) (int64, error)
	ListHits(ctx context.Context, siteID int64) ([]*FpHit, error)

	// UpdateSiteProfile 回写站点的标题 / Server / 技术栈（探测时顺手更新）。
	UpdateSiteProfile(ctx context.Context, siteID int64, title, server string, tech []string) error
}

type fingerprintRepo struct{ r *Repo }

func (r *Repo) Fingerprints() FingerprintRepo { return &fingerprintRepo{r: r} }

const fpRuleColumns = `id, name, category, version, enabled, dsl_version,
	coalesce(condition_tree, 'null'::jsonb), coalesce(rules, '[]'::jsonb),
	coalesce(expression, ''), source, created_at, updated_at`

func scanFpRule(row pgx.Row) (*FpRule, error) {
	var (
		r      FpRule
		tree   []byte
		legacy []byte
	)
	if err := row.Scan(&r.ID, &r.Name, &r.Category, &r.Version, &r.Enabled, &r.DSLVersion,
		&tree, &legacy, &r.Expression, &r.Source, &r.CreatedAt, &r.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	r.CreatedAt, r.UpdatedAt = r.CreatedAt.UTC(), r.UpdatedAt.UTC()
	if len(tree) > 0 && string(tree) != "null" {
		var c Condition
		if err := json.Unmarshal(tree, &c); err == nil {
			r.Condition = &c
		}
	}
	if len(legacy) > 0 {
		_ = json.Unmarshal(legacy, &r.Legacy)
	}
	return &r, nil
}

func (r *fingerprintRepo) ListRules(ctx context.Context, enabledOnly bool) ([]*FpRule, error) {
	// 只取「治理域可执行」的规则：有条件树，或旧版扁平 rules 非空。
	// T10 同步进来的 dddd/seed 规则只有 expression（供 reconkit 引擎用），
	// 在这里没有求值器，排除掉可避免治理列表膨胀与每轮扫描空转。
	q := `select ` + fpRuleColumns + ` from fingerprint_rules
	      where (condition_tree is not null or rules <> '[]'::jsonb)`
	if enabledOnly {
		q += ` and enabled`
	}
	q += ` order by name`
	rows, err := r.r.pool.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*FpRule{}
	for rows.Next() {
		rule, err := scanFpRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rule)
	}
	return out, rows.Err()
}

func (r *fingerprintRepo) GetRuleByName(ctx context.Context, name string) (*FpRule, error) {
	return scanFpRule(r.r.pool.QueryRow(ctx,
		`select `+fpRuleColumns+` from fingerprint_rules where name = $1`, name))
}

func (r *fingerprintRepo) UpsertRule(ctx context.Context, rule *FpRule) error {
	if rule.Name == "" {
		return errors.New("规则名不能为空")
	}
	if rule.DSLVersion == 0 {
		rule.DSLVersion = 2
	}
	tree, err := json.Marshal(rule.Condition)
	if err != nil {
		return fmt.Errorf("序列化条件树失败: %w", err)
	}
	legacy, err := json.Marshal(rule.Legacy)
	if err != nil {
		return fmt.Errorf("序列化扁平规则失败: %w", err)
	}
	if rule.Source == "" {
		rule.Source = "governance"
	}
	return r.r.pool.QueryRow(ctx, `
		insert into fingerprint_rules (id, name, category, version, rules, condition_tree,
		                               dsl_version, enabled, expression, source)
		values (coalesce(nullif($1,''), substr(replace(gen_random_uuid()::text, '-', ''), 1, 24)),
	        $2, $3, $4, $5, $6, $7, $8, $9, $10)
		on conflict (name) do update
		   set category = excluded.category,
		       version = excluded.version,
		       rules = excluded.rules,
		       condition_tree = excluded.condition_tree,
		       dsl_version = excluded.dsl_version,
		       enabled = excluded.enabled,
		       expression = excluded.expression,
		       updated_at = now()
		returning id`, rule.ID, rule.Name, rule.Category, rule.Version, legacy, tree,
		rule.DSLVersion, rule.Enabled, rule.Expression, rule.Source).Scan(&rule.ID)
}

func (r *fingerprintRepo) SetRuleEnabled(ctx context.Context, name string, enabled bool) error {
	tag, err := r.r.pool.Exec(ctx,
		`update fingerprint_rules set enabled = $2, updated_at = now() where name = $1`, name, enabled)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *fingerprintRepo) ListRulesFiltered(ctx context.Context, category, keyword string, page, pageSize int) ([]*FpRule, int64, error) {
	page, pageSize = vulnPage(page, pageSize)
	kw := strings.TrimSpace(keyword)
	args := []any{category, kw, likePattern(kw)}

	const where = `where ($1 = '' or category = $1) and ($2 = '' or name ilike $3)`

	var total int64
	if err := r.r.pool.QueryRow(ctx, `select count(*) from fingerprint_rules `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := r.r.pool.Query(ctx,
		`select `+fpRuleColumns+` from fingerprint_rules `+where+`
		  order by name limit $4 offset $5`,
		append(args, pageSize, (page-1)*pageSize)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := []*FpRule{}
	for rows.Next() {
		rule, err := scanFpRule(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, rule)
	}
	return out, total, rows.Err()
}

func (r *fingerprintRepo) ListRulesPage(ctx context.Context, f FpRuleFilter) ([]*FpRule, int64, error) {
	page, pageSize := vulnPage(f.Page, f.PageSize)
	kw := strings.TrimSpace(f.Keyword)
	args := []any{f.Category, f.Source, f.Enabled, kw, likePattern(kw)}
	const where = `where ($1 = '' or category = $1)
	                 and ($2 = '' or source = $2)
	                 and ($3::boolean is null or enabled = $3)
	                 and ($4 = '' or name ilike $5)`

	var total int64
	if err := r.r.pool.QueryRow(ctx, `select count(*) from fingerprint_rules `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := r.r.pool.Query(ctx,
		`select `+fpRuleColumns+` from fingerprint_rules `+where+`
		  order by name limit $6 offset $7`,
		append(args, pageSize, (page-1)*pageSize)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []*FpRule{}
	for rows.Next() {
		rule, err := scanFpRule(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, rule)
	}
	return out, total, rows.Err()
}

func (r *fingerprintRepo) DeleteRuleByID(ctx context.Context, id string) error {
	tag, err := r.r.pool.Exec(ctx, `delete from fingerprint_rules where id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *fingerprintRepo) DeleteRule(ctx context.Context, name string) error {
	tag, err := r.r.pool.Exec(ctx, `delete from fingerprint_rules where name = $1`, name)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// HitSourceProbe 标记「由探测侧 DSL 匹配器写入」的命中行。
// 命中表有两个写入方：扫描器引擎（按规则名写，evidence.source = 采集来源）和
// 探测复核（按规则 ID 写）。两套匹配器的规则宇宙不同，谁能断言「这条指纹没了」
// 只能是它自己写过的那部分，否则两边会互相抹掉对方的结论。
const HitSourceProbe = "dsl_probe"

func (r *fingerprintRepo) SaveHits(ctx context.Context, siteID int64, ruleIDs []string, recordID *int64, evidence map[string]any) error {
	if len(ruleIDs) == 0 {
		return nil
	}
	if evidence == nil {
		evidence = map[string]any{}
	}
	// 打上本写入方的标记，PruneHits 据此划清清理边界。
	evidence["source"] = HitSourceProbe
	ev, err := jsonb(evidence)
	if err != nil {
		return err
	}
	_, err = r.r.pool.Exec(ctx, `
		insert into fingerprint_hits (site_id, rule_id, observed_at, record_id, evidence)
		select $1, t.rule_id, now(), $3, $4 from unnest($2::char(24)[]) as t(rule_id)
		on conflict (site_id, rule_id) do update
		   set observed_at = now(),
		       record_id = coalesce(excluded.record_id, fingerprint_hits.record_id),
		       evidence = excluded.evidence`,
		siteID, ruleIDs, recordID, ev)
	return err
}

// PruneHits 清理「本轮评估过、但没命中」的规则。
//
// 三重边界，少一个就会误删别人的结论：
//   - rule_id 属于 universe（本轮真正参与判定的规则集合）；
//   - rule_id 不在 keep（本轮命中的集合）里；
//   - 该行是本探测路径写的（evidence.source = dsl_probe）。
//
// 前两版只做第二条件，等价于「删掉这个站点除本次命中以外的所有命中行」。
// 而扫描器引擎是按规则名写命中的，它的结论探测侧不一定复现得出来，于是探活
// 复核一跑就把扫描阶段写进去的命中整片抹掉，表现为「任务日志说命中 N 行，
// 库里却是 0 行」，而且没有任何报错。universe 为空（规则库没加载出来）时一条都不删。
func (r *fingerprintRepo) PruneHits(ctx context.Context, siteID int64, keep, universe []string) (int64, error) {
	if len(universe) == 0 {
		return 0, nil
	}
	// nil 切片会被 pgx 编成 SQL NULL，`not (rule_id = any(NULL))` 求值为 NULL，
	// 整条 DELETE 变成 0 行——「本轮一条都没命中」时该清的反而不清。
	// 这里统一成空数组，语义即「keep 为空 = 本轮没有任何命中」。
	if keep == nil {
		keep = []string{}
	}
	tag, err := r.r.pool.Exec(ctx,
		`delete from fingerprint_hits
		  where site_id = $1
		    and rule_id = any($3::char(24)[])
		    and not (rule_id = any($2::char(24)[]))
		    and coalesce(evidence->>'source', '') = $4`,
		siteID, keep, universe, HitSourceProbe)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (r *fingerprintRepo) ListHits(ctx context.Context, siteID int64) ([]*FpHit, error) {
	rows, err := r.r.pool.Query(ctx, `
		select f.rule_id, r.name, coalesce(r.category,''), f.observed_at, f.record_id, f.evidence
		  from fingerprint_hits f left join fingerprint_rules r on r.id = f.rule_id
		 where f.site_id = $1
		 order by r.name`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*FpHit{}
	for rows.Next() {
		var (
			h  FpHit
			ev []byte
		)
		if err := rows.Scan(&h.RuleID, &h.RuleName, &h.Category, &h.ObservedAt, &h.RecordID, &ev); err != nil {
			return nil, err
		}
		h.ObservedAt = h.ObservedAt.UTC()
		if len(ev) > 0 {
			_ = json.Unmarshal(ev, &h.Evidence)
		}
		if h.RuleName == "" {
			h.RuleName = h.RuleID
		}
		out = append(out, &h)
	}
	return out, rows.Err()
}

// UpdateSiteProfile 回写站点的标题 / Server / 技术栈（探测时顺手更新）。
// tech 语义是合并不是覆盖：这列同时承载流水线扫描写的 scanner 词汇
//（Linkfinder 等，与 fingerprint_rules 零重合），整组覆盖会把另一引擎的
// 结论冲掉；零命中探测（tech 为空）更不能把既有技术栈抹成 []——
// 118 站仅 7 站技术栈可见的主因。代价是 tech 只增不减，过期词条随
// 站点生命周期清理（统一词汇的深度方案见派单 20261031 工单 02）。
func (r *fingerprintRepo) UpdateSiteProfile(ctx context.Context, siteID int64, title, server string, tech []string) error {
	if len(tech) == 0 {
		if title == "" {
			return nil
		}
		_, err := r.r.pool.Exec(ctx, `
			update sites set title = $2 where id = $1`, siteID, title)
		return err
	}
	techJSON, err := json.Marshal(tech)
	if err != nil {
		return err
	}
	_, err = r.r.pool.Exec(ctx, `
		update sites
		   set title = case when $2 <> '' then $2 else title end,
		       tech = (select coalesce(jsonb_agg(distinct e order by e), '[]'::jsonb)
		                 from jsonb_array_elements_text(sites.tech || $3::jsonb) e)
		 where id = $1`, siteID, title, techJSON)
	return err
}
