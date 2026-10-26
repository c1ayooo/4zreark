package repo

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// 情报域：9 个公开漏洞源的轮询结果落 vuln_intel。
//
// 契约两条：
//   - UpsertIntel 按 unique_key 幂等（ON CONFLICT DO UPDATE），重复轮询同一漏洞
//     不产生新行；返回 created 表示本次是 INSERT 还是 UPDATE，供轮询统计
//     New / Updated 使用。
//   - severity 只收 critical/high/medium/low/info。上游（vulnmonitor）输出
//     中文档位，映射在 service 层做，repo 不猜。

// IntelRow 是 vuln_intel 一行。
type IntelRow struct {
	ID          int64
	UniqueKey   string
	Title       string
	Description string
	Severity    string
	CVE         string
	Disclosure  string
	Solutions   string
	Source      string
	SourceName  string
	SourceURL   string
	Tags        []string
	References  []string
	CreatedAt   time.Time
	UpdatedAt   time.Time

	// 以下为富化（T3）写入的列，T1 只读不写。
	EnrichedAt time.Time
	GithubPoc  []POCRef
	CVSSScore  float64
	CVSSVector string
	CWEs       []int
	Affected   []string
	LabOnly    bool
}

// POCRef 是一条通过分诊的 GitHub PoC 仓库。只保留调用方真正会用的字段：
// 全名、链接、热度、分诊结论。恶意与噪音仓库在 Enrich 阶段已被过滤，不会入库。
type POCRef struct {
	FullName    string `json:"full_name"`
	URL         string `json:"url"`
	Stars       int    `json:"stars"`
	Verdict     string `json:"verdict"`
	TriageScore int    `json:"triage_score"`
}

// IntelFilter 是情报列表的查询条件。空值表示不筛。
type IntelFilter struct {
	Severity   string
	SourceName string
	CVE        string
	Keyword    string
	Page       int
	PageSize   int
}

// IntelRepo 是情报域仓储入口。
type IntelRepo interface {
	UpsertIntel(ctx context.Context, in IntelUpsert) (created bool, err error)
	GetByUniqueKey(ctx context.Context, key string) (*IntelRow, error)
	List(ctx context.Context, f IntelFilter) ([]*IntelRow, int64, error)
	SourceStats(ctx context.Context) ([]IntelSourceStat, error)
	SeverityStats(ctx context.Context) ([]IntelSeverityStat, error)
	GetSettings(ctx context.Context) (map[string]string, error)
	SetSetting(ctx context.Context, key, value string) error
	MarkEnriched(ctx context.Context, in IntelEnrich) error
}

// IntelEnrich 是 T3 富化的写回内容。enriched_at 只在成功时由 repo 落 now()：
// 失败不写，避免「查过一次但没查成」被当成已处理而不再重试。
type IntelEnrich struct {
	UniqueKey  string
	GithubPoc  []POCRef
	CVSSScore  float64
	CVSSVector string
	CWEs       []int
	Affected   []string
	LabOnly    bool
}

// IntelUpsert 是轮询产出的归一化情报。字段与 vulnmonitor.Intel 一一对应，
// severity 已由调用方映射成英文档位，source 是展示名、source_name 是引擎键。
type IntelUpsert struct {
	UniqueKey  string
	Title      string
	Desc       string
	Severity   string
	CVE        string
	Disclosure string
	Solutions  string
	Source     string
	SourceName string
	SourceURL  string
	From       string
	Tags       []string
	References []string
}

// IntelSourceStat 按源计数。
type IntelSourceStat struct {
	SourceName string
	Count      int64
}

// IntelSeverityStat 按严重度计数。
type IntelSeverityStat struct {
	Severity string
	Count    int64
}

type intelRepo struct{ r *Repo }

func (r *Repo) Intels() IntelRepo { return &intelRepo{r: r} }

func (r *intelRepo) UpsertIntel(ctx context.Context, in IntelUpsert) (bool, error) {
	if in.UniqueKey == "" {
		return false, errors.New("情报 unique_key 为空")
	}
	if in.Severity == "" {
		return false, errors.New("情报 severity 为空")
	}
	// From 是源站详情页；source_url 为空时用 From 兜底，避免丢链接。
	sourceURL := in.SourceURL
	if sourceURL == "" {
		sourceURL = in.From
	}

	// (xmax = 0) 是 Postgres 判断「本行由当前语句 INSERT」的惯用法：走 UPDATE
	// 分支时 xmax 不为 0。返回的 created 就是 New / Updated 统计的依据。
	var created bool
	err := r.r.pool.QueryRow(ctx, `
		INSERT INTO vuln_intel (unique_key, title, description, severity, cve,
		                        disclosure, solutions, source, source_name,
		                        source_url, tags, refs)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		ON CONFLICT (unique_key) DO UPDATE SET
			title       = EXCLUDED.title,
			description = EXCLUDED.description,
			severity    = EXCLUDED.severity,
			cve         = EXCLUDED.cve,
			disclosure  = EXCLUDED.disclosure,
			solutions   = EXCLUDED.solutions,
			source      = EXCLUDED.source,
			source_url  = EXCLUDED.source_url,
			tags        = EXCLUDED.tags,
			refs        = EXCLUDED.refs,
			updated_at  = now()
		RETURNING (xmax = 0)`,
		in.UniqueKey, in.Title, in.Desc, in.Severity, in.CVE,
		in.Disclosure, in.Solutions, in.Source, in.SourceName,
		sourceURL, jsonStringArray(in.Tags), jsonStringArray(in.References),
	).Scan(&created)
	if err != nil {
		return false, err
	}
	return created, nil
}

func (r *intelRepo) GetByUniqueKey(ctx context.Context, key string) (*IntelRow, error) {
	row := r.r.pool.QueryRow(ctx, intelColumns+` FROM vuln_intel WHERE unique_key=$1`, key)
	i, err := scanIntelRow(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return i, nil
}

func (r *intelRepo) List(ctx context.Context, f IntelFilter) ([]*IntelRow, int64, error) {
	cond, args := intelFilter(f)

	var total int64
	if err := r.r.pool.QueryRow(ctx,
		`SELECT count(*) FROM vuln_intel`+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	page, pageSize := clampPage(f.Page, f.PageSize)
	listArgs := append(append([]any{}, args...), pageSize, (page-1)*pageSize)
	rows, err := r.r.pool.Query(ctx,
		intelColumns+` FROM vuln_intel`+cond+
			` ORDER BY created_at DESC, id DESC LIMIT $`+strconv.Itoa(len(listArgs)-1)+
			` OFFSET $`+strconv.Itoa(len(listArgs)),
		listArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := make([]*IntelRow, 0, pageSize)
	for rows.Next() {
		i, err := scanIntelRow(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, i)
	}
	return out, total, rows.Err()
}

func (r *intelRepo) SourceStats(ctx context.Context) ([]IntelSourceStat, error) {
	rows, err := r.r.pool.Query(ctx, `
		SELECT source_name, count(*) FROM vuln_intel
		GROUP BY source_name ORDER BY count(*) DESC, source_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]IntelSourceStat, 0, 12)
	for rows.Next() {
		var s IntelSourceStat
		if err := rows.Scan(&s.SourceName, &s.Count); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (r *intelRepo) SeverityStats(ctx context.Context) ([]IntelSeverityStat, error) {
	rows, err := r.r.pool.Query(ctx, `
		SELECT severity, count(*) FROM vuln_intel
		GROUP BY severity ORDER BY count(*) DESC, severity`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]IntelSeverityStat, 0, 6)
	for rows.Next() {
		var s IntelSeverityStat
		if err := rows.Scan(&s.Severity, &s.Count); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (r *intelRepo) GetSettings(ctx context.Context) (map[string]string, error) {
	rows, err := r.r.pool.Query(ctx, `SELECT key, value FROM vuln_intel_settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]string, 8)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

func (r *intelRepo) SetSetting(ctx context.Context, key, value string) error {
	_, err := r.r.pool.Exec(ctx, `
		INSERT INTO vuln_intel_settings (key, value) VALUES ($1, $2)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
		key, value)
	return err
}

func (r *intelRepo) MarkEnriched(ctx context.Context, in IntelEnrich) error {
	tag, err := r.r.pool.Exec(ctx, `
		UPDATE vuln_intel SET
			github_poc  = $2::jsonb,
			cvss_score  = $3,
			cvss_vector = $4,
			cwes        = $5::jsonb,
			affected    = $6::jsonb,
			lab_only    = $7,
			enriched_at = now(),
			updated_at  = now()
		WHERE unique_key = $1`,
		in.UniqueKey, jsonPOCRefs(in.GithubPoc), in.CVSSScore, in.CVSSVector,
		jsonIntArray(in.CWEs), jsonStringArray(in.Affected), in.LabOnly)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// intelColumns 与 scanIntelRow 的扫描顺序必须一致。
const intelColumns = `SELECT id, unique_key, title, description, severity, cve,
	disclosure, solutions, source, source_name, source_url, tags, refs,
	created_at, updated_at, enriched_at, github_poc,
	coalesce(cvss_score, 0), cvss_vector, cwes, affected, lab_only`

func scanIntelRow(row pgx.Row) (*IntelRow, error) {
	var i IntelRow
	var enrichedAt *time.Time
	var tagsB, refsB, pocB, cwesB, affectedB []byte
	err := row.Scan(&i.ID, &i.UniqueKey, &i.Title, &i.Description, &i.Severity, &i.CVE,
		&i.Disclosure, &i.Solutions, &i.Source, &i.SourceName, &i.SourceURL, &tagsB, &refsB,
		&i.CreatedAt, &i.UpdatedAt, &enrichedAt, &pocB,
		&i.CVSSScore, &i.CVSSVector, &cwesB, &affectedB, &i.LabOnly)
	if err != nil {
		return nil, err
	}
	i.EnrichedAt = timeFromPG(enrichedAt)
	i.Tags = stringArrayFromJSON(tagsB)
	i.References = stringArrayFromJSON(refsB)
	i.GithubPoc = pocRefsFromJSON(pocB)
	i.CWEs = intArrayFromJSON(cwesB)
	i.Affected = stringArrayFromJSON(affectedB)
	return &i, nil
}

func intelFilter(f IntelFilter) (string, []any) {
	var cond strings.Builder
	var args []any

	add := func(column, val string) {
		if val == "" {
			return
		}
		args = append(args, val)
		cond.WriteString(andOrWhere(&cond))
		cond.WriteString(column + ` = $` + strconv.Itoa(len(args)))
	}

	add("severity", f.Severity)
	add("source_name", f.SourceName)
	add("cve", f.CVE)

	if f.Keyword != "" {
		args = append(args, "%"+f.Keyword+"%")
		n := strconv.Itoa(len(args))
		cond.WriteString(andOrWhere(&cond))
		cond.WriteString(`(title ILIKE $` + n + ` OR description ILIKE $` + n + `)`)
	}
	return cond.String(), args
}

// clampPage 归一化分页参数，与 clusters / vuln 域同一口径（上限 500）。
func clampPage(page, pageSize int) (int, int) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 500 {
		pageSize = 20
	}
	return page, pageSize
}

func andOrWhere(b *strings.Builder) string {
	if b.Len() == 0 {
		return " WHERE "
	}
	return " AND "
}

// jsonStringArray 把字符串切片序列化成 jsonb 列的值，nil 落成 []（不是 {}）。
func jsonStringArray(ss []string) string {
	if len(ss) == 0 {
		return "[]"
	}
	b, err := json.Marshal(ss)
	if err != nil {
		return "[]"
	}
	return string(b)
}

func stringArrayFromJSON(b []byte) []string {
	out := []string{}
	if len(b) == 0 {
		return out
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return []string{}
	}
	if out == nil {
		return []string{}
	}
	return out
}

func intArrayFromJSON(b []byte) []int {
	if len(b) == 0 {
		return nil
	}
	var out []int
	if err := json.Unmarshal(b, &out); err != nil {
		return nil
	}
	return out
}

// jsonIntArray 把 CWE 编号数组序列化成 jsonb。
func jsonIntArray(in []int) string {
	if len(in) == 0 {
		return "[]"
	}
	b, err := json.Marshal(in)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// jsonPOCRefs 把分诊后的 PoC 列表序列化成 jsonb。
func jsonPOCRefs(in []POCRef) string {
	if len(in) == 0 {
		return "[]"
	}
	b, err := json.Marshal(in)
	if err != nil {
		return "[]"
	}
	return string(b)
}

func pocRefsFromJSON(b []byte) []POCRef {
	out := []POCRef{}
	if len(b) == 0 {
		return out
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return []POCRef{}
	}
	if out == nil {
		return []POCRef{}
	}
	return out
}
