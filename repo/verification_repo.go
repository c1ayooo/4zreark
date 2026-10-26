package repo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// 验证域的操作面：历史流水查询、强制复验、失联删除候选、批量核验预览。
//
// 与 assets_detail.go 里的「站点详情内的验证历史」不同，这里的列表是跨站点的，
// 供验证状态页与批量操作使用；所有条件都拼进 WHERE，count 与列表共用同一份口径。

// VerificationBatchLimit 是单批复验/删除的硬上限。
// 复验会立即写回状态，删除会先逐条真实复核，过大的批次会长时间占用请求。
const VerificationBatchLimit = 500

// VerificationDeleteLimit 是失联删除的单批上限：每条都要发一次真实探测，
// 比复验更贵，所以收得更紧。
const VerificationDeleteLimit = 100

const verificationPageMax = 500

// VerificationFilter 是验证历史的查询条件。
type VerificationFilter struct {
	ProjectID  int64
	SiteID     int64
	Status     string
	ReasonCode string
	Page       int
	PageSize   int
}

func normalizeVerificationFilter(f VerificationFilter) VerificationFilter {
	f.Status = strings.TrimSpace(f.Status)
	f.ReasonCode = strings.TrimSpace(f.ReasonCode)
	if f.Page < 1 {
		f.Page = 1
	}
	if f.PageSize < 1 {
		f.PageSize = 20
	}
	if f.PageSize > verificationPageMax {
		f.PageSize = verificationPageMax
	}
	return f
}

// VerificationRow 是跨站点验证历史的一行。
type VerificationRow struct {
	ID         int64          `json:"id"`
	SiteID     int64          `json:"site_id"`
	ProjectID  int64          `json:"project_id"`
	Host       string         `json:"host"`
	Status     string         `json:"status"`
	ReasonCode string         `json:"reason_code"`
	HTTPStatus int            `json:"http_status"`
	Attempts   int            `json:"attempts"`
	Detail     map[string]any `json:"detail"`
	ObservedAt time.Time      `json:"observed_at"`
}

// ListVerifications 分页查询验证历史。
func (a *AssetRepo) ListVerifications(ctx context.Context, f VerificationFilter) ([]*VerificationRow, int64, error) {
	if a == nil || a.r == nil {
		return nil, 0, errUninitialized()
	}
	f = normalizeVerificationFilter(f)

	where := []string{"1=1"}
	args := []any{}
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, fmt.Sprintf(cond, len(args)))
	}
	if f.ProjectID > 0 {
		add("s.project_id = $%d", f.ProjectID)
	}
	if f.SiteID > 0 {
		add("v.site_id = $%d", f.SiteID)
	}
	if f.Status != "" {
		add("v.status = $%d", f.Status)
	}
	if f.ReasonCode != "" {
		add("v.reason_code = $%d", f.ReasonCode)
	}

	base := ` FROM verifications v JOIN sites s ON s.id = v.site_id WHERE ` + strings.Join(where, " AND ")

	var total int64
	if err := a.r.pool.QueryRow(ctx, `SELECT count(*)`+base, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limitAt := len(args) + 1
	offsetAt := len(args) + 2
	listArgs := append(append([]any{}, args...), f.PageSize, (f.Page-1)*f.PageSize)
	sql := `SELECT v.id, v.site_id, s.project_id, s.host, v.status, coalesce(v.reason_code,''),
	               v.http_status, v.attempts, v.detail, v.observed_at` + base +
		fmt.Sprintf(` ORDER BY v.observed_at DESC, v.id DESC LIMIT $%d OFFSET $%d`, limitAt, offsetAt)

	rows, err := a.r.pool.Query(ctx, sql, listArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := []*VerificationRow{}
	for rows.Next() {
		var v VerificationRow
		var detail []byte
		if err := rows.Scan(&v.ID, &v.SiteID, &v.ProjectID, &v.Host, &v.Status, &v.ReasonCode,
			&v.HTTPStatus, &v.Attempts, &detail, &v.ObservedAt); err != nil {
			return nil, 0, err
		}
		if len(detail) > 0 {
			_ = json.Unmarshal(detail, &v.Detail)
		}
		if v.Detail == nil {
			v.Detail = map[string]any{}
		}
		out = append(out, &v)
	}
	return out, total, rows.Err()
}

// RecheckItem 是一条被重置的站点。
type RecheckItem struct {
	SiteID         int64  `json:"site_id"`
	Host           string `json:"host"`
	BeforeState    string `json:"before_state"`
	BeforeAttempts int    `json:"before_attempts"`
}

// RecheckSkip 是一条被跳过的站点及原因。
type RecheckSkip struct {
	SiteID int64  `json:"site_id"`
	Host   string `json:"host"`
	Reason string `json:"reason"`
}

// RecheckReport 是一次强制复验的回执。
type RecheckReport struct {
	Requested    int           `json:"requested"`
	Reset        int           `json:"reset"`
	Skipped      int           `json:"skipped"`
	Items        []RecheckItem `json:"items"`
	SkippedItems []RecheckSkip `json:"skipped_items"`
	Warnings     []string      `json:"warnings,omitempty"`
}

// RecheckSites 强制复验：重置 attempts 与失败计数，让下一轮探测立即重跑。
//
// 只重置、不删除；失联站点回到 pending（下一次探测成功即 reachable），
// archived 站点不参与，避免把已归档资产重新拉回回归队列。
func (a *AssetRepo) RecheckSites(ctx context.Context, ids []int64) (*RecheckReport, error) {
	if a == nil || a.r == nil {
		return nil, errUninitialized()
	}
	if len(ids) == 0 {
		return nil, errors.New("site_ids 不能为空")
	}
	if len(ids) > VerificationBatchLimit {
		return nil, fmt.Errorf("单次最多复验 %d 个站点", VerificationBatchLimit)
	}

	tx, err := a.r.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	rows, err := tx.Query(ctx, `
		SELECT id, host, state, attempts
		  FROM sites
		 WHERE id = ANY($1)
		 ORDER BY id
		 FOR UPDATE`, ids)
	if err != nil {
		return nil, err
	}

	type rowState struct {
		id       int64
		host     string
		state    string
		attempts int
	}
	found := make([]rowState, 0, len(ids))
	byID := make(map[int64]rowState, len(ids))
	for rows.Next() {
		var r rowState
		if err := rows.Scan(&r.id, &r.host, &r.state, &r.attempts); err != nil {
			rows.Close()
			return nil, err
		}
		found = append(found, r)
		byID[r.id] = r
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	report := &RecheckReport{
		Requested:    len(ids),
		Items:        []RecheckItem{},
		SkippedItems: []RecheckSkip{},
	}
	for _, id := range ids {
		r, ok := byID[id]
		if !ok {
			report.Skipped++
			report.SkippedItems = append(report.SkippedItems, RecheckSkip{SiteID: id, Reason: "站点不存在"})
			continue
		}
		if r.state == "archived" {
			report.Skipped++
			report.SkippedItems = append(report.SkippedItems, RecheckSkip{
				SiteID: r.id, Host: r.host, Reason: "站点已归档，不参与复验",
			})
			continue
		}
		if _, err := tx.Exec(ctx, `
			UPDATE sites
			   SET attempts = 0,
			       verification_status = 'pending',
			       verification_reason = NULL,
			       next_verification_at = now(),
			       state = CASE WHEN state = 'lost' THEN 'pending' ELSE state END,
			       consecutive_failures = CASE WHEN state = 'lost' THEN 0 ELSE consecutive_failures END,
			       retry_step = CASE WHEN state = 'lost' THEN 0 ELSE retry_step END,
			       lost_since_ms = CASE WHEN state = 'lost' THEN 0 ELSE lost_since_ms END,
			       cleanup_eligible = false,
			       updated_at = now()
			 WHERE id = $1`, r.id); err != nil {
			return nil, err
		}
		report.Reset++
		report.Items = append(report.Items, RecheckItem{
			SiteID: r.id, Host: r.host, BeforeState: r.state, BeforeAttempts: r.attempts,
		})
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return report, nil
}

// LostDeleteCandidate 是失联删除的候选站点。
type LostDeleteCandidate struct {
	ID             int64
	ProjectID      int64
	Host           string
	State          string
	LostSinceMS    int64
	ProtectedUntil *time.Time
}

// LostDeleteCandidates 读取删除候选项，不做状态过滤：
// 复核结果与跳过原因要由 service 层逐条给出，调用方才能解释「为什么没删」。
func (a *AssetRepo) LostDeleteCandidates(ctx context.Context, ids []int64) ([]*LostDeleteCandidate, error) {
	if a == nil || a.r == nil {
		return nil, errUninitialized()
	}
	if len(ids) == 0 {
		return nil, errors.New("site_ids 不能为空")
	}
	if len(ids) > VerificationDeleteLimit {
		return nil, fmt.Errorf("单次最多删除 %d 个失联站点", VerificationDeleteLimit)
	}
	rows, err := a.r.pool.Query(ctx, `
		SELECT id, project_id, host, state, lost_since_ms, protected_until
		  FROM sites
		 WHERE id = ANY($1)
		 ORDER BY id`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*LostDeleteCandidate{}
	for rows.Next() {
		var c LostDeleteCandidate
		if err := rows.Scan(&c.ID, &c.ProjectID, &c.Host, &c.State, &c.LostSinceMS, &c.ProtectedUntil); err != nil {
			return nil, err
		}
		out = append(out, &c)
	}
	return out, rows.Err()
}

// DeleteLostSite 物理删除一个仍处于 lost 的站点。
// 相关流水（verifications / asset_events / 指纹命中 / 入口）由外键级联清理；
// raw_records 的 site_id 置空，保留证据链但不阻塞删除。
func (a *AssetRepo) DeleteLostSite(ctx context.Context, siteID int64) error {
	if a == nil || a.r == nil {
		return errUninitialized()
	}
	tag, err := a.r.pool.Exec(ctx, `DELETE FROM sites WHERE id = $1 AND state = 'lost'`, siteID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// VerificationSample 是批量预览里的样本行。
type VerificationSample struct {
	SiteID             int64      `json:"site_id"`
	Host               string     `json:"host"`
	State              string     `json:"state"`
	VerificationStatus string     `json:"verification_status"`
	Attempts           int        `json:"attempts"`
	NextVerificationAt *time.Time `json:"next_verification_at"`
}

// VerificationBatchPreview 是批量核验预览的结果。
type VerificationBatchPreview struct {
	Total  int64                `json:"total"`
	Sample []VerificationSample `json:"sample"`
	Note   string               `json:"note,omitempty"`
}

// PreviewVerificationBatch 复用资产列表的筛选条件，只统计「可复验」的站点。
// 不写任何表，也不发请求；过滤口径与执行时保持一致（archived 不参与）。
func (a *AssetRepo) PreviewVerificationBatch(ctx context.Context, q AssetQuery) (*VerificationBatchPreview, error) {
	if a == nil || a.r == nil {
		return nil, errUninitialized()
	}
	q.Kind = "site"
	q.SiteGroup = true
	w, err := a.buildAssetWhere(q)
	if err != nil {
		return nil, err
	}
	w.parts = append(w.parts, "s.state <> 'archived'")
	where := w.String()

	var total int64
	if err := a.r.pool.QueryRow(ctx, `SELECT count(*) FROM sites s WHERE `+where, w.args...).Scan(&total); err != nil {
		return nil, err
	}

	rows, err := a.r.pool.Query(ctx, `
		SELECT s.id, s.host, s.state, s.verification_status, s.attempts, s.next_verification_at
		  FROM sites s
		 WHERE `+where+`
		 ORDER BY s.id
		 LIMIT 20`, w.args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	res := &VerificationBatchPreview{Total: total, Sample: []VerificationSample{}}
	for rows.Next() {
		var s VerificationSample
		if err := rows.Scan(&s.SiteID, &s.Host, &s.State, &s.VerificationStatus,
			&s.Attempts, &s.NextVerificationAt); err != nil {
			return nil, err
		}
		res.Sample = append(res.Sample, s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if total == 0 {
		res.Note = "当前筛选条件下没有可复验的站点"
	}
	return res, nil
}

// VerificationBatchSiteIDs 返回批量预览同一套筛选条件下的站点 ID（最多 limit 条）。
func (a *AssetRepo) VerificationBatchSiteIDs(ctx context.Context, q AssetQuery, limit int) ([]int64, error) {
	if a == nil || a.r == nil {
		return nil, errUninitialized()
	}
	if limit <= 0 || limit > VerificationBatchLimit {
		limit = VerificationBatchLimit
	}
	q.Kind = "site"
	q.SiteGroup = true
	w, err := a.buildAssetWhere(q)
	if err != nil {
		return nil, err
	}
	w.parts = append(w.parts, "s.state <> 'archived'")
	args := append(append([]any{}, w.args...), limit)
	rows, err := a.r.pool.Query(ctx,
		`SELECT s.id FROM sites s WHERE `+w.String()+fmt.Sprintf(` ORDER BY s.id LIMIT $%d`, len(args)), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []int64{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// VerificationStat 是一个计数项。
type VerificationStat struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

// VerificationStats 是验证流水的分布。
type VerificationStats struct {
	ByStatus []VerificationStat `json:"by_status"`
	ByReason []VerificationStat `json:"by_reason"`
}

// VerificationStats 按 project_id 统计状态与失败原因分布。
func (a *AssetRepo) VerificationStats(ctx context.Context, projectID int64) (*VerificationStats, error) {
	if a == nil || a.r == nil {
		return nil, errUninitialized()
	}
	where := ""
	args := []any{}
	if projectID > 0 {
		args = append(args, projectID)
		where = " WHERE s.project_id = $1"
	}
	out := &VerificationStats{ByStatus: []VerificationStat{}, ByReason: []VerificationStat{}}

	rows, err := a.r.pool.Query(ctx,
		`SELECT v.status, count(*) FROM verifications v JOIN sites s ON s.id = v.site_id`+where+`
		 GROUP BY 1 ORDER BY 2 DESC`, args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var st VerificationStat
		if err := rows.Scan(&st.Key, &st.Count); err != nil {
			rows.Close()
			return nil, err
		}
		out.ByStatus = append(out.ByStatus, st)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	reasonWhere := " WHERE v.reason_code IS NOT NULL AND v.reason_code <> ''"
	if projectID > 0 {
		reasonWhere += " AND s.project_id = $1"
	}
	rows, err = a.r.pool.Query(ctx,
		`SELECT v.reason_code, count(*) FROM verifications v JOIN sites s ON s.id = v.site_id`+
			reasonWhere+` GROUP BY 1 ORDER BY 2 DESC LIMIT 20`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var st VerificationStat
		if err := rows.Scan(&st.Key, &st.Count); err != nil {
			return nil, err
		}
		out.ByReason = append(out.ByReason, st)
	}
	return out, rows.Err()
}
