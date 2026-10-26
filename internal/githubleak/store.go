package githubleak

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/google/uuid"
)

const runLockID int64 = 739522101

type Store struct{ db *sql.DB }

func NewStore(ctx context.Context, db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, errors.New("github leak store database is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	_, err := db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS github_leak_findings (
 id TEXT PRIMARY KEY,
 status TEXT NOT NULL DEFAULT 'new' CHECK(status IN('new','triaged','false_positive','resolved')),
	rule_name TEXT NOT NULL DEFAULT 'legacy',
 keyword TEXT NOT NULL,
 repository TEXT NOT NULL,
 path TEXT NOT NULL,
 blob_sha TEXT NOT NULL,
 line_number INTEGER NOT NULL DEFAULT 0,
 secret_type TEXT NOT NULL,
 confidence TEXT NOT NULL CHECK(confidence IN('likely','suspected')),
 severity TEXT NOT NULL CHECK(severity IN('critical','high','medium','low')),
 fingerprint TEXT NOT NULL,
 masked_excerpt TEXT NOT NULL,
 html_url TEXT NOT NULL,
 first_seen_at TIMESTAMPTZ NOT NULL,
 last_seen_at TIMESTAMPTZ NOT NULL
);
DO $github_leak_migration$
DECLARE old_constraint TEXT;
BEGIN
 FOR old_constraint IN
 SELECT conname FROM pg_constraint
 WHERE conrelid='github_leak_findings'::regclass AND contype='u'
   AND pg_get_constraintdef(oid) LIKE 'UNIQUE (repository, path, blob_sha, keyword, secret_type%'
   AND pg_get_constraintdef(oid) NOT LIKE '%fingerprint%'
 LOOP
  EXECUTE format('ALTER TABLE github_leak_findings DROP CONSTRAINT %I',old_constraint);
 END LOOP;
END $github_leak_migration$;
ALTER TABLE github_leak_findings ADD COLUMN IF NOT EXISTS rule_name TEXT NOT NULL DEFAULT 'legacy';
DO $github_leak_identity_migration$
BEGIN
 IF EXISTS (
  SELECT 1 FROM pg_indexes
 WHERE schemaname=current_schema() AND indexname='github_leak_findings_identity_idx'
   AND POSITION('fingerprint' IN LOWER(indexdef))=0
 ) THEN
  EXECUTE 'DROP INDEX IF EXISTS github_leak_findings_identity_idx';
 END IF;
END $github_leak_identity_migration$;
ALTER TABLE github_leak_findings ADD COLUMN IF NOT EXISTS secret_value TEXT NOT NULL DEFAULT '';
ALTER TABLE github_leak_findings ADD COLUMN IF NOT EXISTS secret_key TEXT NOT NULL DEFAULT '';
ALTER TABLE github_leak_findings ADD COLUMN IF NOT EXISTS verify_status TEXT NOT NULL DEFAULT '';
ALTER TABLE github_leak_findings ADD COLUMN IF NOT EXISTS verify_evidence TEXT NOT NULL DEFAULT '';
ALTER TABLE github_leak_findings ADD COLUMN IF NOT EXISTS source_updated_at TIMESTAMPTZ;
CREATE UNIQUE INDEX IF NOT EXISTS github_leak_findings_identity_idx
 ON github_leak_findings(repository,path,blob_sha,keyword,secret_type,line_number,fingerprint);
CREATE INDEX IF NOT EXISTS github_leak_findings_status_idx ON github_leak_findings(status,last_seen_at DESC);
CREATE INDEX IF NOT EXISTS github_leak_findings_keyword_idx ON github_leak_findings(keyword,last_seen_at DESC);
CREATE INDEX IF NOT EXISTS github_leak_findings_confidence_idx ON github_leak_findings(confidence,last_seen_at DESC);
CREATE TABLE IF NOT EXISTS github_leak_keyword_state (
 keyword TEXT PRIMARY KEY,
 etag TEXT NOT NULL DEFAULT '',
 last_attempt_at TIMESTAMPTZ,
 last_success_at TIMESTAMPTZ,
 last_status TEXT NOT NULL DEFAULT 'idle',
 last_error TEXT NOT NULL DEFAULT '',
 incomplete BOOLEAN NOT NULL DEFAULT FALSE,
	truncated BOOLEAN NOT NULL DEFAULT FALSE,
 page_cursor INTEGER NOT NULL DEFAULT 1,
 updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
ALTER TABLE github_leak_keyword_state ADD COLUMN IF NOT EXISTS truncated BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE github_leak_keyword_state ADD COLUMN IF NOT EXISTS page_cursor INTEGER NOT NULL DEFAULT 1;
ALTER TABLE github_leak_keyword_state ADD COLUMN IF NOT EXISTS freshness_policy TEXT NOT NULL DEFAULT '';
ALTER TABLE github_leak_keyword_state ADD COLUMN IF NOT EXISTS freshness_checked_at TIMESTAMPTZ;
ALTER TABLE github_leak_keyword_state ADD COLUMN IF NOT EXISTS freshness_cursor INTEGER NOT NULL DEFAULT 0;
ALTER TABLE github_leak_keyword_state ADD COLUMN IF NOT EXISTS freshness_cursor_etag TEXT NOT NULL DEFAULT '';
CREATE TABLE IF NOT EXISTS github_leak_runs (
 id TEXT PRIMARY KEY,
 status TEXT NOT NULL CHECK(status IN('running','success','partial','error','rate_limited','cancelled')),
 error TEXT NOT NULL DEFAULT '',
 started_at TIMESTAMPTZ NOT NULL,
 finished_at TIMESTAMPTZ,
 rate_remaining INTEGER NOT NULL DEFAULT -1,
 rate_reset_at TIMESTAMPTZ,
	requests INTEGER NOT NULL DEFAULT 0,
 processed INTEGER NOT NULL DEFAULT 0,
 detected INTEGER NOT NULL DEFAULT 0
);
ALTER TABLE github_leak_runs ADD COLUMN IF NOT EXISTS requests INTEGER NOT NULL DEFAULT 0;
ALTER TABLE github_leak_runs ADD COLUMN IF NOT EXISTS filtered_fork INTEGER NOT NULL DEFAULT 0;
ALTER TABLE github_leak_runs ADD COLUMN IF NOT EXISTS filtered_noise INTEGER NOT NULL DEFAULT 0;
ALTER TABLE github_leak_runs ADD COLUMN IF NOT EXISTS filtered_suppressed INTEGER NOT NULL DEFAULT 0;
ALTER TABLE github_leak_runs ADD COLUMN IF NOT EXISTS filtered_boilerplate INTEGER NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS github_leak_runs_started_idx ON github_leak_runs(started_at DESC);
`)
	if err != nil {
		return nil, fmt.Errorf("initialize github leak schema: %w", err)
	}
	// 静默清单（误报治理最后一公里）：repo/org/path_glob/fingerprint_prefix
	if _, err := db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS github_leak_suppressions (
	id TEXT PRIMARY KEY,
	pattern_type TEXT NOT NULL,
	pattern TEXT NOT NULL,
	note TEXT NOT NULL DEFAULT '',
	created_by TEXT NOT NULL DEFAULT '',
	created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS github_leak_suppressions_type_pattern_key ON github_leak_suppressions(pattern_type, pattern);
`); err != nil {
		return nil, fmt.Errorf("initialize github leak suppressions: %w", err)
	}
	return &Store{db: db}, nil
}

// ResetWaterline 重置规则水位线（清 ETag/时效复核状态）→ 下一轮强制全量扫描。
// query 为空 = 重置全部规则（新增检测模式后回扫历史用）。
func (s *Store) ResetWaterline(ctx context.Context, query string) (int64, error) {
	query = strings.TrimSpace(query)
	const resetSet = `SET etag='', last_status='', freshness_checked_at=NULL, freshness_cursor=0, freshness_cursor_etag=''`
	var res sql.Result
	var err error
	if query == "" {
		res, err = s.db.ExecContext(ctx, `UPDATE github_leak_keyword_state `+resetSet)
	} else {
		res, err = s.db.ExecContext(ctx, `UPDATE github_leak_keyword_state `+resetSet+` WHERE keyword = $1`, query)
	}
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// RulePrecisionStats 按规则聚合处置状态（confirmed/false_positive/ignored 比例
// = 规则精确率运营视图；状态由人工研判 UpdateStatus 沉淀）。
// 真阳性按现行状态机统计：triaged/resolved（'confirmed' 为历史遗留值，一并
// 计入防止存量数据失真；'ignored' 同理保留兼容）。
func (s *Store) RulePrecisionStats(ctx context.Context) ([]RulePrecision, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT COALESCE(rule_name,''), COUNT(*),
		       SUM(CASE WHEN status IN ('triaged','resolved','confirmed') THEN 1 ELSE 0 END),
		       SUM(CASE WHEN status='false_positive' THEN 1 ELSE 0 END),
		       SUM(CASE WHEN status='ignored' THEN 1 ELSE 0 END),
		       MAX(last_seen_at)
		FROM github_leak_findings
		GROUP BY rule_name ORDER BY COUNT(*) DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]RulePrecision, 0, 16)
	for rows.Next() {
		var r RulePrecision
		var lastSeen string
		if err := rows.Scan(&r.RuleName, &r.Total, &r.Confirmed, &r.FalsePositive, &r.Ignored, &lastSeen); err != nil {
			continue
		}
		if t, err := time.Parse(time.RFC3339Nano, lastSeen); err == nil {
			r.LastSeenAt = t
		}
		if r.Total > 0 {
			r.Precision = float64(r.Confirmed) / float64(r.Total)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) AcquireRunLock(ctx context.Context) (func(), bool, error) {
	if s == nil || s.db == nil {
		return nil, false, errors.New("github leak store unavailable")
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return nil, false, err
	}
	var locked bool
	if err = conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, runLockID).Scan(&locked); err != nil || !locked {
		_ = conn.Close()
		return nil, false, err
	}
	var once sync.Once
	unlock := func() {
		once.Do(func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := conn.ExecContext(cleanup, `SELECT pg_advisory_unlock($1)`, runLockID); err != nil {
				// 释放失败靠随后 conn.Close() 断连兜底释放会话级锁
				log.Printf("[githubleak] 释放 run advisory 锁失败(靠连接关闭兜底): %v", err)
			}
			_ = conn.Close()
		})
	}
	return unlock, true, nil
}

// UpsertCandidates 候选入库（指纹去重 upsert）。返回本轮**真正新增**的候选
// （xmax=0 判定）与更新条数——新增集合是 IM 通知的素材源。
func (s *Store) UpsertCandidates(ctx context.Context, candidates []Candidate, seenAt time.Time) (inserted []Candidate, updated int, err error) {
	if seenAt.IsZero() {
		seenAt = time.Now().UTC()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.PrepareContext(ctx, `
INSERT INTO github_leak_findings
 (id,status,rule_name,keyword,repository,path,blob_sha,line_number,secret_type,confidence,severity,fingerprint,masked_excerpt,html_url,secret_value,secret_key,source_updated_at,first_seen_at,last_seen_at)
VALUES($1,'new',$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$17)
ON CONFLICT(repository,path,blob_sha,keyword,secret_type,line_number,fingerprint) DO UPDATE SET
	rule_name=EXCLUDED.rule_name,
 confidence=EXCLUDED.confidence,severity=EXCLUDED.severity,
 fingerprint=EXCLUDED.fingerprint,masked_excerpt=EXCLUDED.masked_excerpt,html_url=EXCLUDED.html_url,
 secret_value=EXCLUDED.secret_value,
 secret_key=COALESCE(NULLIF(EXCLUDED.secret_key,''),github_leak_findings.secret_key),
 source_updated_at=EXCLUDED.source_updated_at,
 last_seen_at=EXCLUDED.last_seen_at
RETURNING (xmax=0)`)
	if err != nil {
		return nil, 0, err
	}
	defer stmt.Close()
	newlyInserted := make([]Candidate, 0, len(candidates))
	for _, candidate := range candidates {
		candidate, err = validateCandidate(candidate)
		if err != nil {
			return nil, 0, err
		}
		var created bool
		err = stmt.QueryRowContext(ctx, uuid.NewString(), candidate.RuleName, candidate.Keyword, candidate.Repository, candidate.Path,
			candidate.BlobSHA, candidate.Line, candidate.SecretType, candidate.Confidence, candidate.Severity,
			candidate.Fingerprint, candidate.MaskedExcerpt, candidate.HTMLURL, candidate.SecretValue, candidate.SecretKey,
			candidate.SourceUpdatedAt.UTC(), seenAt.UTC()).Scan(&created)
		if err != nil {
			return nil, 0, err
		}
		if created {
			newlyInserted = append(newlyInserted, candidate)
		} else {
			updated++
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, 0, err
	}
	return newlyInserted, updated, nil
}

func validateCandidate(candidate Candidate) (Candidate, error) {
	var err error
	if strings.TrimSpace(candidate.RuleName) == "" {
		candidate.RuleName = "legacy"
	}
	if candidate.RuleName, err = normalizeRuleName(candidate.RuleName); err != nil {
		return Candidate{}, err
	}
	if candidate.Keyword, err = normalizeRuleQuery(candidate.Keyword); err != nil {
		return Candidate{}, err
	}
	candidate.Repository = strings.TrimSpace(candidate.Repository)
	candidate.Path = strings.TrimSpace(candidate.Path)
	candidate.BlobSHA = strings.TrimSpace(candidate.BlobSHA)
	candidate.SecretType = strings.TrimSpace(candidate.SecretType)
	candidate.Confidence = strings.ToLower(strings.TrimSpace(candidate.Confidence))
	candidate.Severity = strings.ToLower(strings.TrimSpace(candidate.Severity))
	candidate.Fingerprint = strings.ToLower(strings.TrimSpace(candidate.Fingerprint))
	candidate.MaskedExcerpt = strings.TrimSpace(candidate.MaskedExcerpt)
	candidate.HTMLURL = strings.TrimSpace(candidate.HTMLURL)
	if candidate.SourceUpdatedAt.IsZero() {
		return Candidate{}, errors.New("missing GitHub source update time")
	}
	candidate.SourceUpdatedAt = candidate.SourceUpdatedAt.UTC()
	if candidate.SourceUpdatedAt.After(time.Now().UTC().Add(maxSourceFutureSkew)) {
		return Candidate{}, errors.New("GitHub source update time is in the future")
	}
	if candidate.Repository == "" || len(candidate.Repository) > 300 || candidate.Path == "" || len(candidate.Path) > 2000 || hasUnsafeMetadataText(candidate.Repository) || hasUnsafeMetadataText(candidate.Path) {
		return Candidate{}, errors.New("invalid GitHub finding metadata")
	}
	repositoryParts := strings.Split(candidate.Repository, "/")
	if len(repositoryParts) != 2 || repositoryParts[0] == "" || repositoryParts[1] == "" {
		return Candidate{}, errors.New("invalid GitHub finding repository")
	}
	if (len(candidate.BlobSHA) != 40 && len(candidate.BlobSHA) != 64) || !isHexString(candidate.BlobSHA) {
		return Candidate{}, errors.New("invalid GitHub blob SHA")
	}
	if candidate.Line < 0 || candidate.Line > 100000000 {
		return Candidate{}, errors.New("invalid GitHub finding line")
	}
	if candidate.SecretType == "" || len(candidate.SecretType) > 100 || hasUnsafeMetadataText(candidate.SecretType) {
		return Candidate{}, errors.New("invalid secret type")
	}
	if candidate.Confidence != "likely" && candidate.Confidence != "suspected" {
		return Candidate{}, errors.New("invalid confidence")
	}
	switch candidate.Severity {
	case "critical", "high", "medium", "low":
	default:
		return Candidate{}, errors.New("invalid severity")
	}
	decoded, decodeErr := hex.DecodeString(candidate.Fingerprint)
	if decodeErr != nil || len(decoded) != sha256Size {
		return Candidate{}, errors.New("invalid HMAC fingerprint")
	}
	if candidate.MaskedExcerpt == "" || len(candidate.MaskedExcerpt) > 2048 || containsControl(candidate.MaskedExcerpt) {
		return Candidate{}, errors.New("invalid masked excerpt")
	}
	u, parseErr := url.Parse(candidate.HTMLURL)
	if parseErr != nil || u.Scheme != "https" || !strings.EqualFold(u.Hostname(), "github.com") || u.Port() != "" || u.User != nil || u.RawQuery != "" {
		return Candidate{}, errors.New("invalid GitHub finding URL")
	}
	if u.Fragment != "" && lineNumberFromURL(candidate.HTMLURL) == 0 {
		return Candidate{}, errors.New("invalid GitHub finding URL fragment")
	}
	if line := lineNumberFromURL(candidate.HTMLURL); line != candidate.Line {
		return Candidate{}, errors.New("GitHub finding line does not match URL")
	}
	return candidate, nil
}

const sha256Size = 32

func containsControl(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

const findingColumns = `id,status,rule_name,keyword,repository,path,blob_sha,line_number,secret_type,confidence,severity,fingerprint,masked_excerpt,html_url,secret_value,secret_key,verify_status,verify_evidence,source_updated_at,first_seen_at,last_seen_at`

type rowScanner interface{ Scan(...any) error }

func scanFinding(row rowScanner) (Finding, error) {
	var finding Finding
	err := row.Scan(&finding.ID, &finding.Status, &finding.RuleName, &finding.Keyword, &finding.Repository, &finding.Path, &finding.BlobSHA,
		&finding.Line, &finding.SecretType, &finding.Confidence, &finding.Severity, &finding.Fingerprint,
		&finding.MaskedExcerpt, &finding.HTMLURL, &finding.SecretValue, &finding.SecretKey, &finding.VerifyStatus,
		&finding.VerifyEvidence, &finding.SourceUpdatedAt, &finding.FirstSeenAt, &finding.LastSeenAt)
	return finding, err
}

// RecordVerifyResult 回写一条 finding 的验证结论（检测→验证闭环落库；
// verify_evidence 存厂商错误码/账号归属等脱敏摘要,与 verify_status 同步更新）。
func (s *Store) RecordVerifyResult(ctx context.Context, id, verifyStatus, verifyEvidence string) error {
	r, err := s.db.ExecContext(ctx, `UPDATE github_leak_findings SET verify_status=$2, verify_evidence=$3 WHERE id=$1`,
		id, verifyStatus, verifyEvidence)
	if err != nil {
		return err
	}
	if n, _ := r.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ListSince 返回某个时间点之后首次入库的命中（用于信息收集机器人通知的水位查询）。
func (s *Store) ListSince(ctx context.Context, after time.Time, limit int) ([]Finding, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+findingColumns+` FROM github_leak_findings
	 WHERE first_seen_at > $1 ORDER BY first_seen_at, id LIMIT $2`, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Finding{}
	for rows.Next() {
		f, scanErr := scanFinding(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *Store) List(ctx context.Context, filter ListFilter) (ListResult, error) {
	result := ListResult{Items: []Finding{}}
	if err := filter.Validate(); err != nil {
		return result, err
	}
	result.Page, result.PageSize = filter.Page, filter.PageSize
	where, args := buildListWhere(filter)
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return result, err
	}
	defer func() { _ = tx.Rollback() }()
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM github_leak_findings WHERE "+where, args...).Scan(&result.Total); err != nil {
		return result, err
	}
	result.TotalPages = (result.Total + filter.PageSize - 1) / filter.PageSize
	args = append(args, filter.PageSize, (filter.Page-1)*filter.PageSize)
	query := fmt.Sprintf("SELECT %s FROM github_leak_findings WHERE %s ORDER BY last_seen_at DESC,id LIMIT $%d OFFSET $%d", findingColumns, where, len(args)-1, len(args))
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return result, err
	}
	for rows.Next() {
		finding, scanErr := scanFinding(rows)
		if scanErr != nil {
			_ = rows.Close()
			return result, scanErr
		}
		result.Items = append(result.Items, finding)
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return result, err
	}
	return result, tx.Commit()
}

func buildListWhere(filter ListFilter) (string, []any) {
	where := "TRUE"
	args := make([]any, 0, 5)
	add := func(expression string, value any) {
		args = append(args, value)
		where += " AND " + fmt.Sprintf(expression, len(args))
	}
	if filter.Status != "" {
		add("status=$%d", filter.Status)
	}
	if filter.Keyword != "" {
		add("LOWER(keyword)=LOWER($%d)", filter.Keyword)
	}
	if filter.Query != "" {
		// 模糊检索（规则名/仓库/路径/类型全字段）：PG 参数化下 ESCAPE 子句转义不稳定，
		// 改用 strpos 语义（等价包含匹配，无通配符注入面）
		add(`strpos(LOWER(id||' '||fingerprint||' '||repository||' '||path||' '||rule_name||' '||keyword||' '||secret_type), $%d) > 0`, strings.ToLower(filter.Query))
	}
	if len(filter.RuleNames) > 0 {
		add("rule_name = ANY($%d)", filter.RuleNames)
	}
	if filter.SourceUpdatedAfter != nil {
		// 回溯窗口过滤：窗口外的历史行仍保留在库中供审计，但不再展示。
		// source_updated_at 为 NULL 的存量行（本特性上线前入库）保守放行。
		add("(source_updated_at IS NULL OR source_updated_at >= $%d)", filter.SourceUpdatedAfter.UTC())
	}
	return where, args
}

// ListMissingSecret 返回未记录明文的命中（历史行明文回填队列，最近命中优先）。
func (s *Store) ListMissingSecret(ctx context.Context, limit int) ([]Finding, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+findingColumns+` FROM github_leak_findings
	 WHERE secret_value = '' ORDER BY last_seen_at DESC, id LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Finding{}
	for rows.Next() {
		f, scanErr := scanFinding(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// UpdateSecretValue 仅在明文为空时回填，幂等且不覆盖已有值；key 同步回填，
// 已有 key 不被空值覆盖。
func (s *Store) UpdateSecretValue(ctx context.Context, id, key, value string) error {
	id = strings.TrimSpace(id)
	key = strings.TrimSpace(key)
	if id == "" || len(id) > 100 || len(key) > 256 || containsControl(key) || value == "" || len(value) > 64<<10 || containsControlExceptNewlineTab(value) {
		return errors.New("invalid secret value backfill")
	}
	res, err := s.db.ExecContext(ctx, `UPDATE github_leak_findings SET secret_value=$2,
	 secret_key=COALESCE(NULLIF($3,''),secret_key) WHERE id=$1 AND secret_value=''`, id, value, key)
	if err != nil {
		return err
	}
	if n, affErr := res.RowsAffected(); affErr == nil && n == 0 {
		return ErrNotFound
	}
	return nil
}

// containsControlExceptNewlineTab 放行私钥块必需的换行/制表，其余控制字符拒绝。
func containsControlExceptNewlineTab(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' {
			return true
		}
	}
	return false
}

func (s *Store) Get(ctx context.Context, id string) (Finding, error) {
	id = strings.TrimSpace(id)
	if id == "" || len(id) > 100 {
		return Finding{}, ErrNotFound
	}
	finding, err := scanFinding(s.db.QueryRowContext(ctx, "SELECT "+findingColumns+" FROM github_leak_findings WHERE id=$1", id))
	if errors.Is(err, sql.ErrNoRows) {
		return Finding{}, ErrNotFound
	}
	return finding, err
}

func (s *Store) UpdateStatus(ctx context.Context, id, status string) (Finding, error) {
	status = strings.ToLower(strings.TrimSpace(status))
	if !ValidStatus(status) {
		return Finding{}, errors.New("invalid finding status")
	}
	finding, err := scanFinding(s.db.QueryRowContext(ctx, `UPDATE github_leak_findings SET status=$2 WHERE id=$1 RETURNING `+findingColumns, strings.TrimSpace(id), status))
	if errors.Is(err, sql.ErrNoRows) {
		return Finding{}, ErrNotFound
	}
	return finding, err
}

// Stats 统计（sourceUpdatedAfter 非空时只统计回溯窗口内数据；存量 NULL 行放行）。
func (s *Store) Stats(ctx context.Context, sourceUpdatedAfter *time.Time) (Stats, error) {
	var stats Stats
	where := "TRUE"
	args := []any{}
	if sourceUpdatedAfter != nil {
		where = "(source_updated_at IS NULL OR source_updated_at >= $1)"
		args = append(args, sourceUpdatedAfter.UTC())
	}
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*),
 COUNT(*) FILTER(WHERE status='new'),COUNT(*) FILTER(WHERE status='triaged'),
 COUNT(*) FILTER(WHERE status='false_positive'),COUNT(*) FILTER(WHERE status='resolved'),
 COUNT(*) FILTER(WHERE confidence='likely'),COUNT(*) FILTER(WHERE confidence='suspected')
 FROM github_leak_findings WHERE `+where, args...).Scan(&stats.Total, &stats.New, &stats.Triaged, &stats.FalsePositive, &stats.Resolved, &stats.Likely, &stats.Suspected)
	return stats, err
}

func (s *Store) KeywordState(ctx context.Context, keyword string) (KeywordState, error) {
	keyword, err := normalizeRuleQuery(keyword)
	if err != nil {
		return KeywordState{}, err
	}
	var state KeywordState
	err = s.db.QueryRowContext(ctx, `SELECT keyword,etag,last_attempt_at,last_success_at,last_status,last_error,incomplete,truncated,
	 freshness_policy,freshness_checked_at,freshness_cursor,freshness_cursor_etag,page_cursor FROM github_leak_keyword_state WHERE keyword=$1`, keyword).
		Scan(&state.Keyword, &state.ETag, &state.LastAttemptAt, &state.LastSuccessAt, &state.LastStatus, &state.LastError, &state.Incomplete, &state.Truncated,
			&state.FreshnessPolicy, &state.FreshnessCheckedAt, &state.FreshnessCursor, &state.FreshnessCursorETag, &state.PageCursor)
	if errors.Is(err, sql.ErrNoRows) {
		return KeywordState{Keyword: keyword}, nil
	}
	return state, err
}

func (s *Store) SaveKeywordState(ctx context.Context, state KeywordState) error {
	keyword, err := normalizeRuleQuery(state.Keyword)
	if err != nil {
		return err
	}
	state.LastError = safeError(state.LastError)
	incomplete := int64(0)
	if state.Incomplete {
		incomplete = 1
	}
	truncated := int64(0)
	if state.Truncated {
		truncated = 1
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO github_leak_keyword_state
 (keyword,etag,last_attempt_at,last_success_at,last_status,last_error,incomplete,truncated,
  freshness_policy,freshness_checked_at,freshness_cursor,freshness_cursor_etag,page_cursor,updated_at)
 VALUES($1,$2,$3,$4,$5,$6,($7::bigint <> 0),($8::bigint <> 0),$9,$10,$11,$12,$13,CURRENT_TIMESTAMP)
 ON CONFLICT(keyword) DO UPDATE SET etag=EXCLUDED.etag,last_attempt_at=EXCLUDED.last_attempt_at,
	last_success_at=EXCLUDED.last_success_at,last_status=EXCLUDED.last_status,last_error=EXCLUDED.last_error,
	incomplete=EXCLUDED.incomplete,truncated=EXCLUDED.truncated,freshness_policy=EXCLUDED.freshness_policy,
	freshness_checked_at=EXCLUDED.freshness_checked_at,freshness_cursor=EXCLUDED.freshness_cursor,
	freshness_cursor_etag=EXCLUDED.freshness_cursor_etag,page_cursor=EXCLUDED.page_cursor,updated_at=CURRENT_TIMESTAMP`,
		keyword, strings.TrimSpace(state.ETag), state.LastAttemptAt,
		state.LastSuccessAt, strings.TrimSpace(state.LastStatus), state.LastError, incomplete, truncated,
		strings.TrimSpace(state.FreshnessPolicy), state.FreshnessCheckedAt, state.FreshnessCursor, strings.TrimSpace(state.FreshnessCursorETag), state.PageCursor)
	return err
}

func (s *Store) BeginRun(ctx context.Context, at time.Time) (RunRecord, error) {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	// A process crash may leave a durable running marker; the advisory lock is
	// the authority, so a new lock owner may safely close those old rows.
	if _, err := s.db.ExecContext(ctx, `UPDATE github_leak_runs SET status='cancelled',error='previous run interrupted',finished_at=$1 WHERE status='running'`, at.UTC()); err != nil {
		log.Printf("[githubleak] 归档上次中断的 running 记录失败(锁语义不受影响): %v", err)
	}
	run := RunRecord{ID: uuid.NewString(), Status: "running", StartedAt: at.UTC(), RateRemaining: -1}
	_, err := s.db.ExecContext(ctx, `INSERT INTO github_leak_runs(id,status,error,started_at,rate_remaining,requests,processed,detected) VALUES($1,$2,'',$3,-1,0,0,0)`, run.ID, run.Status, run.StartedAt)
	return run, err
}

func (s *Store) FinishRun(ctx context.Context, run RunRecord) error {
	if run.ID == "" {
		return errors.New("run id is required")
	}
	switch run.Status {
	case "success", "partial", "error", "rate_limited", "cancelled":
	default:
		return errors.New("invalid run status")
	}
	finished := time.Now().UTC()
	if run.FinishedAt != nil {
		finished = run.FinishedAt.UTC()
	}
	_, err := s.db.ExecContext(ctx, `UPDATE github_leak_runs SET status=$2,error=$3,finished_at=$4,
 rate_remaining=$5,rate_reset_at=$6,requests=$7,processed=$8,detected=$9,
 filtered_fork=$10,filtered_noise=$11,filtered_suppressed=$12,filtered_boilerplate=$13 WHERE id=$1`, run.ID, run.Status,
		safeError(run.Error), finished, run.RateRemaining, run.RateResetAt, run.Requests, run.Processed, run.Detected,
		run.FilteredFork, run.FilteredNoise, run.FilteredSuppressed, run.FilteredBoilerplate)
	return err
}

// RulePrecision 规则精确率（运营视图）。
type RulePrecision struct {
	RuleName      string    `json:"rule_name"`
	Total         int       `json:"total"`
	Confirmed     int       `json:"confirmed"`
	FalsePositive int       `json:"false_positive"`
	Ignored       int       `json:"ignored"`
	Precision     float64   `json:"precision"`
	LastSeenAt    time.Time `json:"last_seen_at"`
}

func (s *Store) LatestRun(ctx context.Context) (RunRecord, error) {
	var run RunRecord
	err := s.db.QueryRowContext(ctx, `SELECT id,status,error,started_at,finished_at,rate_remaining,rate_reset_at,requests,processed,detected FROM github_leak_runs ORDER BY started_at DESC LIMIT 1`).
		Scan(&run.ID, &run.Status, &run.Error, &run.StartedAt, &run.FinishedAt, &run.RateRemaining, &run.RateResetAt, &run.Requests, &run.Processed, &run.Detected)
	if errors.Is(err, sql.ErrNoRows) {
		return RunRecord{RateRemaining: -1}, nil
	}
	return run, err
}

func safeError(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	// Provider errors are deliberately generic. Still remove controls and cap
	// storage so a future dependency cannot copy a response body into runtime.
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, value)
	value = maskOtherSecrets(value)
	value = strings.Join(strings.Fields(value), " ")
	if len(value) > 300 {
		value = value[:300]
	}
	return value
}

// PurgeExpiredFindings 清理处置完结且超过保留期的 findings（防表无限膨胀）。
// 只清 false_positive / resolved；new/triaged 与未处置的一律保留。
func (s *Store) PurgeExpiredFindings(ctx context.Context, retainDays int) (int64, error) {
	if retainDays <= 0 {
		return 0, nil
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -retainDays)
	res, err := s.db.ExecContext(ctx, `
		DELETE FROM github_leak_findings
		WHERE status IN ('false_positive','resolved')
		  AND COALESCE(last_seen_at, first_seen_at) < $1`, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// CleanupSample 清洗预览样例（不含任何凭据内容）。
type CleanupSample struct {
	Repository string `json:"repository"`
	Path       string `json:"path"`
	SecretType string `json:"secret_type"`
	Severity   string `json:"severity"`
	Status     string `json:"status"`
}

// CleanupReport 历史误报清洗报告。
type CleanupReport struct {
	Total    int             `json:"total"`
	Matched  int             `json:"matched"`
	Deleted  int             `json:"deleted"`
	ByStatus map[string]int  `json:"by_status,omitempty"`
	ByType   map[string]int  `json:"by_type,omitempty"`
	Samples  []CleanupSample `json:"samples,omitempty"`
}

// CleanupNoiseFindings 按检测层同源的噪声路径规则回溯清洗存量 findings。
// apply=false 仅返回报告；true 时删除命中条目（分批，单批 200）。
func (s *Store) CleanupNoiseFindings(ctx context.Context, apply bool) (CleanupReport, error) {
	report := CleanupReport{ByStatus: map[string]int{}, ByType: map[string]int{}}
	rows, err := s.db.QueryContext(ctx, `SELECT id, repository, path, secret_type, severity, status FROM github_leak_findings`)
	if err != nil {
		return report, err
	}
	ids := make([]string, 0, 64)
	for rows.Next() {
		var id, repo, path, secretType, severity, status string
		if err := rows.Scan(&id, &repo, &path, &secretType, &severity, &status); err != nil {
			continue
		}
		report.Total++
		if !IsNoisePath(path) {
			continue
		}
		report.Matched++
		report.ByStatus[status]++
		report.ByType[secretType]++
		if len(report.Samples) < 25 {
			report.Samples = append(report.Samples, CleanupSample{Repository: repo, Path: path, SecretType: secretType, Severity: severity, Status: status})
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return report, err
	}
	if !apply || len(ids) == 0 {
		return report, nil
	}
	for i := 0; i < len(ids); i += 200 {
		end := i + 200
		if end > len(ids) {
			end = len(ids)
		}
		batch := strings.Join(ids[i:end], ",")
		res, err := s.db.ExecContext(ctx, `DELETE FROM github_leak_findings WHERE id = ANY(string_to_array($1, ','))`, batch)
		if err != nil {
			return report, err
		}
		n, _ := res.RowsAffected()
		report.Deleted += int(n)
	}
	return report, nil
}
