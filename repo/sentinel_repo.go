package repo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CommitSentinel 域的数据访问层。表结构见 docs/sql/schema_sentinel.sql。
//
// 设计约束（v0.3 §4）：
//   - 本文件是该域唯一允许出现 SQL 的地方，service 层只调用这里的方法；
//   - 判定写库走 (commit_id, model) 唯一键 + ON CONFLICT DO NOTHING，天然「永不重判」；
//   - commit.diff 体积大，列表查询不 select，只有详情页取。

// GitRepo 是被监控的代码仓库。
type GitRepo struct {
	ID              string     `json:"id"`
	FullName        string     `json:"full_name"`
	CloneURL        string     `json:"clone_url"`
	DefaultBranch   string     `json:"default_branch"`
	Branch          string     `json:"branch"`
	IntervalMinutes int        `json:"interval_minutes"`
	Enabled         bool       `json:"enabled"`
	LastCheckedAt   *time.Time `json:"last_checked_at"`
	LastCommitSHA   string     `json:"last_commit_sha"`
	LastError       string     `json:"last_error"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// EffectiveBranch 返回实际采集分支；branch 为空时跟随默认分支。
func (g *GitRepo) EffectiveBranch() string {
	if g == nil {
		return ""
	}
	if strings.TrimSpace(g.Branch) != "" {
		return g.Branch
	}
	return g.DefaultBranch
}

// GitCommit 是一次提交及其清洗后的 patch。
type GitCommit struct {
	ID           int64     `json:"id"`
	RepoID       string    `json:"repo_id"`
	RepoFullName string    `json:"repo_full_name"`
	SHA          string    `json:"sha"`
	AuthorName   string    `json:"author_name"`
	AuthorEmail  string    `json:"author_email"`
	CommittedAt  time.Time `json:"committed_at"`
	Subject      string    `json:"subject"`
	Message      string    `json:"message"`
	FilesChanged int       `json:"files_changed"`
	Additions    int       `json:"additions"`
	Deletions    int       `json:"deletions"`
	Diff         string    `json:"diff,omitempty"`
	Status       string    `json:"status"`
	SkipReason   string    `json:"skip_reason"`
	CreatedAt    time.Time `json:"created_at"`
}

// CommitListItem 是提交列表行：不含 diff，附最新判定的摘要。
type CommitListItem struct {
	ID            int64     `json:"id"`
	RepoID        string    `json:"repo_id"`
	RepoFullName  string    `json:"repo_full_name"`
	SHA           string    `json:"sha"`
	Subject       string    `json:"subject"`
	AuthorName    string    `json:"author_name"`
	CommittedAt   time.Time `json:"committed_at"`
	FilesChanged  int       `json:"files_changed"`
	Additions     int       `json:"additions"`
	Deletions     int       `json:"deletions"`
	Status        string    `json:"status"`
	SkipReason    string    `json:"skip_reason"`
	Judged        bool      `json:"judged"`
	IsSecurityFix bool      `json:"is_security_fix"`
	VulnClass     string    `json:"vuln_class"`
	Severity      string    `json:"severity"`
	Confidence    float64   `json:"confidence"`
}

// CommitFilter 是提交列表的筛选条件，零值表示不限制。
type CommitFilter struct {
	RepoID          string
	SHA             string
	Status          string
	OnlySecurityFix bool
	Since           *time.Time
	Until           *time.Time
	Page            int
	Size            int
}

// CommitJudgment 是一次模型判定。同一 (commit, model) 只允许一条。
type CommitJudgment struct {
	ID               int64           `json:"id"`
	CommitID         int64           `json:"commit_id"`
	Model            string          `json:"model"`
	IsSecurityFix    bool            `json:"is_security_fix"`
	VulnClass        string          `json:"vuln_class"`
	Severity         string          `json:"severity"`
	Confidence       float64         `json:"confidence"`
	Title            string          `json:"title"`
	Reasoning        string          `json:"reasoning"`
	Evidence         json.RawMessage `json:"evidence"`
	Partial          bool            `json:"partial"`
	PromptTokens     int             `json:"prompt_tokens"`
	CompletionTokens int             `json:"completion_tokens"`
	CreatedAt        time.Time       `json:"created_at"`
}

// CommitFinding 是判定命中后落地的可验证发现。
type CommitFinding struct {
	ID         int64     `json:"id"`
	CommitID   int64     `json:"commit_id"`
	JudgmentID *int64    `json:"judgment_id"`
	VulnClass  string    `json:"vuln_class"`
	Severity   string    `json:"severity"`
	Status     string    `json:"status"`
	Title      string    `json:"title"`
	Detail     string    `json:"detail"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// Sentinel 是提交哨兵域的仓储入口。
type Sentinel struct{ r *Repo }

// Sentinel 返回提交哨兵仓储。
func (r *Repo) Sentinel() *Sentinel { return &Sentinel{r: r} }

func (s *Sentinel) pool() *pgxpool.Pool { return s.r.Pool() }

const sentinelRepoColumns = `id, full_name, clone_url, default_branch, branch,
	interval_minutes, enabled, last_checked_at, last_commit_sha, last_error, created_at, updated_at`

func scanGitRepo(row pgx.Row) (*GitRepo, error) {
	var g GitRepo
	err := row.Scan(&g.ID, &g.FullName, &g.CloneURL, &g.DefaultBranch, &g.Branch,
		&g.IntervalMinutes, &g.Enabled, &g.LastCheckedAt, &g.LastCommitSHA, &g.LastError,
		&g.CreatedAt, &g.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &g, nil
}

// CreateRepo 新增仓库；full_name 冲突返回 ErrDuplicate。
func (s *Sentinel) CreateRepo(ctx context.Context, g *GitRepo) error {
	_, err := s.pool().Exec(ctx, `
		insert into repo (id, full_name, clone_url, default_branch, branch,
		                  interval_minutes, enabled, last_commit_sha)
		values ($1,$2,$3,$4,$5,$6,$7,$8)`,
		g.ID, g.FullName, g.CloneURL, g.DefaultBranch, g.Branch,
		g.IntervalMinutes, g.Enabled, g.LastCommitSHA)
	if err != nil && isUniqueViolation(err) {
		return ErrDuplicate
	}
	return err
}

// sentinelRepoUpdatable 是允许更新的列白名单，禁止把调用方 map 直接拼进 SQL。
var sentinelRepoUpdatable = map[string]string{
	"full_name":        "full_name",
	"clone_url":        "clone_url",
	"default_branch":   "default_branch",
	"branch":           "branch",
	"interval_minutes": "interval_minutes",
	"enabled":          "enabled",
	"last_commit_sha":  "last_commit_sha",
	"last_error":       "last_error",
}

// UpdateRepo 按白名单更新仓库字段，并刷新 updated_at。
func (s *Sentinel) UpdateRepo(ctx context.Context, id string, fields map[string]interface{}) error {
	sets := make([]string, 0, len(fields)+1)
	args := make([]interface{}, 0, len(fields)+2)
	for key, val := range fields {
		col, ok := sentinelRepoUpdatable[key]
		if !ok {
			return fmt.Errorf("仓库字段不可更新: %s", key)
		}
		args = append(args, val)
		sets = append(sets, fmt.Sprintf("%s = $%d", col, len(args)))
	}
	if len(sets) == 0 {
		return nil
	}
	sets = append(sets, "updated_at = now()")
	args = append(args, id)

	tag, err := s.pool().Exec(ctx,
		fmt.Sprintf("update repo set %s where id = $%d", strings.Join(sets, ", "), len(args)), args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteRepo 删除仓库；commit 等子表由外键级联清理。
func (s *Sentinel) DeleteRepo(ctx context.Context, id string) error {
	tag, err := s.pool().Exec(ctx, `delete from repo where id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// GetRepo 按 id 读取仓库。
func (s *Sentinel) GetRepo(ctx context.Context, id string) (*GitRepo, error) {
	return scanGitRepo(s.pool().QueryRow(ctx,
		`select `+sentinelRepoColumns+` from repo where id = $1`, id))
}

// GetRepoByFullName 按 owner/name 读取仓库。
func (s *Sentinel) GetRepoByFullName(ctx context.Context, fullName string) (*GitRepo, error) {
	return scanGitRepo(s.pool().QueryRow(ctx,
		`select `+sentinelRepoColumns+` from repo where full_name = $1`, fullName))
}

// ListRepos 列出全部仓库（含停用的，前端需要显示开关状态）。
func (s *Sentinel) ListRepos(ctx context.Context, keyword string) ([]*GitRepo, error) {
	rows, err := s.pool().Query(ctx, `
		select `+sentinelRepoColumns+`
		  from repo
		 where ($1 = '' or full_name ilike '%' || $1 || '%')
		 order by enabled desc, full_name asc`, keyword)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]*GitRepo, 0, 16)
	for rows.Next() {
		g, err := scanGitRepo(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, g)
	}
	return items, rows.Err()
}

// ListDueRepos 取到点需要采集的仓库（按最久未检查优先）。
func (s *Sentinel) ListDueRepos(ctx context.Context, limit int) ([]*GitRepo, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := s.pool().Query(ctx, `
		select `+sentinelRepoColumns+`
		  from repo
		 where enabled
		   and (last_checked_at is null
		        or last_checked_at < now() - make_interval(mins => interval_minutes))
		 order by last_checked_at asc nulls first
		 limit $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]*GitRepo, 0, limit)
	for rows.Next() {
		g, err := scanGitRepo(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, g)
	}
	return items, rows.Err()
}

// MarkRepoChecked 记录一次采集结果（成功时 errMsg 传空串）。
func (s *Sentinel) MarkRepoChecked(ctx context.Context, id, lastSHA, errMsg string) error {
	_, err := s.pool().Exec(ctx, `
		update repo
		   set last_checked_at = now(),
		       last_commit_sha = case when $2 = '' then last_commit_sha else $2 end,
		       last_error = $3,
		       updated_at = now()
		 where id = $1`, id, lastSHA, errMsg)
	return err
}

// InsertCommit 写入一条提交；已存在（同 repo+sha）时返回 inserted=false。
func (s *Sentinel) InsertCommit(ctx context.Context, c *GitCommit) (int64, bool, error) {
	var id int64
	err := s.pool().QueryRow(ctx, `
		insert into commit (repo_id, sha, author_name, author_email, committed_at,
		                    subject, message, files_changed, additions, deletions, diff, status)
		values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'pending')
		on conflict (repo_id, sha) do nothing
		returning id`,
		c.RepoID, c.SHA, c.AuthorName, c.AuthorEmail, c.CommittedAt,
		c.Subject, c.Message, c.FilesChanged, c.Additions, c.Deletions, c.Diff,
	).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return id, true, nil
}

// GetCommit 读取提交详情（含 diff）。
func (s *Sentinel) GetCommit(ctx context.Context, id int64) (*GitCommit, error) {
	var c GitCommit
	err := s.pool().QueryRow(ctx, `
		select c.id, c.repo_id, coalesce(r.full_name, ''), c.sha, c.author_name, c.author_email,
		       c.committed_at, c.subject, c.message, c.files_changed, c.additions, c.deletions,
		       c.diff, c.status, c.skip_reason, c.created_at
		  from commit c
		  left join repo r on r.id = c.repo_id
		 where c.id = $1`, id).Scan(
		&c.ID, &c.RepoID, &c.RepoFullName, &c.SHA, &c.AuthorName, &c.AuthorEmail,
		&c.CommittedAt, &c.Subject, &c.Message, &c.FilesChanged, &c.Additions, &c.Deletions,
		&c.Diff, &c.Status, &c.SkipReason, &c.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// GetCommitBySHA 按仓库 + sha 读取提交。
func (s *Sentinel) GetCommitBySHA(ctx context.Context, repoID, sha string) (*GitCommit, error) {
	var id int64
	err := s.pool().QueryRow(ctx,
		`select id from commit where repo_id = $1 and sha = $2`, repoID, sha).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return s.GetCommit(ctx, id)
}

// buildCommitWhere 生成提交列表的 where 子句与参数（$n 从 1 开始）。
func buildCommitWhere(f CommitFilter) (string, []interface{}) {
	conds := make([]string, 0, 6)
	args := make([]interface{}, 0, 6)

	if f.RepoID != "" {
		args = append(args, f.RepoID)
		conds = append(conds, fmt.Sprintf("c.repo_id = $%d", len(args)))
	}
	if f.SHA != "" {
		args = append(args, strings.ToLower(f.SHA)+"%")
		conds = append(conds, fmt.Sprintf("c.sha like $%d", len(args)))
	}
	if f.Status != "" {
		args = append(args, f.Status)
		conds = append(conds, fmt.Sprintf("c.status = $%d", len(args)))
	}
	if f.Since != nil {
		args = append(args, *f.Since)
		conds = append(conds, fmt.Sprintf("c.committed_at >= $%d", len(args)))
	}
	if f.Until != nil {
		args = append(args, *f.Until)
		conds = append(conds, fmt.Sprintf("c.committed_at < $%d", len(args)))
	}
	if f.OnlySecurityFix {
		conds = append(conds, "coalesce(j.is_security_fix, false)")
	}
	if len(conds) == 0 {
		return "", args
	}
	return " where " + strings.Join(conds, " and "), args
}

// latestJudgmentJoin 取每条提交 id 最大的判定作为列表摘要。
const latestJudgmentJoin = `
	left join lateral (
		select is_security_fix, vuln_class, severity, confidence
		  from judgment
		 where commit_id = c.id
		 order by id desc
		 limit 1
	) j on true`

// ListCommits 分页查询提交（不含 diff），返回行与总数。
func (s *Sentinel) ListCommits(ctx context.Context, f CommitFilter) ([]*CommitListItem, int64, error) {
	if f.Size <= 0 || f.Size > 200 {
		f.Size = 20
	}
	if f.Page <= 0 {
		f.Page = 1
	}
	where, args := buildCommitWhere(f)

	var total int64
	countSQL := `select count(*) from commit c ` + latestJudgmentJoin + where
	if err := s.pool().QueryRow(ctx, countSQL, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	args = append(args, f.Size, (f.Page-1)*f.Size)
	listSQL := `
		select c.id, c.repo_id, coalesce(r.full_name, ''), c.sha, c.subject, c.author_name,
		       c.committed_at, c.files_changed, c.additions, c.deletions, c.status, c.skip_reason,
		       (j.is_security_fix is not null) as judged,
		       coalesce(j.is_security_fix, false), coalesce(j.vuln_class, ''),
		       coalesce(j.severity, ''), coalesce(j.confidence, 0)::float8
		  from commit c
		  left join repo r on r.id = c.repo_id` + latestJudgmentJoin + where +
		fmt.Sprintf(" order by c.committed_at desc, c.id desc limit $%d offset $%d", len(args)-1, len(args))

	rows, err := s.pool().Query(ctx, listSQL, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	items := make([]*CommitListItem, 0, f.Size)
	for rows.Next() {
		var it CommitListItem
		if err := rows.Scan(&it.ID, &it.RepoID, &it.RepoFullName, &it.SHA, &it.Subject, &it.AuthorName,
			&it.CommittedAt, &it.FilesChanged, &it.Additions, &it.Deletions, &it.Status, &it.SkipReason,
			&it.Judged, &it.IsSecurityFix, &it.VulnClass, &it.Severity, &it.Confidence); err != nil {
			return nil, 0, err
		}
		items = append(items, &it)
	}
	return items, total, rows.Err()
}

// ListPendingCommits 取待判定提交（采集完成后投喂 judge 队列）。
func (s *Sentinel) ListPendingCommits(ctx context.Context, repoID string, limit int) ([]*GitCommit, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.pool().Query(ctx, `
		select c.id, c.repo_id, c.sha, c.committed_at, c.subject, c.diff, c.status
		  from commit c
		 where c.status = 'pending'
		   and ($1 = '' or c.repo_id = $1)
		 order by c.committed_at desc, c.id desc
		 limit $2`, repoID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]*GitCommit, 0, limit)
	for rows.Next() {
		var c GitCommit
		if err := rows.Scan(&c.ID, &c.RepoID, &c.SHA, &c.CommittedAt, &c.Subject, &c.Diff, &c.Status); err != nil {
			return nil, err
		}
		items = append(items, &c)
	}
	return items, rows.Err()
}

// MarkCommitStatus 更新提交处理状态（pending/skipped/judged/failed）。
func (s *Sentinel) MarkCommitStatus(ctx context.Context, id int64, status, reason string) error {
	_, err := s.pool().Exec(ctx,
		`update commit set status = $2, skip_reason = $3 where id = $1`, id, status, reason)
	return err
}

// InsertJudgment 写入判定；(commit_id, model) 已存在时 inserted=false，实现永不重判。
func (s *Sentinel) InsertJudgment(ctx context.Context, j *CommitJudgment) (int64, bool, error) {
	evidence := j.Evidence
	if len(evidence) == 0 {
		evidence = json.RawMessage("[]")
	}
	var id int64
	err := s.pool().QueryRow(ctx, `
		insert into judgment (commit_id, model, is_security_fix, vuln_class, severity, confidence,
		                      title, reasoning, evidence, partial, prompt_tokens, completion_tokens)
		values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		on conflict (commit_id, model) do nothing
		returning id`,
		j.CommitID, j.Model, j.IsSecurityFix, j.VulnClass, j.Severity, j.Confidence,
		j.Title, j.Reasoning, evidence, j.Partial, j.PromptTokens, j.CompletionTokens,
	).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return id, true, nil
}

const judgmentColumns = `id, commit_id, model, is_security_fix, vuln_class, severity,
	confidence::float8, title, reasoning, evidence, partial, prompt_tokens, completion_tokens, created_at`

func scanJudgment(row pgx.Row) (*CommitJudgment, error) {
	var j CommitJudgment
	err := row.Scan(&j.ID, &j.CommitID, &j.Model, &j.IsSecurityFix, &j.VulnClass, &j.Severity,
		&j.Confidence, &j.Title, &j.Reasoning, &j.Evidence, &j.Partial,
		&j.PromptTokens, &j.CompletionTokens, &j.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &j, nil
}

// GetJudgment 取某条提交的判定（任取一条，按 id 倒序）。
func (s *Sentinel) GetJudgment(ctx context.Context, commitID int64) (*CommitJudgment, error) {
	return scanJudgment(s.pool().QueryRow(ctx,
		`select `+judgmentColumns+` from judgment where commit_id = $1 order by id desc limit 1`, commitID))
}

// LatestJudgments 取最近判定（总览页）。
func (s *Sentinel) LatestJudgments(ctx context.Context, limit int) ([]*CommitJudgment, error) {
	if limit <= 0 || limit > 50 {
		limit = 10
	}
	rows, err := s.pool().Query(ctx,
		`select `+judgmentColumns+` from judgment order by id desc limit $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]*CommitJudgment, 0, limit)
	for rows.Next() {
		j, err := scanJudgment(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, j)
	}
	return items, rows.Err()
}

// CreateFinding 记录一条发现。
func (s *Sentinel) CreateFinding(ctx context.Context, f *CommitFinding) (int64, error) {
	var id int64
	err := s.pool().QueryRow(ctx, `
		insert into finding (commit_id, judgment_id, vuln_class, severity, status, title, detail)
		values ($1,$2,$3,$4,coalesce(nullif($5,''),'open'),$6,$7)
		returning id`,
		f.CommitID, f.JudgmentID, f.VulnClass, f.Severity, f.Status, f.Title, f.Detail).Scan(&id)
	return id, err
}

// ListFindingsByCommit 列出某提交下的发现。
func (s *Sentinel) ListFindingsByCommit(ctx context.Context, commitID int64) ([]*CommitFinding, error) {
	rows, err := s.pool().Query(ctx, `
		select id, commit_id, judgment_id, vuln_class, severity, status, title, detail, created_at, updated_at
		  from finding where commit_id = $1 order by id desc`, commitID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]*CommitFinding, 0, 4)
	for rows.Next() {
		var f CommitFinding
		if err := rows.Scan(&f.ID, &f.CommitID, &f.JudgmentID, &f.VulnClass, &f.Severity,
			&f.Status, &f.Title, &f.Detail, &f.CreatedAt, &f.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, &f)
	}
	return items, rows.Err()
}

// FindingFilter 是发现列表（跨仓库）的筛选条件，零值表示不限制。
type FindingFilter struct {
	Status   string
	Severity string
	RepoID   string
	Page     int
	Size     int
}

// FindingListItem 是发现列表行：带上来源提交与仓库，便于从产物回溯到改动。
type FindingListItem struct {
	CommitFinding
	RepoID       string    `json:"repo_id"`
	RepoFullName string    `json:"repo_full_name"`
	SHA          string    `json:"sha"`
	Subject      string    `json:"subject"`
	CommittedAt  time.Time `json:"committed_at"`
	Model        string    `json:"model"`
}

// ListFindings 分页查询全部发现，返回行与总数。
func (s *Sentinel) ListFindings(ctx context.Context, f FindingFilter) ([]*FindingListItem, int64, error) {
	if f.Size <= 0 || f.Size > 200 {
		f.Size = 20
	}
	if f.Page <= 0 {
		f.Page = 1
	}

	conds := make([]string, 0, 3)
	args := make([]interface{}, 0, 5)
	if f.Status != "" {
		args = append(args, f.Status)
		conds = append(conds, fmt.Sprintf("f.status = $%d", len(args)))
	}
	if f.Severity != "" {
		args = append(args, f.Severity)
		conds = append(conds, fmt.Sprintf("f.severity = $%d", len(args)))
	}
	if f.RepoID != "" {
		args = append(args, f.RepoID)
		conds = append(conds, fmt.Sprintf("c.repo_id = $%d", len(args)))
	}
	where := ""
	if len(conds) > 0 {
		where = " where " + strings.Join(conds, " and ")
	}

	var total int64
	if err := s.pool().QueryRow(ctx,
		`select count(*) from finding f join commit c on c.id = f.commit_id`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	args = append(args, f.Size, (f.Page-1)*f.Size)
	rows, err := s.pool().Query(ctx, `
		select f.id, f.commit_id, f.judgment_id, f.vuln_class, f.severity, f.status,
		       f.title, f.detail, f.created_at, f.updated_at,
		       c.repo_id, coalesce(r.full_name, ''), c.sha, c.subject, c.committed_at,
		       coalesce(j.model, '')
		  from finding f
		  join commit c on c.id = f.commit_id
		  left join repo r on r.id = c.repo_id
		  left join judgment j on j.id = f.judgment_id`+where+`
		 order by f.created_at desc, f.id desc`+
		fmt.Sprintf(" limit $%d offset $%d", len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	items := make([]*FindingListItem, 0, f.Size)
	for rows.Next() {
		var it FindingListItem
		if err := rows.Scan(&it.ID, &it.CommitID, &it.JudgmentID, &it.VulnClass, &it.Severity, &it.Status,
			&it.Title, &it.Detail, &it.CreatedAt, &it.UpdatedAt,
			&it.RepoID, &it.RepoFullName, &it.SHA, &it.Subject, &it.CommittedAt, &it.Model); err != nil {
			return nil, 0, err
		}
		items = append(items, &it)
	}
	return items, total, rows.Err()
}


