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
	Score        int       `json:"score"`
	SkipReason   string    `json:"skip_reason"`
	// 判定失败状态机：attempts 用于上限，next_judge_at 用于退避，
	// last_judge_error 保留最近一次原因供排查。
	JudgeAttempts  int        `json:"judge_attempts"`
	NextJudgeAt    *time.Time `json:"next_judge_at,omitempty"`
	LastJudgeError string     `json:"last_judge_error,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

// CommitListItem 是提交列表行：不含 diff，附最新判定的摘要。
type CommitListItem struct {
	ID            int64     `json:"id"`
	Grade         string    `json:"grade"`
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
// VulnClasses 走「扩展口径」：传 SQLI/CMDI 会自动连带历史数据里的 INJECTION。
type CommitFilter struct {
	RepoID          string
	SHA             string
	Status          string
	OnlySecurityFix bool
	VulnClasses     []string
	MinSeverity     string // info/low/medium/high/critical，语义为「不低于」
	Since           *time.Time
	Until           *time.Time
	Page            int
	Size            int
}

// CommitJudgment 是一次模型判定。同一 (commit, model) 只允许一条。
type CommitJudgment struct {
	ID            int64           `json:"id"`
	CommitID      int64           `json:"commit_id"`
	Model         string          `json:"model"`
	IsSecurityFix bool            `json:"is_security_fix"`
	VulnClass     string          `json:"vuln_class"`
	Severity      string          `json:"severity"`
	Confidence    float64         `json:"confidence"`
	Title         string          `json:"title"`
	Reasoning     string          `json:"reasoning"`
	Evidence      json.RawMessage `json:"evidence"`
	// 命中安全修复时展开的三段式说明与摘录片段（migration_sentinel_judge_detail.sql），
	// 旧判定记录为空值，前端需做空值兼容。
	AttackPath       string          `json:"attack_path"`
	Impact           string          `json:"impact"`
	FixEvidence      string          `json:"fix_evidence"`
	Snippets         json.RawMessage `json:"evidence_snippets"`
	Partial          bool            `json:"partial"`
	PromptTokens     int             `json:"prompt_tokens"`
	CompletionTokens int             `json:"completion_tokens"`
	CreatedAt        time.Time       `json:"created_at"`
}

// CommitFinding 是判定命中后落地的可验证发现。
type CommitFinding struct {
	ID         int64      `json:"id"`
	CommitID   int64      `json:"commit_id"`
	JudgmentID *int64     `json:"judgment_id"`
	VulnClass  string     `json:"vuln_class"`
	Severity   string     `json:"severity"`
	Status     string     `json:"status"`
	Title      string     `json:"title"`
	Detail     string     `json:"detail"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	VerifiedAt *time.Time `json:"verified_at"`
	VerifiedBy string     `json:"verified_by"`
	Grade      string     `json:"grade"`
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
		                    subject, message, files_changed, additions, deletions, diff, score, status)
		values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'pending')
		on conflict (repo_id, sha) do nothing
		returning id`,
		c.RepoID, c.SHA, c.AuthorName, c.AuthorEmail, c.CommittedAt,
		c.Subject, c.Message, c.FilesChanged, c.Additions, c.Deletions, c.Diff, c.Score,
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
// VulnClasses/MinSeverity 条件作用在 lateral join 出的判定摘要 j 上。
func buildCommitWhere(f CommitFilter) (string, []interface{}) {
	conds := make([]string, 0, 8)
	args := make([]interface{}, 0, 8)

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
	if len(f.VulnClasses) > 0 {
		args = append(args, ExpandVulnClasses(f.VulnClasses))
		conds = append(conds, fmt.Sprintf("coalesce(j.vuln_class, '') = any($%d)", len(args)))
	}
	if min := severityFloor(f.MinSeverity); len(min) > 0 {
		args = append(args, min)
		conds = append(conds, fmt.Sprintf("coalesce(j.severity, '') = any($%d)", len(args)))
	}
	if len(conds) == 0 {
		return "", args
	}
	return " where " + strings.Join(conds, " and "), args
}

// ExpandVulnClasses 把筛选口径扩展成实际查询口径：
// SQLI/CMDI 历史上落在 INJECTION 桶里，选中时自动连带，避免老数据查不到。
// 返回值已去重、归一为大写。
func ExpandVulnClasses(classes []string) []string {
	seen := make(map[string]bool, len(classes)+2)
	out := make([]string, 0, len(classes)+2)
	add := func(v string) {
		v = strings.ToUpper(strings.TrimSpace(v))
		if v == "" || seen[v] {
			return
		}
		seen[v] = true
		out = append(out, v)
	}
	for _, c := range classes {
		add(c)
		switch strings.ToUpper(strings.TrimSpace(c)) {
		case "SQLI", "CMDI":
			add("INJECTION")
		}
	}
	return out
}

// severityFloor 把「不低于 X」翻译成允许的 severity 集合；非法值返回 nil（不过滤）。
func severityFloor(min string) []string {
	rank := map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
	r, ok := rank[strings.ToLower(strings.TrimSpace(min))]
	if !ok {
		return nil
	}
	byRank := []string{"info", "low", "medium", "high", "critical"}
	return byRank[r:]
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
		select c.id, c.repo_id, c.sha, c.committed_at, c.subject, c.diff, c.status,
		       c.judge_attempts, c.next_judge_at, c.last_judge_error
		  from commit c
		 where c.judge_attempts < 5
		   and (c.status = 'pending' or (c.status = 'failed' and c.next_judge_at is not null))
		   and (c.next_judge_at is null or c.next_judge_at <= now())
		   and ($1 = '' or c.repo_id = $1)
		 order by c.score desc, c.committed_at desc, c.id desc
		 limit $2`, repoID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]*GitCommit, 0, limit)
	for rows.Next() {
		var c GitCommit
		if err := rows.Scan(&c.ID, &c.RepoID, &c.SHA, &c.CommittedAt, &c.Subject, &c.Diff, &c.Status,
			&c.JudgeAttempts, &c.NextJudgeAt, &c.LastJudgeError); err != nil {
			return nil, err
		}
		items = append(items, &c)
	}
	return items, rows.Err()
}

// MarkCommitStatus 更新提交处理状态（pending/skipped/judged/failed）。
func (s *Sentinel) MarkCommitStatus(ctx context.Context, id int64, status, reason string) error {
	_, err := s.pool().Exec(ctx,
		`update commit
		    set status = $2, skip_reason = $3,
		        next_judge_at = null, last_judge_error = ''
		  where id = $1`, id, status, reason)
	return err
}

// MarkCommitJudgeRetry 记录一次可重试失败：attempts+1，按 backoff 设置下次时间；
// 达到上限时置 failed 且清空 next_judge_at（不再被调度器捡起）。
// 返回是否已耗尽。
func (s *Sentinel) MarkCommitJudgeRetry(ctx context.Context, id int64, errMsg string, maxAttempts int, backoff time.Duration) (bool, error) {
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	secs := int(backoff.Seconds())
	if secs <= 0 {
		secs = 30
	}
	var attempts int
	err := s.pool().QueryRow(ctx, `
		update commit
		   set judge_attempts = judge_attempts + 1,
		       last_judge_error = $2,
		       next_judge_at = case when judge_attempts + 1 >= $3 then null
		                            else now() + ($4::int * interval '1 second') end,
		       status = case when judge_attempts + 1 >= $3 then 'failed' else 'pending' end
		 where id = $1
		 returning judge_attempts`, id, errMsg, maxAttempts, secs).Scan(&attempts)
	return attempts >= maxAttempts, err
}

// MarkCommitJudgeTerminal 标记永久失败：不再自动重投，保留错误供人工处理。
func (s *Sentinel) MarkCommitJudgeTerminal(ctx context.Context, id int64, errMsg string) error {
	_, err := s.pool().Exec(ctx,
		`update commit
		    set status = 'failed', last_judge_error = $2, next_judge_at = null
		  where id = $1`, id, errMsg)
	return err
}

// InsertJudgment 写入判定；(commit_id, model) 已存在时 inserted=false，实现永不重判。
func (s *Sentinel) InsertJudgment(ctx context.Context, j *CommitJudgment) (int64, bool, error) {
	evidence := j.Evidence
	if len(evidence) == 0 {
		evidence = json.RawMessage("[]")
	}
	snippets := j.Snippets
	if len(snippets) == 0 {
		snippets = json.RawMessage("[]")
	}
	var id int64
	err := s.pool().QueryRow(ctx, `
		insert into judgment (commit_id, model, is_security_fix, vuln_class, severity, confidence,
		                      title, reasoning, evidence, attack_path, impact, fix_evidence,
		                      evidence_snippets, partial, prompt_tokens, completion_tokens)
		values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
		on conflict (commit_id, model) do nothing
		returning id`,
		j.CommitID, j.Model, j.IsSecurityFix, j.VulnClass, j.Severity, j.Confidence,
		j.Title, j.Reasoning, evidence, j.AttackPath, j.Impact, j.FixEvidence,
		snippets, j.Partial, j.PromptTokens, j.CompletionTokens,
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
	confidence::float8, title, reasoning, evidence, attack_path, impact, fix_evidence,
	evidence_snippets, partial, prompt_tokens, completion_tokens, created_at`

func scanJudgment(row pgx.Row) (*CommitJudgment, error) {
	var j CommitJudgment
	err := row.Scan(&j.ID, &j.CommitID, &j.Model, &j.IsSecurityFix, &j.VulnClass, &j.Severity,
		&j.Confidence, &j.Title, &j.Reasoning, &j.Evidence, &j.AttackPath, &j.Impact,
		&j.FixEvidence, &j.Snippets, &j.Partial,
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

// GetJudgmentByModel 取某条提交在指定模型名下的判定。
// 判定以 (commit_id, model) 幂等，内部 judge 与外部 agent 提交（model=agent:*）互为独立判定，
// 「已判定过」的判断必须按模型维度做，否则外部判定会挡住内部重判路径。
func (s *Sentinel) GetJudgmentByModel(ctx context.Context, commitID int64, model string) (*CommitJudgment, error) {
	return scanJudgment(s.pool().QueryRow(ctx,
		`select `+judgmentColumns+` from judgment where commit_id = $1 and model = $2 limit 1`, commitID, model))
}

// ListJudgmentsByCommit 列出某条提交的全部判定（内部模型与外部 agent 并列），按 id 倒序。
func (s *Sentinel) ListJudgmentsByCommit(ctx context.Context, commitID int64) ([]*CommitJudgment, error) {
	rows, err := s.pool().Query(ctx,
		`select `+judgmentColumns+` from judgment where commit_id = $1 order by id desc`, commitID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]*CommitJudgment, 0, 2)
	for rows.Next() {
		j, err := scanJudgment(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, j)
	}
	return items, rows.Err()
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
		insert into finding (commit_id, judgment_id, vuln_class, severity, status, title, detail, grade)
		values ($1,$2,$3,$4,coalesce(nullif($5,''),'open'),$6,$7,$8)
		returning id`,
		f.CommitID, f.JudgmentID, f.VulnClass, f.Severity, f.Status, f.Title, f.Detail, f.Grade).Scan(&id)
	return id, err
}

// ListFindingsByCommit 列出某提交下的发现。
func (s *Sentinel) ListFindingsByCommit(ctx context.Context, commitID int64) ([]*CommitFinding, error) {
	rows, err := s.pool().Query(ctx, `
		select id, commit_id, judgment_id, vuln_class, severity, status, title, detail, created_at, updated_at, verified_at, verified_by, grade
		  from finding where commit_id = $1 order by id desc`, commitID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]*CommitFinding, 0, 4)
	for rows.Next() {
		var f CommitFinding
		if err := rows.Scan(&f.ID, &f.CommitID, &f.JudgmentID, &f.VulnClass, &f.Severity,
			&f.Status, &f.Title, &f.Detail, &f.CreatedAt, &f.UpdatedAt, &f.VerifiedAt, &f.VerifiedBy, &f.Grade); err != nil {
			return nil, err
		}
		items = append(items, &f)
	}
	return items, rows.Err()
}

// FindingFilter 是发现列表（跨仓库）的筛选条件，零值表示不限制。
// VulnClasses 走「扩展口径」（见 ExpandVulnClasses）；MinSeverity 语义为「不低于」。
type FindingFilter struct {
	Status      string
	Severity    string
	VulnClasses []string
	MinSeverity string
	RepoID      string
	// Verified 按机器验证过滤："true"=已验证（verified_at 非空），"false"=未验证，空=不过滤。
	Verified string
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
	// Artifacts 是该发现的产物摘要（高危工作台列表列用）：
	// 只带 id/kind/title/status，不带 content。可能为空。
	Artifacts []FindingArtifactSummary `json:"artifacts,omitempty"`
}

// FindingArtifactSummary 是产物在列表里的精简形态。
type FindingArtifactSummary struct {
	ID     int64  `json:"id"`
	Kind   string `json:"kind"`
	Title  string `json:"title"`
	Status string `json:"status"`
}

// listFindingArtifactSummaries 批量取发现的产物摘要，按 finding_id 分组返回。
func (s *Sentinel) listFindingArtifactSummaries(ctx context.Context, findingIDs []int64) (map[int64][]FindingArtifactSummary, error) {
	out := make(map[int64][]FindingArtifactSummary, len(findingIDs))
	if len(findingIDs) == 0 {
		return out, nil
	}
	rows, err := s.pool().Query(ctx, `
		select id, finding_id, kind, title, status
		  from artifact
		 where finding_id = any($1)
		 order by id`, findingIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var a FindingArtifactSummary
		var fid int64
		if err := rows.Scan(&a.ID, &fid, &a.Kind, &a.Title, &a.Status); err != nil {
			return nil, err
		}
		out[fid] = append(out[fid], a)
	}
	return out, rows.Err()
}

// ListFindings 分页查询全部发现，返回行与总数。
func (s *Sentinel) ListFindings(ctx context.Context, f FindingFilter) ([]*FindingListItem, int64, error) {
	if f.Size <= 0 || f.Size > 200 {
		f.Size = 20
	}
	if f.Page <= 0 {
		f.Page = 1
	}

	conds := make([]string, 0, 5)
	args := make([]interface{}, 0, 5)
	if f.Status != "" {
		args = append(args, f.Status)
		conds = append(conds, fmt.Sprintf("f.status = $%d", len(args)))
	}
	if f.Severity != "" {
		args = append(args, f.Severity)
		conds = append(conds, fmt.Sprintf("f.severity = $%d", len(args)))
	}
	if len(f.VulnClasses) > 0 {
		args = append(args, ExpandVulnClasses(f.VulnClasses))
		conds = append(conds, fmt.Sprintf("f.vuln_class = any($%d)", len(args)))
	}
	if min := severityFloor(f.MinSeverity); len(min) > 0 {
		args = append(args, min)
		conds = append(conds, fmt.Sprintf("f.severity = any($%d)", len(args)))
	}
	if f.RepoID != "" {
		args = append(args, f.RepoID)
		conds = append(conds, fmt.Sprintf("c.repo_id = $%d", len(args)))
	}
	if f.Verified == "true" {
		conds = append(conds, "f.verified_at is not null")
	} else if f.Verified == "false" {
		conds = append(conds, "f.verified_at is null")
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
		       f.title, f.detail, f.created_at, f.updated_at, f.grade, f.verified_at,
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
			&it.Title, &it.Detail, &it.CreatedAt, &it.UpdatedAt, &it.Grade, &it.VerifiedAt,
			&it.RepoID, &it.RepoFullName, &it.SHA, &it.Subject, &it.CommittedAt, &it.Model); err != nil {
			return nil, 0, err
		}
		items = append(items, &it)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	// 批量补产物摘要（高危工作台的「验证产物」列）：一次 any 查询，不逐行回表。
	ids := make([]int64, 0, len(items))
	for _, it := range items {
		ids = append(ids, it.ID)
	}
	arts, err := s.listFindingArtifactSummaries(ctx, ids)
	if err != nil {
		return nil, 0, err
	}
	for _, it := range items {
		it.Artifacts = arts[it.ID]
	}
	return items, total, nil
}

// FindingRef 是回填用的发现最小引用。
type FindingRef struct {
	FindingID int64
	CommitID  int64
}

// ListHighRiskFindingsMissingArtifacts 取高危且从未生成过深审产物的发现（存量回填用）。
// 「缺产物」= 不存在 kind=report、title=deep-analysis 的任何状态产物。
func (s *Sentinel) ListHighRiskFindingsMissingArtifacts(ctx context.Context, limit int) ([]*FindingRef, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := s.pool().Query(ctx, `
		select f.id, f.commit_id
		  from finding f
		 where f.severity in ('high', 'critical')
		   and not exists (
		       select 1 from artifact a
		        where a.finding_id = f.id and a.kind = 'report' and a.title = 'deep-analysis')
		 order by f.id
		 limit $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	refs := make([]*FindingRef, 0, limit)
	for rows.Next() {
		var r FindingRef
		if err := rows.Scan(&r.FindingID, &r.CommitID); err != nil {
			return nil, err
		}
		refs = append(refs, &r)
	}
	return refs, rows.Err()
}

// FindingsSummary 是发现域统计（高危漏洞工作台首页卡片）。
type FindingsSummary struct {
	HighRisk   int64 `json:"high_risk"`   // severity in (high, critical)
	Verified   int64 `json:"verified"`    // 其中已机器验证（verified_at 非空）
	Confirmed  int64 `json:"confirmed"`   // 其中人工 confirmed
	PendingPoc int64 `json:"pending_poc"` // 其中尚未机器验证（待靶场验证/差分复现）
}

// SummarizeFindings 统计高危发现的验证完成度。单条聚合查询，无分页。
func (s *Sentinel) SummarizeFindings(ctx context.Context) (*FindingsSummary, error) {
	var sum FindingsSummary
	err := s.pool().QueryRow(ctx, `
		select
			count(*) filter (where f.severity in ('high', 'critical')),
			count(*) filter (where f.severity in ('high', 'critical') and f.verified_at is not null),
			count(*) filter (where f.severity in ('high', 'critical') and f.status = 'confirmed'),
			count(*) filter (where f.severity in ('high', 'critical') and f.verified_at is null)
		  from finding f`).Scan(&sum.HighRisk, &sum.Verified, &sum.Confirmed, &sum.PendingPoc)
	if err != nil {
		return nil, err
	}
	return &sum, nil
}

// ListPocVerifyEvents 取某发现最近的靶场验证事件（时间线数据源）。
// payload 里带 finding_id（service 层写入），按 id 倒序取回后由调用方按 run 分组。
func (s *Sentinel) ListPocVerifyEvents(ctx context.Context, findingID int64, limit int) ([]*SentinelRunEvent, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	rows, err := s.pool().Query(ctx, `
		select id, run_id, seq, level, kind, message, payload, created_at
		  from sentinel_run_event
		 where kind like 'poc_verify%' and payload->>'finding_id' = $1
		 order by id desc limit $2`, findingID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := make([]*SentinelRunEvent, 0, 16)
	for rows.Next() {
		var e SentinelRunEvent
		if err := rows.Scan(&e.ID, &e.RunID, &e.Seq, &e.Level, &e.Kind, &e.Message, &e.Payload, &e.CreatedAt); err != nil {
			return nil, err
		}
		events = append(events, &e)
	}
	return events, rows.Err()
}

// FindingExportRow 是导出报告的一行：finding 全字段 + 来源提交/仓库 + 判定详情。
type FindingExportRow struct {
	CommitFinding
	RepoID       string          `json:"repo_id"`
	RepoFullName string          `json:"repo_full_name"`
	SHA          string          `json:"sha"`
	Subject      string          `json:"subject"`
	CommittedAt  time.Time       `json:"committed_at"`
	Model        string          `json:"model"`
	Confidence   float64         `json:"confidence"`
	Reasoning    string          `json:"reasoning"`
	AttackPath   string          `json:"attack_path"`
	Impact       string          `json:"impact"`
	FixEvidence  string          `json:"fix_evidence"`
	Snippets     json.RawMessage `json:"evidence_snippets"`
}

// ListFindingsForExport 导出用批量查询（不分页）：沿用 FindingFilter 条件，
// 按 severity 从高到低排，单次最多 limit 行，防止一次导出把内存打爆。
func (s *Sentinel) ListFindingsForExport(ctx context.Context, f FindingFilter, limit int) ([]*FindingExportRow, error) {
	if limit <= 0 || limit > 2000 {
		limit = 500
	}
	// 复用 ListFindings 的条件拼装：借一次假分页调用不划算，这里直接内联同样逻辑。
	conds := make([]string, 0, 5)
	args := make([]interface{}, 0, 5)
	if f.Status != "" {
		args = append(args, f.Status)
		conds = append(conds, fmt.Sprintf("f.status = $%d", len(args)))
	}
	if f.Severity != "" {
		args = append(args, f.Severity)
		conds = append(conds, fmt.Sprintf("f.severity = $%d", len(args)))
	}
	if len(f.VulnClasses) > 0 {
		args = append(args, ExpandVulnClasses(f.VulnClasses))
		conds = append(conds, fmt.Sprintf("f.vuln_class = any($%d)", len(args)))
	}
	if min := severityFloor(f.MinSeverity); len(min) > 0 {
		args = append(args, min)
		conds = append(conds, fmt.Sprintf("f.severity = any($%d)", len(args)))
	}
	if f.RepoID != "" {
		args = append(args, f.RepoID)
		conds = append(conds, fmt.Sprintf("c.repo_id = $%d", len(args)))
	}
	where := ""
	if len(conds) > 0 {
		where = " where " + strings.Join(conds, " and ")
	}

	args = append(args, limit)
	rows, err := s.pool().Query(ctx, `
		select f.id, f.commit_id, f.judgment_id, f.vuln_class, f.severity, f.status,
		       f.title, f.detail, f.created_at, f.updated_at, f.verified_at, f.verified_by,
		       c.repo_id, coalesce(r.full_name, ''), c.sha, c.subject, c.committed_at,
		       coalesce(j.model, ''), coalesce(j.confidence, 0)::float8,
		       coalesce(j.reasoning, ''), coalesce(j.attack_path, ''),
		       coalesce(j.impact, ''), coalesce(j.fix_evidence, ''),
		       coalesce(j.evidence_snippets, '[]'::jsonb)
		  from finding f
		  join commit c on c.id = f.commit_id
		  left join repo r on r.id = c.repo_id
		  left join judgment j on j.id = f.judgment_id`+where+`
		 order by array_position(array['critical','high','medium','low','info'], f.severity), f.created_at desc
		 limit $`+fmt.Sprint(len(args)), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]*FindingExportRow, 0, 64)
	for rows.Next() {
		var it FindingExportRow
		if err := rows.Scan(&it.ID, &it.CommitID, &it.JudgmentID, &it.VulnClass, &it.Severity, &it.Status,
			&it.Title, &it.Detail, &it.CreatedAt, &it.UpdatedAt, &it.VerifiedAt, &it.VerifiedBy,
			&it.RepoID, &it.RepoFullName, &it.SHA, &it.Subject, &it.CommittedAt,
			&it.Model, &it.Confidence, &it.Reasoning, &it.AttackPath,
			&it.Impact, &it.FixEvidence, &it.Snippets); err != nil {
			return nil, err
		}
		items = append(items, &it)
	}
	return items, rows.Err()
}

// CommitArtifact 是 finding 的产物：PoC 源码、nuclei 模板、patch 证据、复现日志。
// 状态机 draft → pending_review → verified / rejected → deprecated，
// 铁律：非 verified 产物不可下载、不可发布到 PoC 库（service 层守卫）。
type CommitArtifact struct {
	ID        int64     `json:"id"`
	FindingID int64     `json:"finding_id"`
	Kind      string    `json:"kind"`
	Title     string    `json:"title"`
	Status    string    `json:"status"`
	Path      string    `json:"path"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

const artifactColumns = `id, finding_id, kind, title, status, path, content, created_at, updated_at`

func scanArtifact(row pgx.Row) (*CommitArtifact, error) {
	var a CommitArtifact
	if err := row.Scan(&a.ID, &a.FindingID, &a.Kind, &a.Title, &a.Status, &a.Path,
		&a.Content, &a.CreatedAt, &a.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &a, nil
}

// InsertArtifact 新建产物，返回带 id / 时间戳的记录。
func (s *Sentinel) InsertArtifact(ctx context.Context, a *CommitArtifact) (int64, error) {
	err := s.pool().QueryRow(ctx, `
		insert into artifact (finding_id, kind, title, status, path, content)
		values ($1,$2,coalesce(nullif($3,''),'untitled'),coalesce(nullif($4,''),'draft'),$5,$6)
		returning id, created_at, updated_at`,
		a.FindingID, a.Kind, a.Title, a.Status, a.Path, a.Content).
		Scan(&a.ID, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return 0, err
	}
	return a.ID, nil
}

// ListArtifacts 列出某发现下的全部产物（含 content，供预览）。
func (s *Sentinel) ListArtifacts(ctx context.Context, findingID int64) ([]*CommitArtifact, error) {
	rows, err := s.pool().Query(ctx, `
		select `+artifactColumns+` from artifact where finding_id = $1 order by id desc`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]*CommitArtifact, 0, 4)
	for rows.Next() {
		var a CommitArtifact
		if err := rows.Scan(&a.ID, &a.FindingID, &a.Kind, &a.Title, &a.Status, &a.Path,
			&a.Content, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, &a)
	}
	return items, rows.Err()
}

// GetArtifact 按 id 读取产物。
func (s *Sentinel) GetArtifact(ctx context.Context, id int64) (*CommitArtifact, error) {
	return scanArtifact(s.pool().QueryRow(ctx,
		`select `+artifactColumns+` from artifact where id = $1`, id))
}

// SetArtifactStatus 流转产物状态。
func (s *Sentinel) SetArtifactStatus(ctx context.Context, id int64, status string) error {
	tag, err := s.pool().Exec(ctx,
		`update artifact set status = $2, updated_at = now() where id = $1`, id, status)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// CountArtifactsByKind 统计某发现下指定 kind 的产物数（自动固化 patch 前判重用）。
func (s *Sentinel) CountArtifactsByKind(ctx context.Context, findingID int64, kind string) (int64, error) {
	var n int64
	err := s.pool().QueryRow(ctx,
		`select count(*) from artifact where finding_id = $1 and kind = $2`, findingID, kind).Scan(&n)
	return n, err
}

// GetFinding 按 id 读取单个发现。
func (s *Sentinel) GetFinding(ctx context.Context, id int64) (*CommitFinding, error) {
	var f CommitFinding
	err := s.pool().QueryRow(ctx, `
		select id, commit_id, judgment_id, vuln_class, severity, status, title, detail, created_at, updated_at, verified_at, verified_by, grade
		  from finding where id = $1`, id).
		Scan(&f.ID, &f.CommitID, &f.JudgmentID, &f.VulnClass, &f.Severity,
			&f.Status, &f.Title, &f.Detail, &f.CreatedAt, &f.UpdatedAt, &f.VerifiedAt, &f.VerifiedBy, &f.Grade)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &f, nil
}

// SetFindingStatus 流转发现状态（枚举校验在 service 层）。
func (s *Sentinel) SetFindingStatus(ctx context.Context, id int64, status string) error {
	tag, err := s.pool().Exec(ctx,
		`update finding set status = $2, updated_at = now() where id = $1`, id, status)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// MarkFindingVerified 定格机器复现通过：verified_at/by 写入 finding。
func (s *Sentinel) MarkFindingVerified(ctx context.Context, id int64, by string) error {
	tag, err := s.pool().Exec(ctx,
		`update finding set verified_at = now(), verified_by = $2, updated_at = now() where id = $1`,
		id, by)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
