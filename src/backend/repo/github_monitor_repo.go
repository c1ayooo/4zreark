package repo

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// GitHub 监控（迁移自 4zreco/internal/githubleak）：
// findings/candidates/runs/suppressions 四张表由 githubleak.Store（database/sql）自建自管；
// 这里只管 4zreark 侧的项目绑定——规则（项目 ID + 关键词）与开关设置。
// 规则名落库时带项目名前缀（「{项目名}: {规则名}」），findings.rule_name 可溯源到项目。

type GitHubMonitorRule struct {
	ID        int64     `json:"id"`
	ProjectID int64     `json:"project_id"`
	Name      string    `json:"name"`
	Keywords  []string  `json:"keywords"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
}

type GitHubMonitorSettings struct {
	ProjectID       int64     `json:"project_id"`
	Enabled         bool      `json:"enabled"`
	Token           string    `json:"-"` // 不回显
	TokenConfigured bool      `json:"token_configured"`
	IntervalSeconds int       `json:"interval_seconds,omitempty"`
	Updated         time.Time `json:"updated,omitempty"`
}

type GitHubMonitorRepo interface {
	ListRules(ctx context.Context, projectID int64) ([]GitHubMonitorRule, error)
	CreateRule(ctx context.Context, r *GitHubMonitorRule) (*GitHubMonitorRule, error)
	UpdateRule(ctx context.Context, r *GitHubMonitorRule) (*GitHubMonitorRule, error)
	DeleteRule(ctx context.Context, projectID, ruleID int64) error
	// ListAllEnabledRules 全部启用规则（监控循环同步用，跨项目）。
	ListAllEnabledRules(ctx context.Context) ([]GitHubMonitorRule, error)
	GetSettings(ctx context.Context, projectID int64) (*GitHubMonitorSettings, error)
	UpsertSettings(ctx context.Context, s *GitHubMonitorSettings) error
	// FirstToken 任一项目配过的 GitHub Token（监控循环出网用；token 池化是后续事）。
	FirstToken(ctx context.Context) (string, error)
	ProjectName(ctx context.Context, projectID int64) (string, error)
}

type githubMonitorRepo struct{ r *Repo }

func (r *Repo) GitHubMonitor() GitHubMonitorRepo { return &githubMonitorRepo{r: r} }

func (g *githubMonitorRepo) ensureSchema(ctx context.Context) error {
	_, err := g.r.pool.Exec(ctx, `
create table if not exists github_monitor_rules (
	id bigserial primary key,
	project_id bigint not null references projects(id) on delete cascade,
	name text not null,
	keywords jsonb not null default '[]',
	enabled boolean not null default true,
	created_at timestamptz not null default now()
);
create table if not exists github_monitor_settings (
	project_id bigint primary key references projects(id) on delete cascade,
	enabled boolean not null default false,
	token text not null default '',
	interval_seconds int not null default 0,
	updated timestamptz not null default now()
);`)
	return err
}

func (g *githubMonitorRepo) ListRules(ctx context.Context, projectID int64) ([]GitHubMonitorRule, error) {
	if err := g.ensureSchema(ctx); err != nil {
		return nil, err
	}
	rows, err := g.r.pool.Query(ctx, `
select id, project_id, name, coalesce(keywords, '[]'::jsonb), enabled, created_at
from github_monitor_rules where project_id = $1 order by id`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []GitHubMonitorRule{}
	for rows.Next() {
		var r GitHubMonitorRule
		var kw []byte
		if err := rows.Scan(&r.ID, &r.ProjectID, &r.Name, &kw, &r.Enabled, &r.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(kw, &r.Keywords)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (g *githubMonitorRepo) CreateRule(ctx context.Context, r *GitHubMonitorRule) (*GitHubMonitorRule, error) {
	if err := g.ensureSchema(ctx); err != nil {
		return nil, err
	}
	kw, _ := json.Marshal(r.Keywords)
	err := g.r.pool.QueryRow(ctx, `
insert into github_monitor_rules (project_id, name, keywords, enabled)
values ($1,$2,$3,$4) returning id, created_at`, r.ProjectID, r.Name, kw, r.Enabled).
		Scan(&r.ID, &r.CreatedAt)
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (g *githubMonitorRepo) UpdateRule(ctx context.Context, r *GitHubMonitorRule) (*GitHubMonitorRule, error) {
	kw, _ := json.Marshal(r.Keywords)
	tag, err := g.r.pool.Exec(ctx, `
update github_monitor_rules set name=$2, keywords=$3, enabled=$4
where id=$1 and project_id=$5`, r.ID, r.Name, kw, r.Enabled, r.ProjectID)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, pgx.ErrNoRows
	}
	return r, nil
}

func (g *githubMonitorRepo) DeleteRule(ctx context.Context, projectID, ruleID int64) error {
	_, err := g.r.pool.Exec(ctx, `delete from github_monitor_rules where id=$1 and project_id=$2`, ruleID, projectID)
	return err
}

func (g *githubMonitorRepo) ListAllEnabledRules(ctx context.Context) ([]GitHubMonitorRule, error) {
	if err := g.ensureSchema(ctx); err != nil {
		return nil, err
	}
	rows, err := g.r.pool.Query(ctx, `
select r.id, r.project_id, p.name || ': ' || r.name, coalesce(r.keywords,'[]'::jsonb), r.enabled, r.created_at
from github_monitor_rules r join projects p on p.id = r.project_id
where r.enabled and p.collection_paused = false order by r.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []GitHubMonitorRule{}
	for rows.Next() {
		var r GitHubMonitorRule
		var kw []byte
		if err := rows.Scan(&r.ID, &r.ProjectID, &r.Name, &kw, &r.Enabled, &r.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(kw, &r.Keywords)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (g *githubMonitorRepo) GetSettings(ctx context.Context, projectID int64) (*GitHubMonitorSettings, error) {
	if err := g.ensureSchema(ctx); err != nil {
		return nil, err
	}
	s := &GitHubMonitorSettings{ProjectID: projectID}
	var token string
	err := g.r.pool.QueryRow(ctx, `
select enabled, token, interval_seconds, updated
from github_monitor_settings where project_id = $1`, projectID).
		Scan(&s.Enabled, &token, &s.IntervalSeconds, &s.Updated)
	if errors.Is(err, pgx.ErrNoRows) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	s.Token = token
	s.TokenConfigured = token != ""
	return s, nil
}

func (g *githubMonitorRepo) UpsertSettings(ctx context.Context, s *GitHubMonitorSettings) error {
	if err := g.ensureSchema(ctx); err != nil {
		return err
	}
	_, err := g.r.pool.Exec(ctx, `
insert into github_monitor_settings (project_id, enabled, token, interval_seconds, updated)
values ($1,$2,$3,$4,now())
on conflict (project_id) do update set
	enabled = excluded.enabled,
	token = case when excluded.token != '' then excluded.token else github_monitor_settings.token end,
	interval_seconds = excluded.interval_seconds,
	updated = now()`, s.ProjectID, s.Enabled, s.Token, s.IntervalSeconds)
	return err
}

func (g *githubMonitorRepo) FirstToken(ctx context.Context) (string, error) {
	if err := g.ensureSchema(ctx); err != nil {
		return "", err
	}
	var token string
	err := g.r.pool.QueryRow(ctx,
		`select token from github_monitor_settings where token != '' and enabled order by project_id limit 1`).
		Scan(&token)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return token, err
}

func (g *githubMonitorRepo) ProjectName(ctx context.Context, projectID int64) (string, error) {
	var name string
	err := g.r.pool.QueryRow(ctx, `select name from projects where id = $1`, projectID).Scan(&name)
	return name, err
}

var _ = time.Now
