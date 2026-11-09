package repo

import (
	"fmt"

	"context"
	"encoding/json"
	"errors"
	"github.com/c1ayooo/4zreark/internal/secretbox"
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
	ProjectID       int64  `json:"project_id"`
	Enabled         bool   `json:"enabled"`
	Token           string `json:"-"` // 不回显
	TokenConfigured bool   `json:"token_configured"`
	IntervalSeconds int    `json:"interval_seconds,omitempty"`
	// 高级误报治理与动态规则（迁移自 4zreco 的 PatchSettings/PatchAdvancedSettings 参数面）。
	// 零值/空串语义为「沿用旧值」，UpsertSettings 里用 excluded case 实现。
	RepoMaxAgeDays        int       `json:"repo_max_age_days,omitempty"`
	LookbackDays          int       `json:"lookback_days,omitempty"`
	BoilerplateRepos      int       `json:"boilerplate_repos,omitempty"`
	BlobRescan            bool      `json:"blob_rescan"`
	MaxBlobRescansPerRule int       `json:"max_blob_rescans_per_rule,omitempty"`
	ExtraRulesPath        string    `json:"extra_rules_path,omitempty"`
	NotifyEnabled         bool      `json:"notify_enabled"`
	Updated               time.Time `json:"updated,omitempty"`
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
	// FirstActiveSettings 任一已启用项目的监控设置（token 已解密）。
	// 监控循环出网用它取 token 与轮询间隔；token 池化是后续事。
	FirstActiveSettings(ctx context.Context) (*GitHubMonitorSettings, error)
	// FirstToken 任一项目配过的 GitHub Token（FirstActiveSettings 的便捷包装）。
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
);
-- 高级误报治理与动态规则列（迁移自 4zreco 的设置面；幂等补列，老库无痛升级）
alter table github_monitor_settings add column if not exists repo_max_age_days int not null default 0;
alter table github_monitor_settings add column if not exists lookback_days int not null default 0;
alter table github_monitor_settings add column if not exists boilerplate_repos int not null default 0;
alter table github_monitor_settings add column if not exists blob_rescan boolean not null default true;
alter table github_monitor_settings add column if not exists max_blob_rescans_per_rule int not null default 0;
alter table github_monitor_settings add column if not exists extra_rules_path text not null default '';
alter table github_monitor_settings add column if not exists notify_enabled boolean not null default true;`)
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
select enabled, token, interval_seconds, repo_max_age_days, lookback_days, boilerplate_repos,
       blob_rescan, max_blob_rescans_per_rule, extra_rules_path, notify_enabled, updated
from github_monitor_settings where project_id = $1`, projectID).
		Scan(&s.Enabled, &token, &s.IntervalSeconds, &s.RepoMaxAgeDays, &s.LookbackDays,
			&s.BoilerplateRepos, &s.BlobRescan, &s.MaxBlobRescansPerRule, &s.ExtraRulesPath,
			&s.NotifyEnabled, &s.Updated)
	if errors.Is(err, pgx.ErrNoRows) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	// 审计 M13：双读——enc:v1: 解密，存量明文原样返回（迁移共存期）。
	if plain, derr := secretbox.DecryptText(token); derr != nil {
		return nil, fmt.Errorf("解密监控 token 失败: %w", derr)
	} else {
		token = plain
	}
	s.Token = token
	s.TokenConfigured = token != ""
	return s, nil
}

func (g *githubMonitorRepo) UpsertSettings(ctx context.Context, s *GitHubMonitorSettings) error {
	if err := g.ensureSchema(ctx); err != nil {
		return err
	}
	// 审计 M13：token 信封加密落库；空 token 语义不变（表示"沿用旧值"）。
	encToken, encErr := secretbox.EncryptText(s.Token)
	if encErr != nil {
		return fmt.Errorf("加密监控 token 失败: %w", encErr)
	}
	_, err := g.r.pool.Exec(ctx, `
insert into github_monitor_settings (project_id, enabled, token, interval_seconds,
                                     repo_max_age_days, lookback_days, boilerplate_repos,
                                     blob_rescan, max_blob_rescans_per_rule, extra_rules_path,
                                     notify_enabled, updated)
values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,now())
on conflict (project_id) do update set
	enabled = excluded.enabled,
	token = case when excluded.token != '' then excluded.token else github_monitor_settings.token end,
	interval_seconds = excluded.interval_seconds,
	-- 高级参数零值/空串 = 沿用旧值（前端只传变更字段）
	repo_max_age_days = case when excluded.repo_max_age_days > 0 then excluded.repo_max_age_days else github_monitor_settings.repo_max_age_days end,
	lookback_days = case when excluded.lookback_days > 0 then excluded.lookback_days else github_monitor_settings.lookback_days end,
	boilerplate_repos = case when excluded.boilerplate_repos > 0 then excluded.boilerplate_repos else github_monitor_settings.boilerplate_repos end,
	blob_rescan = excluded.blob_rescan,
	max_blob_rescans_per_rule = case when excluded.max_blob_rescans_per_rule > 0 then excluded.max_blob_rescans_per_rule else github_monitor_settings.max_blob_rescans_per_rule end,
	extra_rules_path = case when excluded.extra_rules_path != '' then excluded.extra_rules_path else github_monitor_settings.extra_rules_path end,
	notify_enabled = excluded.notify_enabled,
	updated = now()`,
		s.ProjectID, s.Enabled, encToken, s.IntervalSeconds,
		s.RepoMaxAgeDays, s.LookbackDays, s.BoilerplateRepos,
		s.BlobRescan, s.MaxBlobRescansPerRule, s.ExtraRulesPath,
		s.NotifyEnabled)
	return err
}

// FirstActiveSettings 取第一个「已启用且有 token」项目的设置，token 走与
// GetSettings 相同的解密路径——此前这里直接返回 enc:v1 密文，导致监控循环
// 拿密文当 Bearer，GitHub 一律 401。
func (g *githubMonitorRepo) FirstActiveSettings(ctx context.Context) (*GitHubMonitorSettings, error) {
	if err := g.ensureSchema(ctx); err != nil {
		return nil, err
	}
	s := &GitHubMonitorSettings{}
	var token string
	err := g.r.pool.QueryRow(ctx, `
select project_id, enabled, token, interval_seconds, repo_max_age_days, lookback_days,
       boilerplate_repos, blob_rescan, max_blob_rescans_per_rule, extra_rules_path, notify_enabled
from github_monitor_settings
where token != '' and enabled
order by project_id limit 1`).
		Scan(&s.ProjectID, &s.Enabled, &token, &s.IntervalSeconds, &s.RepoMaxAgeDays,
			&s.LookbackDays, &s.BoilerplateRepos, &s.BlobRescan, &s.MaxBlobRescansPerRule,
			&s.ExtraRulesPath, &s.NotifyEnabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	plain, derr := secretbox.DecryptText(token)
	if derr != nil {
		return nil, fmt.Errorf("解密监控 token 失败: %w", derr)
	}
	s.Token = plain
	s.TokenConfigured = plain != ""
	return s, nil
}

func (g *githubMonitorRepo) FirstToken(ctx context.Context) (string, error) {
	s, err := g.FirstActiveSettings(ctx)
	if err != nil {
		return "", err
	}
	return s.Token, nil
}

func (g *githubMonitorRepo) ProjectName(ctx context.Context, projectID int64) (string, error) {
	var name string
	err := g.r.pool.QueryRow(ctx, `select name from projects where id = $1`, projectID).Scan(&name)
	return name, err
}

var _ = time.Now
