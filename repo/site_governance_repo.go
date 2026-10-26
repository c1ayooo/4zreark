package repo

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// 站点资产治理：星标 / 标签 / 备注，以及 TLS 证书到期时间。
//
// 字段由 docs/sql/migration_site_governance.sql / migration_site_cert_expiry.sql
// 落库；这里是启动兜底（ADD COLUMN IF NOT EXISTS 幂等），老库跑一次新代码也能用。

var siteExtendedSchemaOnce sync.Once

// ensureSiteExtendedSchema 保证治理与证书字段存在。进程内只跑一次；
// 失败时清掉 once 标记让下次调用重试。
func (a *AssetRepo) ensureSiteExtendedSchema(ctx context.Context) error {
	var err error
	siteExtendedSchemaOnce.Do(func() {
		_, err = a.r.pool.Exec(ctx, `
alter table sites add column if not exists starred boolean not null default false;
alter table sites add column if not exists tags jsonb not null default '[]'::jsonb;
alter table sites add column if not exists note text not null default '';
alter table sites add column if not exists ignored boolean not null default false;
alter table sites add column if not exists cert_not_after timestamptz;
create index if not exists idx_sites_starred on sites (project_id, last_seen desc) where starred;
create index if not exists idx_sites_tags on sites using gin (tags jsonb_path_ops);
create index if not exists idx_sites_ignored on sites (project_id, last_seen desc) where ignored;
create index if not exists idx_sites_cert_expiry on sites (cert_not_after) where cert_not_after is not null;`)
		if err != nil {
			siteExtendedSchemaOnce = sync.Once{}
		}
	})
	return err
}

// SiteGovernanceInput 治理操作输入。指针为 nil 的字段不改（部分更新）。
type SiteGovernanceInput struct {
	Starred *bool
	Tags    *[]string
	Note    *string
	Ignored *bool
}

// UpdateSiteGovernance 星标/标签/备注。同事务只改出现的字段，避免并发互踩。
func (a *AssetRepo) UpdateSiteGovernance(ctx context.Context, siteID int64, in SiteGovernanceInput) error {
	if a == nil || a.r == nil {
		return errUninitialized()
	}
	if err := a.ensureSiteExtendedSchema(ctx); err != nil {
		return err
	}
	if in.Starred == nil && in.Tags == nil && in.Note == nil {
		return nil
	}

	sets := []string{}
	args := []any{}
	add := func(v any) string { // 追加参数并返回其占位符
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}
	if in.Starred != nil {
		sets = append(sets, "starred = "+add(*in.Starred))
	}
	if in.Tags != nil {
		sets = append(sets, "tags = "+add(stringSliceJSONB(normalizeTags(*in.Tags))))
	}
	if in.Note != nil {
		sets = append(sets, "note = "+add(strings.TrimSpace(*in.Note)))
	}
	if in.Ignored != nil {
		sets = append(sets, "ignored = "+add(*in.Ignored))
	}
	args = append(args, siteID)

	tag, err := a.r.pool.Exec(ctx,
		`update sites set `+strings.Join(sets, ", ")+` where id = `+fmt.Sprintf("$%d", len(args)),
		args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// normalizeTags 清洗标签：去空白、去重、限长。治理输入是人工敲的，宽进严出。
func normalizeTags(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, t := range in {
		t = strings.TrimSpace(t)
		if t == "" || len(t) > 64 {
			continue
		}
		if seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
		if len(out) >= 20 {
			break
		}
	}
	return out
}

// ExpiringCertSite 是一条即将到期的证书站点。
type ExpiringCertSite struct {
	SiteID       int64      `json:"site_id"`
	ProjectID    int64      `json:"project_id"`
	Host         string     `json:"host"`
	Value        string     `json:"value"`
	CertNotAfter time.Time  `json:"cert_not_after"`
	DaysLeft     int        `json:"days_left"`
	LastSeen     *time.Time `json:"last_seen"`
}

// ListExpiringCerts 取证书 N 天内到期的站点。daysLeft 封顶查询窗口，
// 返回按剩余天数升序（最紧急在前）。
func (a *AssetRepo) ListExpiringCerts(ctx context.Context, daysLeft int, limit int) ([]ExpiringCertSite, error) {
	if a == nil || a.r == nil {
		return nil, errUninitialized()
	}
	if err := a.ensureSiteExtendedSchema(ctx); err != nil {
		return nil, err
	}
	if daysLeft <= 0 {
		daysLeft = 30
	}
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := a.r.pool.Query(ctx, `
select s.id, s.project_id, s.host, s.value, s.cert_not_after,
       coalesce(ceil(extract(epoch from (s.cert_not_after - now()))/86400)::int, 0),
       s.last_seen
  from sites s
 where s.cert_not_after is not null
   and s.cert_not_after < now() + make_interval(days => $1::int)
   and not exists (select 1 from projects p where p.id = s.project_id and p.collection_paused)
 order by s.cert_not_after asc
 limit $2`, daysLeft, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ExpiringCertSite{}
	for rows.Next() {
		var e ExpiringCertSite
		if err := rows.Scan(&e.SiteID, &e.ProjectID, &e.Host, &e.Value,
			&e.CertNotAfter, &e.DaysLeft, &e.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// LastCertExpiryEventAt 查站点最近一次 cert_expiry 事件的时间，用来做告警去重
// （同一站点的同级别提醒 24 小时内不重复发）。
func (a *AssetRepo) LastCertExpiryEventAt(ctx context.Context, siteID int64) (*time.Time, error) {
	var t *time.Time
	err := a.r.pool.QueryRow(ctx, `
select max(created_at) from asset_events
 where site_id = $1 and event_type = 'cert_expiry'`, siteID).Scan(&t)
	return t, err
}
