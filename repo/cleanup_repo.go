package repo

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

func errUninitialized() error { return fmt.Errorf("资产仓储未初始化") }

// OperationLogInput 是操作审计的一条记录。
// 目前只给治理域的自动动作（归档 / 人工干预）用；
// 等分片 C 把 logger 中间件也从 Mongo 迁过来，统一走这里。
type OperationLogInput struct {
	UserID    string
	Username  string
	Action    string
	Module    string
	Target    string
	Detail    string
	IP        string
	UserAgent string
	Status    int
}

// LogOperation 写一条操作日志。
func (r *Repo) LogOperation(ctx context.Context, in OperationLogInput) error {
	if r == nil || r.pool == nil {
		return nil
	}
	if in.Status == 0 {
		in.Status = 1
	}
	var userID any
	if in.UserID != "" {
		userID = in.UserID
	}
	_, err := r.pool.Exec(ctx,
		`insert into operation_logs (user_id, username, action, module, target, detail, ip, user_agent, status)
		 values ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		userID, in.Username, in.Action, in.Module, in.Target, in.Detail, in.IP, in.UserAgent, in.Status)
	return err
}

// CleanupCandidate 是待归档的失联站点。
type CleanupCandidate struct {
	ID          int64
	ProjectID   int64
	Host        string
	LostSinceMS int64
}

// LostSitesForCleanup 取「失联超过 days 天、且不在人工保护期内」的站点。
func (a *AssetRepo) LostSitesForCleanup(ctx context.Context, days, limit int) ([]CleanupCandidate, error) {
	if a == nil || a.r == nil {
		return nil, errUninitialized()
	}
	if days <= 0 {
		days = 30
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := a.r.pool.Query(ctx,
		`SELECT id, project_id, host, lost_since_ms
		   FROM sites
		  WHERE state = 'lost'
		    AND lost_since_ms > 0
		    AND lost_since_ms < (extract(epoch from now()) * 1000 - $1::bigint * 86400000)
		    AND (protected_until IS NULL OR protected_until < now())
		  ORDER BY lost_since_ms
		  LIMIT $2`, days, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []CleanupCandidate{}
	for rows.Next() {
		var c CleanupCandidate
		if err := rows.Scan(&c.ID, &c.ProjectID, &c.Host, &c.LostSinceMS); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ArchiveSite 归档一个站点：状态置 archived，并留一条事件。
// 只改状态，不删数据——站点与它的证据要留到 retention 到期。
func (a *AssetRepo) ArchiveSite(ctx context.Context, siteID int64, reason string) error {
	if a == nil || a.r == nil {
		return errUninitialized()
	}
	tx, err := a.r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var projectID int64
	var host string
	if err := tx.QueryRow(ctx,
		`UPDATE sites SET state = 'archived', cleanup_eligible = false
		  WHERE id = $1 AND state = 'lost'
		  RETURNING project_id, host`, siteID).Scan(&projectID, &host); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO asset_events (project_id, site_id, event_type, title, after)
		VALUES ($1, $2, 'archived', $3, jsonb_build_object('reason', $4::text))`,
		projectID, siteID, host+" 失联归档", reason); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// SetProtection 设置人工删除保护期（这段时间内不会被自动归档）。
func (a *AssetRepo) SetProtection(ctx context.Context, siteID int64, until time.Time) error {
	if a == nil || a.r == nil {
		return errUninitialized()
	}
	tag, err := a.r.pool.Exec(ctx,
		`UPDATE sites SET protected_until = $2 WHERE id = $1`, siteID, timeToPG(until))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ClearProtection 解除人工删除保护期：protected_until 置空（列可空，见 schema_governance.sql）。
// 与 SetProtection 相对；不触碰 ProtectSite 的 days<=0 强制 90 天语义。
func (a *AssetRepo) ClearProtection(ctx context.Context, siteID int64) error {
	if a == nil || a.r == nil {
		return errUninitialized()
	}
	tag, err := a.r.pool.Exec(ctx,
		`UPDATE sites SET protected_until = NULL WHERE id = $1`, siteID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SiteForDelete 是删除前要读的站点信息：host 用于审计，protected_until 用于保护期校验。
type SiteForDelete struct {
	ID             int64
	ProjectID      int64
	Host           string
	ProtectedUntil *time.Time
}

// GetSiteForDelete 读取单个站点的删除前信息，不存在时返回 ErrNotFound。
func (a *AssetRepo) GetSiteForDelete(ctx context.Context, siteID int64) (*SiteForDelete, error) {
	if a == nil || a.r == nil {
		return nil, errUninitialized()
	}
	var s SiteForDelete
	err := a.r.pool.QueryRow(ctx,
		`SELECT id, project_id, host, protected_until FROM sites WHERE id = $1`, siteID).
		Scan(&s.ID, &s.ProjectID, &s.Host, &s.ProtectedUntil)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// DeleteSite 物理删除一个站点，不要求 lost 状态（与 DeleteLostSite 的唯一差别）。
// 级联清单与 DeleteLostSite 相同，全部由外键兜底：
// verifications / asset_events / 指纹命中 / 入口（site_endpoints、site_routes）级联删除，
// raw_records.site_id 置空保留证据链。
// 注意：DeleteLostSite（verification_repo.go）不在本工单可改清单内，两处 SQL 暂时各自维护；
// 若级联口径变化，务必两边同步。
func (a *AssetRepo) DeleteSite(ctx context.Context, siteID int64) error {
	if a == nil || a.r == nil {
		return errUninitialized()
	}
	tag, err := a.r.pool.Exec(ctx, `DELETE FROM sites WHERE id = $1`, siteID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
