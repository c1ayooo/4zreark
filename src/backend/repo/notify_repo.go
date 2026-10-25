package repo

import (
	"context"
	"encoding/json"
	"time"
)

// NotifyConfigRecord 是持久化的通知渠道配置。
// Config 保持 notify.NotifyConfig 的 JSON 形态，repo 不反向依赖 service 层。
type NotifyConfigRecord struct {
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	Enabled   bool      `json:"enabled"`
	Config    []byte    `json:"config"`
	UpdatedAt time.Time `json:"updated_at"`
}

// NotificationRow 是一条站内通知；Read 是当前用户的已读状态。
type NotificationRow struct {
	ID        int64           `json:"id"`
	Level     string          `json:"level"`
	Title     string          `json:"title"`
	Content   string          `json:"content"`
	Source    string          `json:"source"`
	Extra     json.RawMessage `json:"extra"`
	Read      bool            `json:"read"`
	CreatedAt time.Time       `json:"created_at"`
}

// NotifyRepo 是通知域的唯一数据入口：渠道配置 + 站内通知 + 已读状态。
type NotifyRepo interface {
	ListConfigs(ctx context.Context) ([]*NotifyConfigRecord, error)
	UpsertConfig(ctx context.Context, rec *NotifyConfigRecord) error
	DeleteConfig(ctx context.Context, name, typ string) error
	SetConfigEnabled(ctx context.Context, name, typ string, enabled bool) error

	AddNotification(ctx context.Context, level, title, content, source string, extra map[string]interface{}) (int64, error)
	ListNotifications(ctx context.Context, userID string, unreadOnly bool, limit, offset int) ([]*NotificationRow, int64, error)
	UnreadCount(ctx context.Context, userID string) (int64, error)
	MarkRead(ctx context.Context, userID string, id int64) error
	MarkAllRead(ctx context.Context, userID string) (int64, error)
	PurgeNotifications(ctx context.Context, days, batch int) (int64, error)
}

type notifyRepo struct{ r *Repo }

func (r *Repo) Notify() NotifyRepo { return &notifyRepo{r: r} }

func (n *notifyRepo) ListConfigs(ctx context.Context) ([]*NotifyConfigRecord, error) {
	rows, err := n.r.pool.Query(ctx,
		`select name, type, enabled, config, updated_at from notify_configs order by id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]*NotifyConfigRecord, 0)
	for rows.Next() {
		var rec NotifyConfigRecord
		if err := rows.Scan(&rec.Name, &rec.Type, &rec.Enabled, &rec.Config, &rec.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, &rec)
	}
	return out, rows.Err()
}

func (n *notifyRepo) UpsertConfig(ctx context.Context, rec *NotifyConfigRecord) error {
	if rec == nil {
		return nil
	}
	if len(rec.Config) == 0 {
		rec.Config = []byte("{}")
	}
	_, err := n.r.pool.Exec(ctx, `
insert into notify_configs (name, type, enabled, config, updated_at)
values ($1,$2,$3,$4::jsonb, now())
on conflict (name, type) do update set
    enabled    = excluded.enabled,
    config     = excluded.config,
    updated_at = now()`,
		rec.Name, rec.Type, rec.Enabled, string(rec.Config))
	return err
}

func (n *notifyRepo) DeleteConfig(ctx context.Context, name, typ string) error {
	_, err := n.r.pool.Exec(ctx, `delete from notify_configs where name=$1 and type=$2`, name, typ)
	return err
}

func (n *notifyRepo) SetConfigEnabled(ctx context.Context, name, typ string, enabled bool) error {
	tag, err := n.r.pool.Exec(ctx,
		`update notify_configs set enabled=$3, updated_at=now() where name=$1 and type=$2`,
		name, typ, enabled)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (n *notifyRepo) AddNotification(ctx context.Context, level, title, content, source string, extra map[string]interface{}) (int64, error) {
	raw := []byte("{}")
	if len(extra) > 0 {
		b, err := json.Marshal(extra)
		if err != nil {
			return 0, err
		}
		raw = b
	}
	var id int64
	err := n.r.pool.QueryRow(ctx, `
insert into notifications (level, title, content, source, extra)
values ($1,$2,$3,$4,$5::jsonb)
returning id`, level, title, content, source, string(raw)).Scan(&id)
	return id, err
}

func (n *notifyRepo) ListNotifications(ctx context.Context, userID string, unreadOnly bool, limit, offset int) ([]*NotificationRow, int64, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	countSQL := `select count(*) from notifications`
	listSQL := `
select n.id, n.level, n.title, n.content, n.source, n.extra, n.created_at,
       (r.user_id is not null) as read
  from notifications n
  left join notification_reads r on r.notification_id = n.id and r.user_id = $1
 order by n.created_at desc, n.id desc
 limit $2 offset $3`
	if unreadOnly {
		countSQL = `
select count(*) from notifications n
 where not exists (
       select 1 from notification_reads r
        where r.notification_id = n.id and r.user_id = $1)`
		listSQL = `
select n.id, n.level, n.title, n.content, n.source, n.extra, n.created_at, false as read
  from notifications n
 where not exists (
       select 1 from notification_reads r
        where r.notification_id = n.id and r.user_id = $1)
 order by n.created_at desc, n.id desc
 limit $2 offset $3`
	}

	var total int64
	var err error
	if unreadOnly {
		err = n.r.pool.QueryRow(ctx, countSQL, userID).Scan(&total)
	} else {
		err = n.r.pool.QueryRow(ctx, countSQL).Scan(&total)
	}
	if err != nil {
		return nil, 0, err
	}

	rows, err := n.r.pool.Query(ctx, listSQL, userID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := make([]*NotificationRow, 0)
	for rows.Next() {
		var row NotificationRow
		if err := rows.Scan(&row.ID, &row.Level, &row.Title, &row.Content, &row.Source,
			&row.Extra, &row.CreatedAt, &row.Read); err != nil {
			return nil, 0, err
		}
		out = append(out, &row)
	}
	return out, total, rows.Err()
}

func (n *notifyRepo) UnreadCount(ctx context.Context, userID string) (int64, error) {
	var count int64
	err := n.r.pool.QueryRow(ctx, `
select count(*)
  from notifications n
 where not exists (
       select 1 from notification_reads r
        where r.notification_id = n.id and r.user_id = $1)`, userID).Scan(&count)
	return count, err
}

func (n *notifyRepo) MarkRead(ctx context.Context, userID string, id int64) error {
	if id <= 0 {
		return ErrNotFound
	}
	var exists bool
	if err := n.r.pool.QueryRow(ctx, `select exists (select 1 from notifications where id=$1)`, id).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrNotFound
	}
	_, err := n.r.pool.Exec(ctx, `
insert into notification_reads (notification_id, user_id)
values ($1,$2)
on conflict (notification_id, user_id) do nothing`, id, userID)
	return err
}

func (n *notifyRepo) MarkAllRead(ctx context.Context, userID string) (int64, error) {
	tag, err := n.r.pool.Exec(ctx, `
insert into notification_reads (notification_id, user_id)
select n.id, $1 from notifications n
 where not exists (
       select 1 from notification_reads r
        where r.notification_id = n.id and r.user_id = $1)
on conflict (notification_id, user_id) do nothing`, userID)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// PurgeNotifications 删除 days 天前的站内通知，单批最多 batch 条。
// notification_reads 对 notifications 是 ON DELETE CASCADE，已读状态随之清理。
func (n *notifyRepo) PurgeNotifications(ctx context.Context, days, batch int) (int64, error) {
	if days <= 0 {
		return 0, nil
	}
	if batch <= 0 || batch > 50000 {
		batch = 10000
	}
	tag, err := n.r.pool.Exec(ctx, `
DELETE FROM notifications
 WHERE id IN (
   SELECT id FROM notifications
    WHERE created_at < now() - make_interval(days => $1)
    ORDER BY created_at
    LIMIT $2
 )`, days, batch)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
