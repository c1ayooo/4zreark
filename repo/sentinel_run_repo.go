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

// 提交哨兵的批次、事件流、域内审计与总览聚合。
// 事件流为 /api/sentinel/runs/:id/events?last_seq=N 的续传提供 (run_id, seq) 唯一序列。

// SentinelRun 是一次采集/判定批次。
type SentinelRun struct {
	ID         int64      `json:"id"`
	RunType    string     `json:"run_type"`
	RepoID     *string    `json:"repo_id"`
	Status     string     `json:"status"`
	Total      int        `json:"total"`
	Processed  int        `json:"processed"`
	Failed     int        `json:"failed"`
	LastSeq    int64      `json:"last_seq"`
	Error      string     `json:"error"`
	StartedAt  *time.Time `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at"`
	CreatedAt  time.Time  `json:"created_at"`
}

// SentinelRunEvent 是事件流中的一条记录。
type SentinelRunEvent struct {
	ID        int64           `json:"id"`
	RunID     int64           `json:"run_id"`
	Seq       int64           `json:"seq"`
	Level     string          `json:"level"`
	Kind      string          `json:"kind"`
	Message   string          `json:"message"`
	Payload   json.RawMessage `json:"payload"`
	CreatedAt time.Time       `json:"created_at"`
}

// SentinelOverview 是总览页的聚合数字。
type SentinelOverview struct {
	RepoCount      int64 `json:"repo_count"`
	TodayCommits   int64 `json:"today_commits"`
	SecurityFixes  int64 `json:"security_fixes"`
	PendingCommits int64 `json:"pending_commits"`
	QueueBacklog   int64 `json:"queue_backlog"`
}

const sentinelRunColumns = `id, run_type, repo_id, status, total, processed, failed,
	last_seq, error, started_at, finished_at, created_at`

func scanSentinelRun(row pgx.Row) (*SentinelRun, error) {
	var r SentinelRun
	err := row.Scan(&r.ID, &r.RunType, &r.RepoID, &r.Status, &r.Total, &r.Processed, &r.Failed,
		&r.LastSeq, &r.Error, &r.StartedAt, &r.FinishedAt, &r.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// CreateRun 新建批次。
func (s *Sentinel) CreateRun(ctx context.Context, r *SentinelRun) (int64, error) {
	var id int64
	err := s.pool().QueryRow(ctx, `
		insert into run (run_type, repo_id, status, total)
		values ($1,$2,coalesce(nullif($3,''),'pending'),$4)
		returning id`, r.RunType, r.RepoID, r.Status, r.Total).Scan(&id)
	return id, err
}

// GetRun 读取批次。
func (s *Sentinel) GetRun(ctx context.Context, id int64) (*SentinelRun, error) {
	return scanSentinelRun(s.pool().QueryRow(ctx,
		`select `+sentinelRunColumns+` from run where id = $1`, id))
}

// ListRuns 列出最近批次。
func (s *Sentinel) ListRuns(ctx context.Context, runType string, limit int) ([]*SentinelRun, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := s.pool().Query(ctx, `
		select `+sentinelRunColumns+`
		  from run
		 where ($1 = '' or run_type = $1)
		 order by id desc limit $2`, runType, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]*SentinelRun, 0, limit)
	for rows.Next() {
		r, err := scanSentinelRun(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, r)
	}
	return items, rows.Err()
}

// UpdateRun 按白名单更新批次状态与计数。
func (s *Sentinel) UpdateRun(ctx context.Context, id int64, fields map[string]interface{}) error {
	allowed := map[string]string{
		"status":      "status",
		"total":       "total",
		"processed":   "processed",
		"failed":      "failed",
		"error":       "error",
		"started_at":  "started_at",
		"finished_at": "finished_at",
	}
	sets := make([]string, 0, len(fields))
	args := make([]interface{}, 0, len(fields)+1)
	for key, val := range fields {
		col, ok := allowed[key]
		if !ok {
			return errors.New("批次字段不可更新: " + key)
		}
		args = append(args, val)
		sets = append(sets, col+" = $"+strconv.Itoa(len(args)))
	}
	if len(sets) == 0 {
		return nil
	}
	args = append(args, id)
	tag, err := s.pool().Exec(ctx,
		"update run set "+strings.Join(sets, ", ")+" where id = $"+strconv.Itoa(len(args)), args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// AppendRunEvent 在事务内自增 run.last_seq 并写入事件，保证 seq 连续且唯一。
func (s *Sentinel) AppendRunEvent(ctx context.Context, ev *SentinelRunEvent) (int64, error) {
	tx, err := s.pool().Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := tx.QueryRow(ctx,
		`update run set last_seq = last_seq + 1 where id = $1 returning last_seq`,
		ev.RunID).Scan(&ev.Seq); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, ErrNotFound
		}
		return 0, err
	}

	payload := ev.Payload
	if len(payload) == 0 {
		payload = json.RawMessage("{}")
	}
	if _, err := tx.Exec(ctx, `
		insert into run_event (run_id, seq, level, kind, message, payload)
		values ($1,$2,coalesce(nullif($3,''),'info'),$4,$5,$6)`,
		ev.RunID, ev.Seq, ev.Level, ev.Kind, ev.Message, payload); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return ev.Seq, nil
}

// EventsAfter 拉取 seq > afterSeq 的事件，供 WebSocket 断线续传。
func (s *Sentinel) EventsAfter(ctx context.Context, runID, afterSeq int64, limit int) ([]*SentinelRunEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := s.pool().Query(ctx, `
		select id, run_id, seq, level, kind, message, payload, created_at
		  from run_event
		 where run_id = $1 and seq > $2
		 order by seq asc limit $3`, runID, afterSeq, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]*SentinelRunEvent, 0, limit)
	for rows.Next() {
		var ev SentinelRunEvent
		if err := rows.Scan(&ev.ID, &ev.RunID, &ev.Seq, &ev.Level, &ev.Kind,
			&ev.Message, &ev.Payload, &ev.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, &ev)
	}
	return items, rows.Err()
}

// InsertAudit 写域内审计（仓库增删改、手动触发采集/判定）。
func (s *Sentinel) InsertAudit(ctx context.Context, actor, action, target string, detail map[string]interface{}) error {
	payload := json.RawMessage("{}")
	if len(detail) > 0 {
		if b, err := json.Marshal(detail); err == nil {
			payload = b
		}
	}
	_, err := s.pool().Exec(ctx,
		`insert into audit (actor, action, target, detail) values ($1,$2,$3,$4)`,
		actor, action, target, payload)
	return err
}

// Overview 聚合总览数字。queues 由调用方传入（避免 repo 层耦合队列名常量）。
func (s *Sentinel) Overview(ctx context.Context, queues []string) (*SentinelOverview, error) {
	var o SentinelOverview
	if err := s.pool().QueryRow(ctx, `
		select (select count(*) from repo),
		       (select count(*) from commit where committed_at >= date_trunc('day', now())),
		       (select count(*) from judgment where is_security_fix),
		       (select count(*) from commit where status = 'pending')`).
		Scan(&o.RepoCount, &o.TodayCommits, &o.SecurityFixes, &o.PendingCommits); err != nil {
		return nil, err
	}
	// river_job 由 River 迁移建表；未迁移时不影响总览，只把积压记为 0。
	if len(queues) > 0 {
		if err := s.pool().QueryRow(ctx, `
			select count(*) from river_job
			 where queue = any($1)
			   and state in ('available','pending','retryable','scheduled','running')`,
			queues).Scan(&o.QueueBacklog); err != nil {
			o.QueueBacklog = 0
		}
	}
	return &o, nil
}
