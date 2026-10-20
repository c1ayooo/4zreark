package repo

import (
	"context"
	"time"

	"github.com/c1ayooo/4zreark/models"
)

// AuditRepo 写操作审计日志（operation_logs）。
type AuditRepo interface {
	Add(ctx context.Context, l *models.OperationLog) error
	List(ctx context.Context, limit int) ([]*models.OperationLog, error)
}

type auditRepo struct{ r *Repo }

func (r *auditRepo) Add(ctx context.Context, l *models.OperationLog) error {
	if l == nil {
		return nil
	}
	var userID any
	if !l.UserID.IsZero() {
		userID = l.UserID.Hex()
	}
	created := l.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}

	_, err := r.r.pool.Exec(ctx,
		`insert into operation_logs (user_id, username, action, module, target,
		                             detail, ip, user_agent, status, created_at)
		 values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		userID, l.Username, l.Action, l.Module, l.Target,
		l.Detail, l.IP, l.UserAgent, l.Status, created.UTC())
	return err
}

func (r *auditRepo) List(ctx context.Context, limit int) ([]*models.OperationLog, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := r.r.pool.Query(ctx,
		`select id, user_id, username, action, module, target, detail, ip, user_agent,
		        status, created_at
		   from operation_logs order by created_at desc limit $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*models.OperationLog{}
	for rows.Next() {
		var (
			l         models.OperationLog
			id        int64
			userID    *string
			createdAt time.Time
		)
		if err := rows.Scan(&id, &userID, &l.Username, &l.Action, &l.Module, &l.Target,
			&l.Detail, &l.IP, &l.UserAgent, &l.Status, &createdAt); err != nil {
			return nil, err
		}
		l.ID = id
		if userID != nil {
			if l.UserID, err = objectIDFromHex(*userID); err != nil {
				return nil, err
			}
		}
		l.CreatedAt = timeFromPG(&createdAt)
		out = append(out, &l)
	}
	return out, rows.Err()
}
