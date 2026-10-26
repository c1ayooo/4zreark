package repo

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/models"

	"github.com/c1ayooo/4zreark/oid"
	"github.com/jackc/pgx/v5"
)

// CruiseRepo 是巡航任务与执行日志的仓储入口。
type CruiseRepo interface {
	Create(ctx context.Context, c *models.CruiseTask) error
	Get(ctx context.Context, id string) (*models.CruiseTask, error)
	List(ctx context.Context, workspaceID string, page, pageSize int, search string) ([]*models.CruiseTask, int64, error)
	ListEnabled(ctx context.Context) ([]*models.CruiseTask, error)
	UpdateFields(ctx context.Context, id string, fields map[string]any) error
	Delete(ctx context.Context, id string) error

	SetStatus(ctx context.Context, id, status string) error
	// SetStatusIfRunning 仅当当前仍为 running 时改为目标状态，返回是否生效。
	// 巡航结束「恢复快照状态」专用：执行期间用户 enable/disable 的结果优先，
	// 无条件覆写会造成「显示已启用但 cron entry 已删、永远不再调度」的僵尸态。
	SetStatusIfRunning(ctx context.Context, id, status string) (bool, error)
	// AcquireRun 原子地把巡航从非 running 置为 running，返回是否抢到。
	// cron 触发与「立即执行」并发时只允许一个通过，替代先读后写的 TOCTOU 检查。
	AcquireRun(ctx context.Context, id string) (bool, error)
	// ResetStaleRunning 把所有 running 巡航复位为 enabled，返回复位条数。
	// 只在服务启动时调用：进程刚启动不可能有在跑的巡航，卡在 running 的是
	// 上次崩溃的残留——不回收的话 ListEnabled 查不到它，调度与「立即执行」都被永久拒绝。
	ResetStaleRunning(ctx context.Context) (int64, error)
	SetNextRun(ctx context.Context, id string, next time.Time) error
	// MarkRun 记一次执行：run_count+1，同时更新最近执行时间与任务 ID。
	MarkRun(ctx context.Context, id, taskID string, at time.Time) error
	SetLastStatus(ctx context.Context, id, status string) error
	IncrSuccess(ctx context.Context, id string) error
	IncrFail(ctx context.Context, id string) error

	// AddLog 写一条执行日志，返回自增 ID。
	AddLog(ctx context.Context, l *models.CruiseLog) (string, error)
	// FinishLog 按 (cruise_id, task_id) 回填结束状态；同一任务只会有一条 running 记录。
	FinishLog(ctx context.Context, cruiseID, taskID, status string, end time.Time,
		duration int64, resultCount, vulnCount int, errMsg string) error
	ListLogs(ctx context.Context, cruiseID string, page, pageSize int) ([]*models.CruiseLog, int64, error)
	Stats(ctx context.Context, workspaceID string) (total, enabled, running int64, err error)
}

type cruiseRepo struct{ r *Repo }

const cruiseColumns = `id, workspace_id, project_id, target_source, name, description, status,
	cron_expr, timezone, targets, target_type, task_type, config, notify_on_complete, notify_on_vuln,
	notify_channels, last_run_at, next_run_at, run_count, success_count, fail_count,
	last_task_id, last_status, created_by, tags, created_at, updated_at`

var cruiseUpdatable = map[string]string{
	"project_id":         "project_id",
	"target_source":      "target_source",
	"name":               "name",
	"description":        "description",
	"status":             "status",
	"cron_expr":          "cron_expr",
	"timezone":           "timezone",
	"targets":            "targets",
	"target_type":        "target_type",
	"task_type":          "task_type",
	"config":             "config",
	"notify_on_complete": "notify_on_complete",
	"notify_on_vuln":     "notify_on_vuln",
	"notify_channels":    "notify_channels",
	"last_run_at":        "last_run_at",
	"next_run_at":        "next_run_at",
	"last_task_id":       "last_task_id",
	"last_status":        "last_status",
	"tags":               "tags",
}

var cruiseColumnConv = map[string]func(any) (any, error){
	"targets":         textArrayValue,
	"notify_channels": textArrayValue,
	"tags":            textArrayValue,
	"config":          jsonbValue,
	"status":          stringValue,
	"task_type":       stringValue,
	"last_run_at":     timeValue,
	"next_run_at":     timeValue,
	"last_task_id":    stringValue,
	"last_status":     stringValue,
}

func scanCruise(row pgx.Row) (*models.CruiseTask, error) {
	var (
		c            models.CruiseTask
		hexID        string
		wsID         string
		targetSource string
		status       string
		taskType     string
		cfgB         []byte
		lastRun      *time.Time
		nextRun      *time.Time
		createdB     *string
		created      time.Time
		updated      time.Time
	)
	err := row.Scan(&hexID, &wsID, &c.ProjectID, &targetSource, &c.Name, &c.Description, &status, &c.CronExpr, &c.Timezone,
		&c.Targets, &c.TargetType, &taskType, &cfgB, &c.NotifyOnComplete, &c.NotifyOnVuln,
		&c.NotifyChannels, &lastRun, &nextRun, &c.RunCount, &c.SuccessCount, &c.FailCount,
		&c.LastTaskID, &c.LastStatus, &createdB, &c.Tags, &created, &updated)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if c.ID, err = objectIDFromHex(hexID); err != nil {
		return nil, err
	}
	if c.WorkspaceID, err = objectIDFromHex(wsID); err != nil {
		return nil, err
	}
	c.TargetSource = targetSource
	if c.TargetSource == "" {
		c.TargetSource = models.CruiseTargetSourceStatic
	}
	if createdB != nil {
		if c.CreatedBy, err = objectIDFromHex(*createdB); err != nil {
			return nil, err
		}
	}
	c.Status = models.CruiseStatus(status)
	c.TaskType = models.TaskType(taskType)
	if len(cfgB) > 0 {
		_ = jsonUnmarshal(cfgB, &c.Config)
	}
	c.LastRunAt = timeFromPG(lastRun)
	c.NextRunAt = timeFromPG(nextRun)
	c.CreatedAt = timeFromPG(&created)
	c.UpdatedAt = timeFromPG(&updated)
	return &c, nil
}

func (r *cruiseRepo) Create(ctx context.Context, c *models.CruiseTask) error {
	if c.ID.IsZero() {
		c.ID = oid.NewObjectID()
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now()
	}
	if c.UpdatedAt.IsZero() {
		c.UpdatedAt = c.CreatedAt
	}
	if c.Timezone == "" {
		c.Timezone = "Asia/Shanghai"
	}
	if c.TargetSource == "" {
		c.TargetSource = models.CruiseTargetSourceStatic
	}
	cfg, err := jsonb(c.Config)
	if err != nil {
		return err
	}

	_, err = r.r.pool.Exec(ctx,
		`insert into cruise_tasks (`+cruiseColumns+`)
		 values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,
		         $19,$20,$21,$22,$23,$24,$25,$26,$27)`,
		c.ID.Hex(), workspaceIDHex(c.WorkspaceID), c.ProjectID, c.TargetSource,
		c.Name, c.Description, string(c.Status),
		c.CronExpr, c.Timezone, textArray(c.Targets), c.TargetType, string(c.TaskType), cfg,
		c.NotifyOnComplete, c.NotifyOnVuln, textArray(c.NotifyChannels),
		timeToPG(c.LastRunAt), timeToPG(c.NextRunAt), c.RunCount, c.SuccessCount, c.FailCount,
		c.LastTaskID, c.LastStatus, objectIDOrNil(c.CreatedBy), textArray(c.Tags),
		c.CreatedAt.UTC(), c.UpdatedAt.UTC())
	return err
}

func (r *cruiseRepo) Get(ctx context.Context, id string) (*models.CruiseTask, error) {
	if _, err := idFromString(id); err != nil {
		return nil, ErrNotFound
	}
	return scanCruise(r.r.pool.QueryRow(ctx, `select `+cruiseColumns+` from cruise_tasks where id = $1`, id))
}

func (r *cruiseRepo) List(ctx context.Context, workspaceID string, page, pageSize int, search string) ([]*models.CruiseTask, int64, error) {
	page, pageSize = vulnPage(page, pageSize)
	kw := strings.TrimSpace(search)
	args := []any{workspaceID, kw, likePattern(kw)}

	const where = `where ($1 = '' or workspace_id = $1)
	                 and ($2 = '' or name ilike $3 or description ilike $3)`

	var total int64
	if err := r.r.pool.QueryRow(ctx, `select count(*) from cruise_tasks `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := r.r.pool.Query(ctx,
		`select `+cruiseColumns+` from cruise_tasks `+where+`
		  order by created_at desc limit $4 offset $5`,
		append(args, pageSize, (page-1)*pageSize)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := []*models.CruiseTask{}
	for rows.Next() {
		c, err := scanCruise(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, c)
	}
	return out, total, rows.Err()
}

func (r *cruiseRepo) ListEnabled(ctx context.Context) ([]*models.CruiseTask, error) {
	rows, err := r.r.pool.Query(ctx,
		`select `+cruiseColumns+` from cruise_tasks where status = 'enabled' order by created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*models.CruiseTask{}
	for rows.Next() {
		c, err := scanCruise(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (r *cruiseRepo) UpdateFields(ctx context.Context, id string, fields map[string]any) error {
	if _, err := idFromString(id); err != nil {
		return ErrNotFound
	}
	if len(fields) == 0 {
		return nil
	}

	sets := make([]string, 0, len(fields)+1)
	args := make([]any, 0, len(fields)+2)
	i := 1
	for k, v := range fields {
		col, ok := cruiseUpdatable[k]
		if !ok {
			continue
		}
		val := v
		if c, ok := cruiseColumnConv[col]; ok && c != nil {
			var err error
			if val, err = c(v); err != nil {
				return fmt.Errorf("字段 %s 取值非法: %w", k, err)
			}
		}
		sets = append(sets, fmt.Sprintf("%s = $%d", col, i))
		args = append(args, val)
		i++
	}
	if len(sets) == 0 {
		return nil
	}
	sets = append(sets, "updated_at = now()")
	args = append(args, id)

	tag, err := r.r.pool.Exec(ctx,
		"update cruise_tasks set "+strings.Join(sets, ", ")+fmt.Sprintf(" where id = $%d", i), args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *cruiseRepo) Delete(ctx context.Context, id string) error {
	if _, err := idFromString(id); err != nil {
		return ErrNotFound
	}
	tx, err := r.r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `delete from cruise_logs where cruise_id = $1`, id); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `delete from cruise_tasks where id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return tx.Commit(ctx)
}

func (r *cruiseRepo) SetStatus(ctx context.Context, id, status string) error {
	tag, err := r.r.pool.Exec(ctx,
		`update cruise_tasks set status = $2, updated_at = now() where id = $1`, id, status)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *cruiseRepo) SetStatusIfRunning(ctx context.Context, id, status string) (bool, error) {
	tag, err := r.r.pool.Exec(ctx,
		`update cruise_tasks set status = $2, updated_at = now() where id = $1 and status = 'running'`, id, status)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func (r *cruiseRepo) AcquireRun(ctx context.Context, id string) (bool, error) {
	tag, err := r.r.pool.Exec(ctx,
		`update cruise_tasks set status = 'running', updated_at = now()
		  where id = $1 and status <> 'running'`, id)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func (r *cruiseRepo) ResetStaleRunning(ctx context.Context) (int64, error) {
	tag, err := r.r.pool.Exec(ctx,
		`update cruise_tasks set status = 'enabled', updated_at = now() where status = 'running'`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (r *cruiseRepo) SetNextRun(ctx context.Context, id string, next time.Time) error {
	_, err := r.r.pool.Exec(ctx,
		`update cruise_tasks set next_run_at = $2, updated_at = now() where id = $1`, id, next.UTC())
	return err
}

func (r *cruiseRepo) MarkRun(ctx context.Context, id, taskID string, at time.Time) error {
	_, err := r.r.pool.Exec(ctx,
		`update cruise_tasks
		    set last_run_at = $2, last_task_id = $3, run_count = run_count + 1, updated_at = now()
		  where id = $1`, id, at.UTC(), taskID)
	return err
}

func (r *cruiseRepo) SetLastStatus(ctx context.Context, id, status string) error {
	_, err := r.r.pool.Exec(ctx,
		`update cruise_tasks set last_status = $2, updated_at = now() where id = $1`, id, status)
	return err
}

func (r *cruiseRepo) IncrSuccess(ctx context.Context, id string) error {
	_, err := r.r.pool.Exec(ctx,
		`update cruise_tasks set success_count = success_count + 1, updated_at = now() where id = $1`, id)
	return err
}

func (r *cruiseRepo) IncrFail(ctx context.Context, id string) error {
	_, err := r.r.pool.Exec(ctx,
		`update cruise_tasks set fail_count = fail_count + 1, updated_at = now() where id = $1`, id)
	return err
}

func (r *cruiseRepo) AddLog(ctx context.Context, l *models.CruiseLog) (string, error) {
	var id int64
	err := r.r.pool.QueryRow(ctx,
		`insert into cruise_logs (cruise_id, task_id, status, start_time, end_time,
		                          duration, result_count, vuln_count, error, created_at)
		 values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		 returning id`,
		l.CruiseID.Hex(), objectIDOrNil(l.TaskID), l.Status,
		timeToPG(l.StartTime), timeToPG(l.EndTime), l.Duration,
		l.ResultCount, l.VulnCount, l.Error,
		timeOrNow(l.CreatedAt)).Scan(&id)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d", id), nil
}

func (r *cruiseRepo) FinishLog(ctx context.Context, cruiseID, taskID, status string, end time.Time,
	duration int64, resultCount, vulnCount int, errMsg string) error {

	// 只回填最近一条 running 记录：同一任务重复触发时不会把历史记录一起改掉。
	_, err := r.r.pool.Exec(ctx, `
		update cruise_logs
		   set status = $3, end_time = $4, duration = $5,
		       result_count = $6, vuln_count = $7, error = $8
		 where id = (select id from cruise_logs
		              where cruise_id = $1 and task_id = $2
		              order by id desc limit 1)`,
		cruiseID, taskID, status, timeToPG(end), duration, resultCount, vulnCount, errMsg)
	return err
}

func (r *cruiseRepo) ListLogs(ctx context.Context, cruiseID string, page, pageSize int) ([]*models.CruiseLog, int64, error) {
	if _, err := idFromString(cruiseID); err != nil {
		return nil, 0, ErrNotFound
	}
	page, pageSize = vulnPage(page, pageSize)

	var total int64
	if err := r.r.pool.QueryRow(ctx,
		`select count(*) from cruise_logs where cruise_id = $1`, cruiseID).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := r.r.pool.Query(ctx,
		`select id, cruise_id, task_id, status, start_time, end_time, duration,
		        result_count, vuln_count, error, created_at
		   from cruise_logs where cruise_id = $1
		  order by created_at desc limit $2 offset $3`,
		cruiseID, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := []*models.CruiseLog{}
	for rows.Next() {
		var (
			l       models.CruiseLog
			id      int64
			cID     string
			tID     *string
			start   *time.Time
			end     *time.Time
			created time.Time
		)
		if err := rows.Scan(&id, &cID, &tID, &l.Status, &start, &end, &l.Duration,
			&l.ResultCount, &l.VulnCount, &l.Error, &created); err != nil {
			return nil, 0, err
		}
		l.ID = fmt.Sprintf("%d", id)
		if l.CruiseID, err = objectIDFromHex(cID); err != nil {
			return nil, 0, err
		}
		if tID != nil {
			if l.TaskID, err = objectIDFromHex(*tID); err != nil {
				return nil, 0, err
			}
		}
		l.StartTime = timeFromPG(start)
		l.EndTime = timeFromPG(end)
		l.CreatedAt = timeFromPG(&created)
		out = append(out, &l)
	}
	return out, total, rows.Err()
}

func (r *cruiseRepo) Stats(ctx context.Context, workspaceID string) (int64, int64, int64, error) {
	var total, enabled, running int64
	err := r.r.pool.QueryRow(ctx,
		`select count(*),
		        count(*) filter (where status = 'enabled'),
		        count(*) filter (where status = 'running')
		   from cruise_tasks where ($1 = '' or workspace_id = $1)`, workspaceID).
		Scan(&total, &enabled, &running)
	return total, enabled, running, err
}
