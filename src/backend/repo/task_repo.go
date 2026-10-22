package repo

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/models"

	"github.com/c1ayooo/4zreark/oid"
	"github.com/jackc/pgx/v5"
)

// TaskRepo 是 tasks / task_templates / task_logs 的唯一数据入口。
type TaskRepo interface {
	Create(ctx context.Context, t *models.Task) error
	GetByID(ctx context.Context, id string) (*models.Task, error)
	List(ctx context.Context, workspaceID, taskType, status string, projectID int64, page, pageSize int) ([]*models.Task, int64, error)
	ListCursor(ctx context.Context, workspaceID, taskType, status string, projectID int64, cursor string, pageSize int) ([]*models.Task, string, bool, error)
	ListStaleRunning(ctx context.Context, nodeHeartbeatBefore, taskIdleBefore, hardBefore time.Time) ([]*models.Task, error)
	UpdateFields(ctx context.Context, id string, fields map[string]any) error
	Delete(ctx context.Context, id string) error
	StatusCounts(ctx context.Context, workspaceID string) (map[string]int, error)

	CreateTemplate(ctx context.Context, t *models.TaskTemplate) error
	ListTemplates(ctx context.Context, workspaceID string, isPublic *bool) ([]*models.TaskTemplate, error)
	GetTemplate(ctx context.Context, id string) (*models.TaskTemplate, error)
	UpdateTemplate(ctx context.Context, t *models.TaskTemplate) error
	DeleteTemplate(ctx context.Context, id string) error

	AddLog(ctx context.Context, taskID, level, message, detail string) error
	ListLogs(ctx context.Context, taskID string, page, pageSize int) ([]*models.TaskLog, int64, error)
}

type taskRepo struct{ r *Repo }

const taskColumns = `id, workspace_id, project_id, name, description, type, status, targets, target_type,
	config, is_scheduled, cron_expr, progress, node_id, started_at, completed_at,
	total_targets, scanned_targets, discovered_assets, discovered_vulns, discovered_ports,
	last_scanned_index, completed_stages, retry_count, last_error, created_by, tags,
	created_at, updated_at, progress_details`

// taskUpdatable 是 UpdateTask 允许落库的列白名单。
// 键来自 HTTP 请求体或内部调用，必须映射到固定列名，绝不拼原始键。
var taskUpdatable = map[string]string{
	"project_id":         "project_id",
	"name":               "name",
	"description":        "description",
	"type":               "type",
	"status":             "status",
	"targets":            "targets",
	"target_type":        "target_type",
	"config":             "config",
	"is_scheduled":       "is_scheduled",
	"cron_expr":          "cron_expr",
	"progress":           "progress",
	"node_id":            "node_id",
	"started_at":         "started_at",
	"completed_at":       "completed_at",
	"retry_count":        "retry_count",
	"last_error":         "last_error",
	"created_by":         "created_by",
	"tags":               "tags",
	"progress_details":   "progress_details",
	"total_targets":      "total_targets",
	"scanned_targets":    "scanned_targets",
	"discovered_assets":  "discovered_assets",
	"discovered_vulns":   "discovered_vulns",
	"discovered_ports":   "discovered_ports",
	"last_scanned_index": "last_scanned_index",
	"completed_stages":   "completed_stages",
}

// 需要特殊转换的列：jsonb / text[] / 时间 / 枚举
var taskColumnConv = map[string]func(any) (any, error){
	"config":           jsonbValue,
	"progress_details": jsonbValue,
	"targets":          textArrayValue,
	"tags":             textArrayValue,
	"completed_stages": textArrayValue,
	"started_at":       timeValue,
	"completed_at":     timeValue,
	"type":             stringValue,
	"status":           stringValue,
	"created_by":       objectIDValue,
}

func jsonbValue(v any) (any, error) {
	if v == nil {
		return []byte("{}"), nil
	}
	return jsonb(v)
}

func textArrayValue(v any) (any, error) {
	switch x := v.(type) {
	case nil:
		return []string{}, nil
	case []string:
		return textArray(x), nil
	case []any:
		out := make([]string, 0, len(x))
		for _, item := range x {
			out = append(out, fmt.Sprint(item))
		}
		return out, nil
	case string:
		if x == "" {
			return []string{}, nil
		}
		return []string{x}, nil
	default:
		return nil, fmt.Errorf("无法转成 text[]: %T", v)
	}
}

func timeValue(v any) (any, error) {
	switch x := v.(type) {
	case nil:
		return nil, nil
	case time.Time:
		return timeToPG(x), nil
	case *time.Time:
		if x == nil {
			return nil, nil
		}
		return timeToPG(*x), nil
	default:
		return nil, fmt.Errorf("无法转成 timestamptz: %T", v)
	}
}

func stringValue(v any) (any, error) {
	switch x := v.(type) {
	case nil:
		return "", nil
	case string:
		return x, nil
	case []byte:
		return string(x), nil
	case fmt.Stringer:
		return x.String(), nil
	default:
		// models.TaskType / models.TaskStatus 这类底层为 string 的枚举
		return fmt.Sprint(x), nil
	}
}

func objectIDValue(v any) (any, error) {
	switch x := v.(type) {
	case nil:
		return nil, nil
	case oid.ObjectID:
		if x.IsZero() {
			return nil, nil
		}
		return x.Hex(), nil
	case string:
		if x == "" || x == "000000000000000000000000" {
			return nil, nil
		}
		return x, nil
	case *oid.ObjectID:
		if x == nil || x.IsZero() {
			return nil, nil
		}
		return x.Hex(), nil
	default:
		return nil, fmt.Errorf("无法转成 char(24): %T", v)
	}
}

func scanTask(row pgx.Row) (*models.Task, error) {
	var (
		hexID       string
		wsID        string
		t           models.Task
		typeStr     string
		statusStr   string
		configB     []byte
		startedAt   *time.Time
		completedAt *time.Time
		stats       models.TaskResultStats
		createdBy   *string
		createdAt   time.Time
		updatedAt   time.Time
		detailsB    []byte
	)
	err := row.Scan(&hexID, &wsID, &t.ProjectID, &t.Name, &t.Description, &typeStr, &statusStr, &t.Targets,
		&t.TargetType, &configB, &t.IsScheduled, &t.CronExpr, &t.Progress, &t.NodeID,
		&startedAt, &completedAt,
		&stats.TotalTargets, &stats.ScannedTargets, &stats.DiscoveredAssets,
		&stats.DiscoveredVulns, &stats.DiscoveredPorts, &stats.LastScannedIndex,
		&stats.CompletedStages, &t.RetryCount, &t.LastError, &createdBy, &t.Tags,
		&createdAt, &updatedAt, &detailsB)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	if t.ID, err = objectIDFromHex(hexID); err != nil {
		return nil, err
	}
	if t.WorkspaceID, err = objectIDFromHex(wsID); err != nil {
		return nil, err
	}
	if createdBy != nil {
		if t.CreatedBy, err = objectIDFromHex(*createdBy); err != nil {
			return nil, err
		}
	}
	t.Type = models.TaskType(typeStr)
	t.Status = models.TaskStatus(statusStr)
	t.ResultStats = stats
	t.StartedAt = timeFromPG(startedAt)
	t.CompletedAt = timeFromPG(completedAt)
	t.CreatedAt = timeFromPG(&createdAt)
	t.UpdatedAt = timeFromPG(&updatedAt)

	if len(configB) > 0 && string(configB) != "{}" {
		if err := json.Unmarshal(configB, &t.Config); err != nil {
			return nil, fmt.Errorf("解析任务配置失败: %w", err)
		}
	}
	if len(detailsB) > 0 && string(detailsB) != "{}" {
		if err := json.Unmarshal(detailsB, &t.ProgressDetails); err != nil {
			return nil, fmt.Errorf("解析任务进度详情失败: %w", err)
		}
	}
	return &t, nil
}

// objectIDFromHex 把库里读出的 24 位十六进制转成 ObjectID；全零按零值处理。
func objectIDFromHex(s string) (oid.ObjectID, error) {
	if s == "" || s == "000000000000000000000000" {
		return oid.NilObjectID, nil
	}
	parsed, err := oid.ObjectIDFromHex(s)
	if err != nil {
		return oid.NilObjectID, fmt.Errorf("库里的 id 不是合法 ObjectID: %s", s)
	}
	return parsed, nil
}

func (r *taskRepo) Create(ctx context.Context, t *models.Task) error {
	configB, err := jsonb(t.Config)
	if err != nil {
		return fmt.Errorf("序列化任务配置失败: %w", err)
	}
	detailsB, err := jsonb(t.ProgressDetails)
	if err != nil {
		return fmt.Errorf("序列化任务进度详情失败: %w", err)
	}

	_, err = r.r.pool.Exec(ctx,
		`insert into tasks (id, workspace_id, project_id, name, description, type, status, targets, target_type,
		                    config, is_scheduled, cron_expr, progress, node_id, started_at, completed_at,
		                    total_targets, scanned_targets, discovered_assets, discovered_vulns,
		                    discovered_ports, last_scanned_index, completed_stages, retry_count,
		                    last_error, created_by, tags, created_at, updated_at, progress_details)
		 values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30)`,
		t.ID.Hex(), workspaceIDHex(t.WorkspaceID), t.ProjectID, t.Name, t.Description, string(t.Type), string(t.Status),
		textArray(t.Targets), t.TargetType, configB, t.IsScheduled, t.CronExpr, t.Progress, t.NodeID,
		timeToPG(t.StartedAt), timeToPG(t.CompletedAt),
		t.ResultStats.TotalTargets, t.ResultStats.ScannedTargets, t.ResultStats.DiscoveredAssets,
		t.ResultStats.DiscoveredVulns, t.ResultStats.DiscoveredPorts, t.ResultStats.LastScannedIndex,
		textArray(t.ResultStats.CompletedStages), t.RetryCount, t.LastError,
		objectIDOrNil(t.CreatedBy), textArray(t.Tags), timeToPG(t.CreatedAt), timeToPG(t.UpdatedAt),
		detailsB)
	if err != nil {
		return err
	}
	return nil
}

// workspaceIDHex 把零值 workspace 落成 DDL 里的默认值，避免写 NULL。
func workspaceIDHex(id oid.ObjectID) string {
	if id.IsZero() {
		return "000000000000000000000000"
	}
	return id.Hex()
}

func objectIDOrNil(id oid.ObjectID) any {
	if id.IsZero() {
		return nil
	}
	return id.Hex()
}

func (r *taskRepo) GetByID(ctx context.Context, id string) (*models.Task, error) {
	if _, err := idFromString(id); err != nil {
		return nil, ErrNotFound
	}
	return scanTask(r.r.pool.QueryRow(ctx, `select `+taskColumns+` from tasks where id = $1`, id))
}

func (r *taskRepo) List(ctx context.Context, workspaceID, taskType, status string, projectID int64, page, pageSize int) ([]*models.Task, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	const where = `where ($1 = '' or workspace_id = $1)
	                 and ($2 = '' or type = $2)
	                 and ($3 = '' or status = $3)
	                 and ($4 = 0 or project_id = $4)`

	var total int64
	if err := r.r.pool.QueryRow(ctx, `select count(*) from tasks `+where,
		workspaceID, taskType, status, projectID).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := r.r.pool.Query(ctx,
		`select `+taskColumns+` from tasks `+where+`
		  order by created_at desc
		  limit $5 offset $6`,
		workspaceID, taskType, status, projectID, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var tasks []*models.Task
	for rows.Next() {
		t, err := scanTask(rows)
		if err != nil {
			return nil, 0, err
		}
		tasks = append(tasks, t)
	}
	return tasks, total, rows.Err()
}

// EncodeTaskCursor 用 (created_at, id) 作为 keyset 游标，避免 offset + count。
func encodeTaskCursor(t time.Time, id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(t.UTC().Format(time.RFC3339Nano) + "|" + id))
}

func decodeTaskCursor(s string) (time.Time, string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return time.Time{}, "", err
	}
	parts := strings.SplitN(string(raw), "|", 2)
	if len(parts) != 2 {
		return time.Time{}, "", fmt.Errorf("invalid cursor")
	}
	t, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		return time.Time{}, "", err
	}
	return t, parts[1], nil
}

// ListCursor 返回下一页任务；next 为空表示到底。
func (r *taskRepo) ListCursor(ctx context.Context, workspaceID, taskType, status string, projectID int64, cursor string, pageSize int) ([]*models.Task, string, bool, error) {
	if pageSize < 1 || pageSize > 100 {
		pageSize = 10
	}
	where := `where ($1 = '' or workspace_id = $1)
	                 and ($2 = '' or type = $2)
	                 and ($3 = '' or status = $3)
	                 and ($4 = 0 or project_id = $4)`
	args := []any{workspaceID, taskType, status, projectID}
	if cursor != "" {
		t, id, err := decodeTaskCursor(cursor)
		if err != nil {
			return nil, "", false, fmt.Errorf("分页游标无效: %w", err)
		}
		args = append(args, t, id)
		where += fmt.Sprintf(" and (created_at, id) < ($%d, $%d)", len(args)-1, len(args))
	}
	args = append(args, pageSize+1)
	rows, err := r.r.pool.Query(ctx,
		`select `+taskColumns+` from tasks `+where+`
		  order by created_at desc, id desc
		  limit $`+strconv.Itoa(len(args)), args...)
	if err != nil {
		return nil, "", false, err
	}
	defer rows.Close()

	tasks := make([]*models.Task, 0, pageSize+1)
	for rows.Next() {
		t, err := scanTask(rows)
		if err != nil {
			return nil, "", false, err
		}
		tasks = append(tasks, t)
	}
	if err := rows.Err(); err != nil {
		return nil, "", false, err
	}
	hasMore := len(tasks) > pageSize
	if hasMore {
		tasks = tasks[:pageSize]
	}
	next := ""
	if len(tasks) > 0 {
		last := tasks[len(tasks)-1]
		next = encodeTaskCursor(last.CreatedAt, last.ID.Hex())
	}
	return tasks, next, hasMore, nil
}

// ListStaleRunning 找出执行节点已离线、或长时间没有任何进展的 running 任务。
// 节点离线要额外等 taskIdleBefore，避免节点刚重启的几秒内误杀。
func (r *taskRepo) ListStaleRunning(ctx context.Context, nodeHeartbeatBefore, taskIdleBefore, hardBefore time.Time) ([]*models.Task, error) {
	qualified := "t." + strings.ReplaceAll(taskColumns, ",", ", t.")
	rows, err := r.r.pool.Query(ctx,
		`select `+qualified+`
		   from tasks t
		   left join scanner_nodes n on n.node_id = t.node_id
		  where t.status = 'running'
		    and (
		      (t.node_id <> ''
		       and (n.node_id is null or n.status not in ('online','busy') or n.last_heartbeat < $1)
		       and t.updated_at < $2)
		      or t.updated_at < $3
		    )
		  order by t.updated_at asc
		  limit 200`, nodeHeartbeatBefore, taskIdleBefore, hardBefore)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]*models.Task, 0, 16)
	for rows.Next() {
		t, err := scanTask(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (r *taskRepo) UpdateFields(ctx context.Context, id string, fields map[string]any) error {
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
		col, ok := taskUpdatable[k]
		if !ok {
			continue
		}
		val := v
		if conv, ok := taskColumnConv[col]; ok {
			var err error
			if val, err = conv(v); err != nil {
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

	stmt := "update tasks set " + strings.Join(sets, ", ") + fmt.Sprintf(" where id = $%d", i)
	tag, err := r.r.pool.Exec(ctx, stmt, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *taskRepo) Delete(ctx context.Context, id string) error {
	if _, err := idFromString(id); err != nil {
		return ErrNotFound
	}
	tx, err := r.r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// 任务删掉后，挂在它下面的作业必须一起清，否则 worker 会领到孤儿作业
	if _, err := tx.Exec(ctx, `delete from task_jobs where task_id = $1`, id); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `delete from tasks where id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return tx.Commit(ctx)
}

func (r *taskRepo) StatusCounts(ctx context.Context, workspaceID string) (map[string]int, error) {
	rows, err := r.r.pool.Query(ctx,
		`select status, count(*) from tasks where ($1 = '' or workspace_id = $1) group by status`, workspaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]int{}
	for rows.Next() {
		var (
			s string
			n int
		)
		if err := rows.Scan(&s, &n); err != nil {
			return nil, err
		}
		out[s] = n
	}
	return out, rows.Err()
}

// --- 任务模板 ---

const templateColumns = `id, workspace_id, name, description, type, config, is_public, created_by, created_at, updated_at`

func scanTemplate(row pgx.Row) (*models.TaskTemplate, error) {
	var (
		hexID     string
		wsID      string
		t         models.TaskTemplate
		typeStr   string
		configB   []byte
		createdBy *string
		createdAt time.Time
		updatedAt time.Time
	)
	err := row.Scan(&hexID, &wsID, &t.Name, &t.Description, &typeStr, &configB, &t.IsPublic,
		&createdBy, &createdAt, &updatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if t.ID, err = objectIDFromHex(hexID); err != nil {
		return nil, err
	}
	if t.WorkspaceID, err = objectIDFromHex(wsID); err != nil {
		return nil, err
	}
	if createdBy != nil {
		if t.CreatedBy, err = objectIDFromHex(*createdBy); err != nil {
			return nil, err
		}
	}
	t.Type = models.TaskType(typeStr)
	t.CreatedAt = timeFromPG(&createdAt)
	t.UpdatedAt = timeFromPG(&updatedAt)
	if len(configB) > 0 && string(configB) != "{}" {
		if err := json.Unmarshal(configB, &t.Config); err != nil {
			return nil, fmt.Errorf("解析模板配置失败: %w", err)
		}
	}
	return &t, nil
}

func (r *taskRepo) CreateTemplate(ctx context.Context, t *models.TaskTemplate) error {
	configB, err := jsonb(t.Config)
	if err != nil {
		return fmt.Errorf("序列化模板配置失败: %w", err)
	}
	_, err = r.r.pool.Exec(ctx,
		`insert into task_templates (id, workspace_id, name, description, type, config, is_public,
		                             created_by, created_at, updated_at)
		 values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		t.ID.Hex(), workspaceIDHex(t.WorkspaceID), t.Name, t.Description, string(t.Type), configB,
		t.IsPublic, objectIDOrNil(t.CreatedBy), timeToPG(t.CreatedAt), timeToPG(t.UpdatedAt))
	return err
}

func (r *taskRepo) ListTemplates(ctx context.Context, workspaceID string, isPublic *bool) ([]*models.TaskTemplate, error) {
	// workspaceID 非空时：本工作区的模板 + 公共模板（与旧版 $or 语义一致）
	publicFilter := any(nil)
	if isPublic != nil {
		publicFilter = *isPublic
	}
	rows, err := r.r.pool.Query(ctx,
		`select `+templateColumns+`
		   from task_templates
		  where ($1 = '' or workspace_id = $1 or is_public = true)
		    and ($2::boolean is null or is_public = $2)
		  order by name`, workspaceID, publicFilter)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*models.TaskTemplate
	for rows.Next() {
		t, err := scanTemplate(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (r *taskRepo) GetTemplate(ctx context.Context, id string) (*models.TaskTemplate, error) {
	if _, err := idFromString(id); err != nil {
		return nil, ErrNotFound
	}
	return scanTemplate(r.r.pool.QueryRow(ctx,
		`select `+templateColumns+` from task_templates where id = $1`, id))
}

func (r *taskRepo) UpdateTemplate(ctx context.Context, t *models.TaskTemplate) error {
	if _, err := idFromString(t.ID.Hex()); err != nil {
		return ErrNotFound
	}
	configB, err := jsonb(t.Config)
	if err != nil {
		return fmt.Errorf("序列化模板配置失败: %w", err)
	}
	tag, err := r.r.pool.Exec(ctx,
		`update task_templates
		    set name = $2, description = $3, type = $4, config = $5, is_public = $6, updated_at = $7
		  where id = $1`,
		t.ID.Hex(), t.Name, t.Description, string(t.Type), configB, t.IsPublic, timeToPG(t.UpdatedAt))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *taskRepo) DeleteTemplate(ctx context.Context, id string) error {
	if _, err := idFromString(id); err != nil {
		return ErrNotFound
	}
	tag, err := r.r.pool.Exec(ctx, `delete from task_templates where id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// --- 任务日志 ---

func (r *taskRepo) AddLog(ctx context.Context, taskID, level, message, detail string) error {
	if _, err := idFromString(taskID); err != nil {
		return ErrNotFound
	}
	_, err := r.r.pool.Exec(ctx,
		`insert into task_logs (task_id, level, message, detail) values ($1,$2,$3,$4)`,
		taskID, level, message, detail)
	return err
}

func (r *taskRepo) ListLogs(ctx context.Context, taskID string, page, pageSize int) ([]*models.TaskLog, int64, error) {
	if _, err := idFromString(taskID); err != nil {
		return nil, 0, ErrNotFound
	}
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}

	var total int64
	if err := r.r.pool.QueryRow(ctx,
		`select count(*) from task_logs where task_id = $1`, taskID).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := r.r.pool.Query(ctx,
		`select id, task_id, level, message, detail, created_at
		   from task_logs
		  where task_id = $1
		  order by created_at desc
		  limit $2 offset $3`, taskID, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var logs []*models.TaskLog
	for rows.Next() {
		var (
			l         models.TaskLog
			id        int64
			tid       string
			createdAt time.Time
		)
		if err := rows.Scan(&id, &tid, &l.Level, &l.Message, &l.Detail, &createdAt); err != nil {
			return nil, 0, err
		}
		l.ID = fmt.Sprintf("%d", id)
		if l.TaskID, err = objectIDFromHex(tid); err != nil {
			return nil, 0, err
		}
		l.CreatedAt = timeFromPG(&createdAt)
		logs = append(logs, &l)
	}
	return logs, total, rows.Err()
}
