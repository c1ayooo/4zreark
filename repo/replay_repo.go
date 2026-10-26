package repo

import (
	"context"
	"encoding/json"

	"github.com/c1ayooo/4zreark/models"
)

// 历史扫描结果回放（M4 剩余项）：读出 scan_results 里的 Web/端口类结果，
// 交给 AssetService.Ingest 生成 raw_records/sites。
//
// 回放范围由任务创建时勾选的扫描类型决定（端口/URL/指纹/图标），
// vuln 不进入资产域。

type ReplayTask struct {
	ID        string
	ProjectID int64
	Type      models.TaskType
	Config    models.TaskConfig
}

type ReplayRow struct {
	ID   string
	Type string
	Data []byte
}

type ReplayRepo interface {
	Tasks(ctx context.Context, projectID int64, limit int) ([]ReplayTask, error)
	Results(ctx context.Context, taskID string, limit int) ([]ReplayRow, error)
}

type replayRepo struct{ r *Repo }

func (r *Repo) Replay() ReplayRepo { return &replayRepo{r: r} }

func (r *replayRepo) Tasks(ctx context.Context, projectID int64, limit int) ([]ReplayTask, error) {
	if limit <= 0 || limit > 5000 {
		limit = 1000
	}
	rows, err := r.r.pool.Query(ctx, `
select id, project_id, type, config
  from tasks
 where project_id > 0 and ($1 = 0 or project_id = $1)
 order by created_at
 limit $2`, projectID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []ReplayTask{}
	for rows.Next() {
		var t ReplayTask
		var cfg []byte
		if err := rows.Scan(&t.ID, &t.ProjectID, &t.Type, &cfg); err != nil {
			return nil, err
		}
		if len(cfg) > 0 {
			_ = json.Unmarshal(cfg, &t.Config)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (r *replayRepo) Results(ctx context.Context, taskID string, limit int) ([]ReplayRow, error) {
	if limit <= 0 || limit > 20000 {
		limit = 5000
	}
	rows, err := r.r.pool.Query(ctx, `
select id, type, data
  from scan_results
 where task_id = $1
 order by created_at
 limit $2`, taskID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []ReplayRow{}
	for rows.Next() {
		var row ReplayRow
		if err := rows.Scan(&row.ID, &row.Type, &row.Data); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}
