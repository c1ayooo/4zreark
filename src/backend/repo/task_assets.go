package repo

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// TaskSite 是「某个任务贡献过的资产」的读模型。
//
// 关联口径（两条并用，任一命中即算该任务贡献）：
//  1. raw_records.task_id —— 精确来源，需要采集侧写入 task_id（当前历史数据为空）；
//  2. scan_results 的 host/subdomain/url 与 sites.host 对齐 —— 兜底口径，
//     保证 task_id 没落库的历史任务也能正确回溯。
//
// 站点是按 host 归并的产物，一次任务通常只贡献其中几条证据，所以这里刻意不按
// sites.task_id（该表没有这一列）过滤，而是回答「这个任务让哪些站点进入了资产库」。
type TaskSite struct {
	ID         int64     `json:"id"`
	Host       string    `json:"host"`
	Port       int       `json:"port"`
	Protocol   string    `json:"protocol"`
	HTTPStatus int       `json:"http_status"`
	Title      string    `json:"title"`
	Tech       []string  `json:"technology_stack"`
	State      string    `json:"state"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	// Endpoints 是站点全部入口数（协议+端口），TaskHits 是该任务命中的证据条数。
	Endpoints int `json:"endpoints"`
	TaskHits  int `json:"task_hits"`
}

// taskSiteWhere 是两条关联口径的公共条件，$1=taskID，$2=搜索词，$3=like 模式。
const taskSiteWhere = `(
	s.id IN (SELECT site_id FROM raw_records WHERE task_id = $1 AND site_id IS NOT NULL)
	OR EXISTS (
		SELECT 1 FROM scan_results r
		 WHERE r.task_id = $1
		   AND (
		     r.data->>'subdomain' = s.host
		     OR r.data->>'host' = s.host
		     OR split_part(split_part(coalesce(r.url, ''), '://', 2), '/', 1) LIKE s.host || '%'
		   )
	)
) AND ($2 = '' OR s.host ILIKE $3)`

// ListTaskSites 按任务列资产：分页、支持按 host 模糊过滤。
func (a *AssetRepo) ListTaskSites(ctx context.Context, taskID string, page, pageSize int, q string) ([]TaskSite, int64, error) {
	if a == nil || a.r == nil {
		return nil, 0, errUninitialized()
	}
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 200 {
		pageSize = 20
	}
	like := "%" + q + "%"

	var total int64
	if err := a.r.pool.QueryRow(ctx,
		`SELECT count(*) FROM sites s WHERE `+taskSiteWhere, taskID, q, like).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("统计任务资产失败: %w", err)
	}
	if total == 0 {
		return []TaskSite{}, 0, nil
	}

	rows, err := a.r.pool.Query(ctx, `
		SELECT s.id, s.host, s.port, s.protocol, s.http_status, coalesce(s.title, ''),
		       coalesce(s.tech::text, '[]'), s.state, s.first_seen, s.last_seen,
		       (SELECT count(*) FROM site_endpoints e WHERE e.site_id = s.id),
		       (SELECT count(*) FROM scan_results r
		         WHERE r.task_id = $1
		           AND (r.data->>'subdomain' = s.host
		                OR r.data->>'host' = s.host
		                OR split_part(split_part(coalesce(r.url, ''), '://', 2), '/', 1) LIKE s.host || '%'))
		  FROM sites s
		 WHERE `+taskSiteWhere+`
		 ORDER BY s.last_seen DESC, s.id DESC
		 LIMIT $4 OFFSET $5`, taskID, q, like, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, 0, fmt.Errorf("查询任务资产失败: %w", err)
	}
	defer rows.Close()

	out := make([]TaskSite, 0, pageSize)
	for rows.Next() {
		var it TaskSite
		var techJSON string
		if err := rows.Scan(&it.ID, &it.Host, &it.Port, &it.Protocol, &it.HTTPStatus, &it.Title,
			&techJSON, &it.State, &it.FirstSeen, &it.LastSeen, &it.Endpoints, &it.TaskHits); err != nil {
			return nil, 0, fmt.Errorf("扫描任务资产失败: %w", err)
		}
		if techJSON != "" {
			_ = json.Unmarshal([]byte(techJSON), &it.Tech)
		}
		if it.Tech == nil {
			it.Tech = []string{}
		}
		out = append(out, it)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("读取任务资产失败: %w", err)
	}
	return out, total, nil
}
