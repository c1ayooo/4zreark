package repo

import (
	"context"
	"encoding/json"
	"strconv"
	"time"
)

// 变更时间线（兼容入口 /api/changes）：
// 在 events 的基础上按项目与事件类型过滤。列表形状与 /api/events 保持一致，
// 前端不需要为两个入口写两套解析。

func (a *AssetRepo) ListEventsFiltered(ctx context.Context, projectID int64, eventType string, limit int) ([]map[string]any, error) {
	if a == nil || a.r == nil {
		return nil, errUninitialized()
	}
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	args := []any{}
	where := " WHERE 1=1"
	if projectID > 0 {
		args = append(args, projectID)
		where += " AND e.project_id = $" + strconv.Itoa(len(args))
	}
	if eventType != "" {
		args = append(args, eventType)
		where += " AND e.event_type = $" + strconv.Itoa(len(args))
	}
	args = append(args, limit)
	sql := `
		SELECT e.id, e.project_id, e.site_id, e.record_id, e.event_type, e.title,
		       e.before, e.after, e.created_at, s.value, p.name
		FROM asset_events e
		JOIN sites s ON s.id = e.site_id
		JOIN projects p ON p.id = e.project_id` + where + `
		ORDER BY e.created_at DESC, e.id DESC LIMIT $` + strconv.Itoa(len(args))

	rows, err := a.r.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []map[string]any{}
	for rows.Next() {
		var id, pid, sid int64
		var recordID *int64
		var et, title, value, pname string
		var before, after []byte
		var at time.Time
		if err := rows.Scan(&id, &pid, &sid, &recordID, &et, &title,
			&before, &after, &at, &value, &pname); err != nil {
			return nil, err
		}
		var beforeMap, afterMap map[string]any
		_ = json.Unmarshal(before, &beforeMap)
		_ = json.Unmarshal(after, &afterMap)
		if beforeMap == nil {
			beforeMap = map[string]any{}
		}
		if afterMap == nil {
			afterMap = map[string]any{}
		}
		out = append(out, map[string]any{
			"id": id, "project_id": pid, "site_id": sid, "record_id": recordID,
			"event_type": et, "title": title, "before": beforeMap, "after": afterMap,
			"asset_value": value, "project_name": pname, "created_at": at,
		})
	}
	return out, rows.Err()
}
