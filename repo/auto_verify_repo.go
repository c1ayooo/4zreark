package repo

import (
	"context"
	"fmt"
)

// 自动存活验证的候选站点：新导入/扫描出来、还没验证过、且有 HTTP 入口的站点。
// 非 HTTP-only 站点不参与（TCP 探测不在可达性口径里）。

func (a *AssetRepo) PendingVerificationSiteIDs(ctx context.Context, projectID int64, limit int) ([]int64, error) {
	if a == nil || a.r == nil {
		return nil, errUninitialized()
	}
	if limit <= 0 || limit > 500 {
		limit = 20
	}
	args := []any{limit}
	where := `s.state = 'pending' AND s.verification_status = 'pending' AND s.attempts = 0
		AND (s.next_verification_at IS NULL OR s.next_verification_at <= now())`
	if projectID > 0 {
		args = append(args, projectID)
		where += fmt.Sprintf(" AND s.project_id = $%d", len(args))
	}
	rows, err := a.r.pool.Query(ctx, `
		SELECT s.id FROM sites s
		 WHERE `+where+`
		   AND (EXISTS (SELECT 1 FROM site_endpoints e
		                 WHERE e.site_id = s.id AND e.scheme IN ('http','https'))
		        OR NOT EXISTS (SELECT 1 FROM site_endpoints e WHERE e.site_id = s.id))
		 ORDER BY s.first_seen DESC
		 LIMIT $1`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []int64{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
