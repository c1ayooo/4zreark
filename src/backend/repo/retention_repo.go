package repo

import (
	"context"
	"fmt"
)

// 数据保留策略的写入面：按时间批量清理历史流水。
//
// 四条红线：
//   - scan_results 是分区表，按 created_at 过滤，删除走主键子查询；
//   - raw_records 删除前先摘掉 relation_evidence / fingerprint_hits / asset_events
//     对它的引用，再清理没有证据的关系边；
//   - verifications 只删历史流水，不动 sites 当前状态；
//   - asset_events 的 keep/days 口径沿用 PruneEvents（最多 N 条 + 超过 D 天）。

// RetentionCount 统计某张表在 days 天前的行数（dry-run 用）。
// table 只接受白名单，避免调用方把表名拼进 SQL。
func (r *Repo) RetentionCount(ctx context.Context, table string, days int) (int64, error) {
	var q string
	switch table {
	case "scan_results":
		q = `SELECT count(*) FROM scan_results WHERE created_at < now() - make_interval(days => $1)`
	case "raw_records":
		q = `SELECT count(*) FROM raw_records WHERE observed_at < now() - make_interval(days => $1)`
	case "verifications":
		q = `SELECT count(*) FROM verifications WHERE observed_at < now() - make_interval(days => $1)`
	case "asset_events":
		q = `SELECT count(*) FROM asset_events WHERE created_at < now() - make_interval(days => $1)`
	default:
		return 0, fmt.Errorf("不支持的表: %s", table)
	}
	var n int64
	if err := r.pool.QueryRow(ctx, q, days).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// PurgeScanResults 删除 days 天前的扫描结果，单批最多 batch 条。
func (r *Repo) PurgeScanResults(ctx context.Context, days, batch int) (int64, error) {
	if days <= 0 {
		return 0, nil
	}
	if batch <= 0 || batch > 50000 {
		batch = 10000
	}
	tag, err := r.pool.Exec(ctx, `
		DELETE FROM scan_results
		 WHERE id IN (
		   SELECT id FROM scan_results
		    WHERE created_at < now() - make_interval(days => $1)
		    ORDER BY created_at
		    LIMIT $2
		 )`, days, batch)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// PurgeVerifications 删除 days 天前的验证流水，单批最多 batch 条。
func (r *Repo) PurgeVerifications(ctx context.Context, days, batch int) (int64, error) {
	if days <= 0 {
		return 0, nil
	}
	if batch <= 0 || batch > 50000 {
		batch = 10000
	}
	tag, err := r.pool.Exec(ctx, `
		DELETE FROM verifications
		 WHERE id IN (
		   SELECT id FROM verifications
		    WHERE observed_at < now() - make_interval(days => $1)
		    ORDER BY observed_at
		    LIMIT $2
		 )`, days, batch)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// RawRecordVictims 取 days 天前最老的一批原始记录 ID。
func (r *Repo) RawRecordVictims(ctx context.Context, days, batch int) ([]int64, error) {
	if days <= 0 {
		return nil, nil
	}
	if batch <= 0 || batch > 50000 {
		batch = 10000
	}
	rows, err := r.pool.Query(ctx, `
		SELECT id FROM raw_records
		 WHERE observed_at < now() - make_interval(days => $1)
		 ORDER BY observed_at
		 LIMIT $2`, days, batch)
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

// PurgeRawRecords 删除一批原始记录，同时摘掉对它们的证据引用。
// asset_events / fingerprint_hits 的 record_id 置空；relation_evidence 直接删，
// 删完后清掉没有任何证据的关系边（避免留下「无证据关系」）。
func (r *Repo) PurgeRawRecords(ctx context.Context, ids []int64) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx,
		`UPDATE asset_events SET record_id = NULL WHERE record_id = ANY($1)`, ids); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE fingerprint_hits SET record_id = NULL WHERE record_id = ANY($1)`, ids); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM relation_evidence WHERE record_id = ANY($1)`, ids); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `
		DELETE FROM relations r
		 WHERE NOT EXISTS (SELECT 1 FROM relation_evidence e WHERE e.relation_id = r.id)`); err != nil {
		return 0, err
	}
	tag, err := tx.Exec(ctx, `DELETE FROM raw_records WHERE id = ANY($1)`, ids)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
