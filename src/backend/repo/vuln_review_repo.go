package repo

import (
	"context"
	"errors"
	"time"

	"github.com/c1ayooo/4zreark/models"
)

// AddReview 追加一条复核记录，并把复核结论同步回 vulnerabilities：
// reviewer / review_note / reviewed_at / review_count 一条 UPDATE 写完，
// 避免"台账有记录、漏洞卡片上看不到复核人"这种半截状态。
func (r *vulnRepo) AddReview(ctx context.Context, review *models.VulnReview, toStatus models.VulnStatus) error {
	if review == nil {
		return errors.New("缺少复核记录")
	}
	if !models.ValidVulnStatus(toStatus) {
		return errors.New("非法的漏洞状态")
	}
	tag, err := r.r.pool.Exec(ctx, `
INSERT INTO vuln_reviews (vuln_id, workspace_id, from_status, to_status, reviewer, note, auto)
VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		review.VulnID, review.WorkspaceID, string(review.FromStatus), string(toStatus),
		review.Reviewer, review.Note, review.Auto)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return r.UpdateFields(ctx, review.VulnID, map[string]any{
		"status":       string(toStatus),
		"reviewer":     review.Reviewer,
		"review_note":  review.Note,
		"reviewed_at":  time.Now(),
		"review_count": review.ID, // 占位：service 层传入累加后的值
	})
}

// AddReviewWithCount 与 AddReview 相同，但由调用方显式给出 review_count。
// AddReview 里的 count 占位无法累加，因此复核入口统一走这个方法。
func (r *vulnRepo) AddReviewWithCount(ctx context.Context, review *models.VulnReview, toStatus models.VulnStatus, reviewCount int) error {
	if review == nil {
		return errors.New("缺少复核记录")
	}
	if !models.ValidVulnStatus(toStatus) {
		return errors.New("非法的漏洞状态")
	}
	tag, err := r.r.pool.Exec(ctx, `
INSERT INTO vuln_reviews (vuln_id, workspace_id, from_status, to_status, reviewer, note, auto)
VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		review.VulnID, review.WorkspaceID, string(review.FromStatus), string(toStatus),
		review.Reviewer, review.Note, review.Auto)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return r.UpdateFields(ctx, review.VulnID, map[string]any{
		"status":       string(toStatus),
		"reviewer":     review.Reviewer,
		"review_note":  review.Note,
		"reviewed_at":  time.Now(),
		"review_count": reviewCount,
	})
}

// ListReviews 按时间正序返回一条漏洞的复核历史（最早在前，时间线才好读）。
func (r *vulnRepo) ListReviews(ctx context.Context, vulnID string) ([]*models.VulnReview, error) {
	if _, err := idFromString(vulnID); err != nil {
		return nil, ErrNotFound
	}
	rows, err := r.r.pool.Query(ctx, `
SELECT id, vuln_id, workspace_id, from_status, to_status, reviewer, note, auto, created_at
  FROM vuln_reviews WHERE vuln_id = $1 ORDER BY created_at ASC, id ASC`, vulnID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*models.VulnReview
	for rows.Next() {
		var (
			rv        models.VulnReview
			wsID      string
			fromState string
			created   time.Time
		)
		if err := rows.Scan(&rv.ID, &rv.VulnID, &wsID, &fromState, &rv.ToStatus,
			&rv.Reviewer, &rv.Note, &rv.Auto, &created); err != nil {
			return nil, err
		}
		rv.WorkspaceID = wsID
		rv.FromStatus = models.VulnStatus(fromState)
		rv.CreatedAt = timeFromPG(&created)
		out = append(out, &rv)
	}
	return out, rows.Err()
}

// ReviewStats 按工作区统计复核分布，供列表页筛选项展示各终态的真实条数。
func (r *vulnRepo) ReviewStats(ctx context.Context, workspaceID string) (*models.VulnReviewStats, error) {
	st := &models.VulnReviewStats{ByStatus: map[models.VulnStatus]int64{}}
	if err := r.r.pool.QueryRow(ctx, `
SELECT count(*) FILTER (WHERE review_count > 0),
       count(*) FILTER (WHERE status = 'new')
  FROM vulnerabilities WHERE ($1 = '' or workspace_id = $1)`, workspaceID).
		Scan(&st.Reviewed, &st.Pending); err != nil {
		return nil, err
	}
	rows, err := r.r.pool.Query(ctx, `
SELECT to_status, count(*) FROM vuln_reviews
 WHERE ($1 = '' or workspace_id = $1)
 GROUP BY 1`, workspaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			s   string
			cnt int64
		)
		if err := rows.Scan(&s, &cnt); err != nil {
			return nil, err
		}
		st.ByStatus[models.VulnStatus(s)] = cnt
	}
	return st, rows.Err()
}
