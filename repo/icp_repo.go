package repo

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/c1ayooo/4zreark/oid"
	"github.com/jackc/pgx/v5"
)

// 工信部 ICP 查询任务与结果快照。

type ICPQuery struct {
	ID          string     `json:"id"`
	ProjectID   int64      `json:"project_id"`
	Query       string     `json:"query"`
	ServiceType int        `json:"service_type"`
	PageSize    int        `json:"page_size"`
	Status      string     `json:"status"`
	Total       int        `json:"total"`
	Pages       int        `json:"pages"`
	Fetched     int        `json:"fetched"`
	Error       string     `json:"error"`
	CreatedAt   time.Time  `json:"created_at"`
	StartedAt   *time.Time `json:"started_at"`
	FinishedAt  *time.Time `json:"finished_at"`
}

type ICPFiling struct {
	ID               int64     `json:"id"`
	QueryID          string    `json:"query_id"`
	ProjectID        int64     `json:"project_id"`
	Domain           string    `json:"domain"`
	MainLicence      string    `json:"main_licence"`
	ServiceLicence   string    `json:"service_licence"`
	UnitName         string    `json:"unit_name"`
	NatureName       string    `json:"nature_name"`
	ContentType      string    `json:"content_type"`
	LeaderName       string    `json:"leader_name"`
	UpdateRecordTime string    `json:"update_record_time"`
	CreatedAt        time.Time `json:"created_at"`
}

type ICPFilingInput struct {
	Domain           string
	MainLicence      string
	ServiceLicence   string
	UnitName         string
	NatureName       string
	ContentType      string
	LeaderName       string
	UpdateRecordTime string
}

func (r *Repo) CreateICPQuery(ctx context.Context, projectID int64, query string, serviceType, pageSize int) (*ICPQuery, error) {
	if projectID <= 0 {
		return nil, errors.New("project_id 必填")
	}
	if serviceType <= 0 {
		serviceType = 1
	}
	if pageSize <= 0 || pageSize > 40 {
		pageSize = 40
	}
	q := &ICPQuery{
		ID: oid.NewObjectID().Hex(), ProjectID: projectID, Query: query,
		ServiceType: serviceType, PageSize: pageSize, Status: "queued",
		CreatedAt: time.Now().UTC(),
	}
	if _, err := r.pool.Exec(ctx, `
insert into icp_queries (id, project_id, query, service_type, page_size, status, created_at)
values ($1,$2,$3,$4,$5,'queued',$6)`,
		q.ID, q.ProjectID, q.Query, q.ServiceType, q.PageSize, q.CreatedAt); err != nil {
		return nil, err
	}
	return q, nil
}

func (r *Repo) MarkICPQueryRunning(ctx context.Context, id string) error {
	_, err := r.pool.Exec(ctx,
		`update icp_queries set status='running', started_at=now() where id=$1 and status='queued'`, id)
	return err
}

func (r *Repo) UpdateICPQueryProgress(ctx context.Context, id string, total, pages, fetched int) error {
	_, err := r.pool.Exec(ctx,
		`update icp_queries set total=$2, pages=$3, fetched=$4 where id=$1`,
		id, total, pages, fetched)
	return err
}

func (r *Repo) FinishICPQuery(ctx context.Context, id, status, errMsg string) error {
	_, err := r.pool.Exec(ctx,
		`update icp_queries set status=$2, error=$3, finished_at=now() where id=$1`,
		id, status, errMsg)
	return err
}

func (r *Repo) GetICPQuery(ctx context.Context, id string) (*ICPQuery, error) {
	row := r.pool.QueryRow(ctx, `
select id, project_id, query, service_type, page_size, status, total, pages, fetched,
       error, created_at, started_at, finished_at
  from icp_queries where id=$1`, id)
	q, err := scanICPQuery(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return q, err
}

func (r *Repo) ListICPQueries(ctx context.Context, projectID int64, limit int) ([]*ICPQuery, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	q := `select id, project_id, query, service_type, page_size, status, total, pages, fetched,
	             error, created_at, started_at, finished_at
	        from icp_queries`
	args := []any{}
	if projectID > 0 {
		args = append(args, projectID)
		q += ` where project_id=$1`
	}
	args = append(args, limit)
	q += fmt.Sprintf(` order by created_at desc limit $%d`, len(args))
	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*ICPQuery{}
	for rows.Next() {
		item, err := scanICPQuery(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func scanICPQuery(row interface{ Scan(...any) error }) (*ICPQuery, error) {
	var q ICPQuery
	if err := row.Scan(&q.ID, &q.ProjectID, &q.Query, &q.ServiceType, &q.PageSize, &q.Status,
		&q.Total, &q.Pages, &q.Fetched, &q.Error, &q.CreatedAt, &q.StartedAt, &q.FinishedAt); err != nil {
		return nil, err
	}
	q.CreatedAt = timeFromPG(&q.CreatedAt)
	return &q, nil
}

// InsertICPFilings 批量写快照；同一查询内同 (service_licence,domain) 去重。
func (r *Repo) InsertICPFilings(ctx context.Context, queryID string, projectID int64, items []ICPFilingInput) (int, error) {
	if len(items) == 0 {
		return 0, nil
	}
	inserted := 0
	for _, it := range items {
		tag, err := r.pool.Exec(ctx, `
insert into icp_filings (query_id, project_id, domain, main_licence, service_licence,
                         unit_name, nature_name, content_type, leader_name, update_record_time)
values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
on conflict (query_id, service_licence, domain) do nothing`,
			queryID, projectID, it.Domain, it.MainLicence, it.ServiceLicence,
			it.UnitName, it.NatureName, it.ContentType, it.LeaderName, it.UpdateRecordTime)
		if err != nil {
			return inserted, err
		}
		inserted += int(tag.RowsAffected())
	}
	return inserted, nil
}

func (r *Repo) ListICPFilings(ctx context.Context, queryID string, limit int) ([]*ICPFiling, error) {
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	rows, err := r.pool.Query(ctx, `
select id, query_id, project_id, domain, main_licence, service_licence, unit_name,
       nature_name, content_type, leader_name, update_record_time, created_at
  from icp_filings
 where query_id=$1
 order by id
 limit $2`, queryID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*ICPFiling{}
	for rows.Next() {
		var f ICPFiling
		if err := rows.Scan(&f.ID, &f.QueryID, &f.ProjectID, &f.Domain, &f.MainLicence,
			&f.ServiceLicence, &f.UnitName, &f.NatureName, &f.ContentType,
			&f.LeaderName, &f.UpdateRecordTime, &f.CreatedAt); err != nil {
			return nil, err
		}
		f.CreatedAt = timeFromPG(&f.CreatedAt)
		out = append(out, &f)
	}
	return out, rows.Err()
}
