package repo

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/c1ayooo/4zreark/internal/enterprise"
	"github.com/c1ayooo/4zreark/oid"
	"github.com/jackc/pgx/v5"
)

// 企业 BFS 采集的任务/实体/候选域名持久化。
// *Repo 直接实现 enterprise.CollectorStore，采集器不感知 SQL。

func (r *Repo) CreateJob(ctx context.Context, job enterprise.Job) (enterprise.Job, error) {
	projectID, err := strconv.ParseInt(job.ProjectID, 10, 64)
	if err != nil || projectID <= 0 {
		return enterprise.Job{}, errors.New("project_id 必填")
	}
	job.ID = oid.NewObjectID().Hex()
	job.CreatedAt = time.Now().UTC()
	job.Status = "running"
	if job.Depth < 1 {
		job.Depth = 1
	}
	if job.MaxNodes < 1 {
		job.MaxNodes = 20
	}
	_, err = r.pool.Exec(ctx, `
insert into enterprise_jobs (id, project_id, owner, provider, keyword, status, depth, max_nodes, created_at)
values ($1,$2,$3,$4,$5,'running',$6,$7,$8)`,
		job.ID, projectID, job.Owner, job.Provider, job.Keyword, job.Depth, job.MaxNodes, job.CreatedAt)
	if err != nil {
		return enterprise.Job{}, err
	}
	return job, nil
}

func (r *Repo) FinishJob(ctx context.Context, id, status, errMsg string) error {
	_, err := r.pool.Exec(ctx,
		`update enterprise_jobs set status=$2, error=$3, finished_at=now() where id=$1`,
		id, status, errMsg)
	return err
}

func (r *Repo) BumpJob(ctx context.Context, id string, nodes, entities, domains int) error {
	_, err := r.pool.Exec(ctx, `
update enterprise_jobs
   set nodes = nodes + $2, entities = entities + $3, domains = domains + $4
 where id = $1`, id, nodes, entities, domains)
	return err
}

// SaveEntity 幂等写入企业实体；已存在时补全详情并合并域名/备案。
// 返回是否新插入（用于任务 entities 计数）。
func (r *Repo) SaveEntity(ctx context.Context, e *enterprise.Entity) (bool, error) {
	if e == nil || e.Name == "" || e.ExtID == "" {
		return false, nil
	}
	var inserted bool
	err := r.pool.QueryRow(ctx, `
with j as (select project_id from enterprise_jobs where id = $1)
insert into enterprise_entities
    (project_id, name, legal_person, open_status, phone, email,
     job_id, ext_id, entity_type, parent_ext_id, depth, source, status)
select j.project_id, $2, $3, $4, $5, $6,
       $1, $7, $8, $9, $10, 'enterprise', 'unverified'
  from j
on conflict (project_id, name) do update
   set legal_person = case when excluded.legal_person <> '' then excluded.legal_person else enterprise_entities.legal_person end,
       open_status  = case when excluded.open_status  <> '' then excluded.open_status  else enterprise_entities.open_status end,
       phone        = case when excluded.phone        <> '' then excluded.phone        else enterprise_entities.phone end,
       email        = case when excluded.email        <> '' then excluded.email        else enterprise_entities.email end,
       job_id       = excluded.job_id,
       ext_id       = excluded.ext_id,
       entity_type  = excluded.entity_type,
       parent_ext_id = excluded.parent_ext_id,
       depth        = excluded.depth,
       updated_at   = now()
returning (xmax = 0)`,
		e.JobID, e.Name, e.LegalPerson, e.OpenStatus, e.Phone, e.Email,
		e.ExtID, entityTypeOrDefault(e.EntityType), e.ParentExtID, e.Depth).Scan(&inserted)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, errors.New("采集任务不存在")
	}
	return inserted, err
}

// SaveDomain 把域名写入候选资产；同项目已存在则不重复。
func (r *Repo) SaveDomain(ctx context.Context, jobID, domain, site, icp, entityName string) (bool, error) {
	domain = enterprise.NormalizeDomain(domain)
	if domain == "" {
		return false, nil
	}
	tag, err := r.pool.Exec(ctx, `
insert into enterprise_candidates (job_id, project_id, domain, site, icp, entity_name)
select $1, j.project_id, $2, $3, $4, $5 from enterprise_jobs j where j.id = $1
on conflict (project_id, domain) do nothing`,
		jobID, domain, site, icp, entityName)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// ListEnterpriseJobs 按项目列出采集任务。
func (r *Repo) ListEnterpriseJobs(ctx context.Context, projectID int64, limit int) ([]enterprise.Job, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	q := `select id, project_id::text, owner, provider, keyword, status, depth, max_nodes,
	             nodes, entities, domains, imported, error, created_at, finished_at
	        from enterprise_jobs`
	args := []any{}
	if projectID > 0 {
		args = append(args, projectID)
		q += ` where project_id = $1`
	}
	args = append(args, limit)
	q += fmt.Sprintf(` order by created_at desc limit $%d`, len(args))
	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []enterprise.Job{}
	for rows.Next() {
		job, err := scanEnterpriseJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, job)
	}
	return out, rows.Err()
}

func (r *Repo) GetEnterpriseJob(ctx context.Context, id string) (enterprise.Job, error) {
	row := r.pool.QueryRow(ctx, `
select id, project_id::text, owner, provider, keyword, status, depth, max_nodes,
       nodes, entities, domains, imported, error, created_at, finished_at
  from enterprise_jobs where id = $1`, id)
	job, err := scanEnterpriseJob(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return enterprise.Job{}, ErrNotFound
	}
	return job, err
}

func scanEnterpriseJob(row interface{ Scan(...any) error }) (enterprise.Job, error) {
	var (
		j          enterprise.Job
		finishedAt *time.Time
	)
	if err := row.Scan(&j.ID, &j.ProjectID, &j.Owner, &j.Provider, &j.Keyword, &j.Status,
		&j.Depth, &j.MaxNodes, &j.Nodes, &j.Entities, &j.Domains, &j.Imported,
		&j.Error, &j.CreatedAt, &finishedAt); err != nil {
		return j, err
	}
	j.FinishedAt = finishedAt
	j.CreatedAt = timeFromPG(&j.CreatedAt)
	return j, nil
}

// ListEnterpriseCandidates 列出候选域名。
func (r *Repo) ListEnterpriseCandidates(ctx context.Context, projectID int64, status string, limit int) ([]enterprise.CandidateAsset, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	q := `select id, coalesce(job_id,''), project_id::text, domain,
	             trim(site || ' ' || icp) as evidence, entity_name, status, created_at
	        from enterprise_candidates`
	w := newWhereBuilder(1)
	if projectID > 0 {
		w.parts = append(w.parts, "project_id = "+w.ph())
		w.args = append(w.args, projectID)
	}
	if status != "" {
		w.parts = append(w.parts, "status = "+w.ph())
		w.args = append(w.args, status)
	}
	args := append(append([]any{}, w.args...), limit)
	q += fmt.Sprintf(` where %s order by created_at desc, id desc limit $%d`, w.String(), len(args))
	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []enterprise.CandidateAsset{}
	for rows.Next() {
		var (
			a         enterprise.CandidateAsset
			id        int64
			createdAt time.Time
		)
		if err := rows.Scan(&id, &a.JobID, &a.ProjectID, &a.Value, &a.Evidence,
			&a.EntityName, &a.Status, &createdAt); err != nil {
			return nil, err
		}
		a.ID = strconv.FormatInt(id, 10)
		a.Kind = "domain"
		a.CreatedAt = timeFromPG(&createdAt)
		out = append(out, a)
	}
	return out, rows.Err()
}

func entityTypeOrDefault(v string) string {
	if v == "" {
		return "root"
	}
	return v
}
