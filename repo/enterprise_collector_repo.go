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
	if err != nil {
		return err
	}
	// 动作日志：企业采集到终态（与扫描任务的动作日志同一出口）
	level := "success"
	detail := "采集完成"
	if status == "error" {
		level = "error"
		detail = "采集中止：" + errMsg
	} else if status == "canceled" {
		level = "info"
		detail = "用户取消"
	}
	if _, lerr := r.pool.Exec(ctx,
		`insert into task_logs (task_id, category, level, message, detail)
         select id, 'enterprise', $2, '企业采集（' || provider || '）「' || keyword || '」' || $4, ''
           from enterprise_jobs where id = $1`,
		id, level, status, detail); lerr != nil {
		fmt.Printf("[enterprise] 动作日志写入失败: %v\n", lerr)
	}
	return nil
}

func (r *Repo) BumpJob(ctx context.Context, id string, nodes, entities, domains, digital int) error {
	_, err := r.pool.Exec(ctx, `
update enterprise_jobs
   set nodes = nodes + $2, entities = entities + $3, domains = domains + $4,
       digital = digital + $5
 where id = $1`, id, nodes, entities, domains, digital)
	return err
}

// SaveDigitalCandidates 把 BFS 顺带采集的数字资产写入候选池（status=candidate），
// 与既有名单对账：已存在的直接标 imported。返回写入行数。
func (r *Repo) SaveDigitalCandidates(ctx context.Context, jobID, source string, hits []enterprise.DigitalHit) (int64, error) {
	if len(hits) == 0 {
		return 0, nil
	}
	kinds, names, companies, platforms, entities, evidences := make([]string, 0, len(hits)),
		make([]string, 0, len(hits)), make([]string, 0, len(hits)),
		make([]string, 0, len(hits)), make([]string, 0, len(hits)),
		make([]string, 0, len(hits))
	for _, h := range hits {
		if h.Name == "" {
			continue
		}
		kinds = append(kinds, h.Kind)
		names = append(names, h.Name)
		companies = append(companies, h.Company)
		platforms = append(platforms, h.Platform)
		entities = append(entities, h.EntityName)
		evidences = append(evidences, h.Evidence)
	}
	if len(names) == 0 {
		return 0, nil
	}
	tag, err := r.pool.Exec(ctx, `
insert into digital_candidates
    (project_id, kind, name, company, platform, source, entity_name, evidence, status)
select j.project_id, t.k, t.n, t.c, t.p, $2, t.en, t.ev,
       case when exists (select 1 from digital_assets da
                          where da.project_id = j.project_id
                            and da.kind = t.k and da.name = t.n)
            then 'imported' else 'candidate' end
  from enterprise_jobs j,
       unnest($3::text[], $4::text[], $5::text[], $6::text[], $7::text[], $8::text[])
       as t(k, n, c, p, en, ev)
 where j.id = $1
on conflict (project_id, kind, name) do update set
    company = excluded.company, platform = excluded.platform,
    source = excluded.source, entity_name = excluded.entity_name,
    evidence = excluded.evidence, updated_at = now()`,
		jobID, source, kinds, names, companies, platforms, entities, evidences)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
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
// 渠道无关的归属规则：任一渠道采集的域名带 ICP 备案号、且归属实体是
// root/branch/invest（被采集企业及其股权子公司）即视为百分百归属，
// 自动转 domain 种子并把候选置 imported；集团成员（group）口径不自动归属，
// 保留人工确认。
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
	if icp != "" {
		if serr := r.autoSeedConfirmedDomain(ctx, jobID, domain, entityName); serr != nil {
			return tag.RowsAffected() > 0, serr
		}
	}
	return tag.RowsAffected() > 0, nil
}

// autoSeedConfirmedDomain 把备案归属确认的域名转为 domain 种子并置候选 imported。
// 非致命：任何一步失败只记录，不影响候选入库主流程。
func (r *Repo) autoSeedConfirmedDomain(ctx context.Context, jobID, domain, entityName string) error {
	var entityType string
	err := r.pool.QueryRow(ctx, `
select e.entity_type
  from enterprise_jobs j
  join enterprise_entities e on e.project_id = j.project_id and e.name = $2
 where j.id = $1`, jobID, entityName).Scan(&entityType)
	if err != nil {
		// 实体行尚未落库（理论上 walk 先存实体再存域名）或已清理：保守不自动转
		return nil
	}
	if entityType == "group" {
		return nil
	}
	res, err := r.pool.Exec(ctx, `
insert into seeds (project_id, kind, value, enabled)
select j.project_id, 'domain', $2, true from enterprise_jobs j where j.id = $1
on conflict (project_id, kind, value) do nothing`,
		jobID, domain)
	if err != nil {
		return err
	}
	if res.RowsAffected() > 0 {
		_, err = r.pool.Exec(ctx, `
update enterprise_candidates
   set status = 'imported'
 where project_id = (select project_id from enterprise_jobs where id = $1)
   and domain = $2`, jobID, domain)
	}
	return err
}

// ListEnterpriseJobs 按项目列出采集任务。
func (r *Repo) ListEnterpriseJobs(ctx context.Context, projectID int64, limit int) ([]enterprise.Job, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	q := `select id, project_id::text, owner, provider, keyword, status, depth, max_nodes,
	             nodes, entities, domains, digital, imported, error, created_at, finished_at
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
       nodes, entities, domains, digital, imported, error, created_at, finished_at
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
		&j.Depth, &j.MaxNodes, &j.Nodes, &j.Entities, &j.Domains, &j.Digital, &j.Imported,
		&j.Error, &j.CreatedAt, &finishedAt); err != nil {
		return j, err
	}
	j.FinishedAt = finishedAt
	j.CreatedAt = timeFromPG(&j.CreatedAt)
	return j, nil
}

// CollectSiteCount 项目站点数（采集概览用）。
func (r *Repo) CollectSiteCount(ctx context.Context, projectID int64) (int, error) {
	var n int
	err := r.pool.QueryRow(ctx, `select count(*) from sites where project_id = $1`, projectID).Scan(&n)
	return n, err
}

// CollectEntityCount 按实体类型计数（采集概览用）。
func (r *Repo) CollectEntityCount(ctx context.Context, projectID int64) (map[string]int, error) {
	rows, err := r.pool.Query(ctx,
		`select entity_type, count(*) from enterprise_entities where project_id = $1 group by entity_type`,
		projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var typ string
		var n int
		if err := rows.Scan(&typ, &n); err != nil {
			return nil, err
		}
		out[typ] = n
	}
	return out, rows.Err()
}

// CollectCandidateCount 按候选状态计数，并回传无备案号（不会自动转种子）的候选数。
func (r *Repo) CollectCandidateCount(ctx context.Context, projectID int64) (map[string]int, int, error) {
	rows, err := r.pool.Query(ctx,
		`select status, count(*) from enterprise_candidates where project_id = $1 group by status`,
		projectID)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var status string
		var n int
		if err := rows.Scan(&status, &n); err != nil {
			return nil, 0, err
		}
		out[status] = n
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	var noICP int
	if err := r.pool.QueryRow(ctx,
		`select count(*) from enterprise_candidates where project_id = $1 and status = 'candidate' and icp = ''`,
		projectID).Scan(&noICP); err != nil {
		return nil, 0, err
	}
	return out, noICP, nil
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

// PromoteDomainCandidates 候选域名批量转 domain 种子并置 imported。
// 集团成员与无备案域名的人工确认快速通道——带备案的 root/branch/invest 域名
// 在 SaveDomain 里已自动转种子，这里只处理留在候选池的那部分。
// 返回实际转种子的域名数（已在种子里的会去重，不计入）。
func (r *Repo) PromoteDomainCandidates(ctx context.Context, projectID int64, ids []int64) (int, error) {
	if projectID <= 0 || len(ids) == 0 {
		return 0, errors.New("project_id 与 ids 必填")
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `
insert into seeds (project_id, kind, value, enabled)
select project_id, 'domain', domain, true
  from enterprise_candidates
 where project_id = $1 and id = any($2) and status = 'candidate'
on conflict (project_id, kind, value) do nothing`, projectID, ids)
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `
update enterprise_candidates set status = 'imported'
 where project_id = $1 and id = any($2) and status = 'candidate'`, projectID, ids); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// RejectDomainCandidates 批量忽略候选域名（用户明确不要的，不再展示与重加）。
func (r *Repo) RejectDomainCandidates(ctx context.Context, ids []int64) (int, error) {
	if len(ids) == 0 {
		return 0, errors.New("ids 必填")
	}
	tag, err := r.pool.Exec(ctx, `
update enterprise_candidates set status = 'rejected'
 where id = any($1) and status = 'candidate'`, ids)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

func entityTypeOrDefault(v string) string {
	if v == "" {
		return "root"
	}
	return v
}
