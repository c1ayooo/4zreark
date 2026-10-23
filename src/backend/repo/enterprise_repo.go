package repo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// 企业身份域：企业名 / 备案域名 / 线索。与数字资产名单解耦，不触发 DNS 与扫描。
// 归属对齐是查询动作：按项目 + 企业名匹配 digital_assets.company。

type EnterpriseDomain struct {
	Domain   string `json:"domain"`
	Site     string `json:"site,omitempty"`
	ICP      string `json:"icp,omitempty"`
	Evidence string `json:"evidence,omitempty"`
}

type EnterpriseEntity struct {
	ID          int64  `json:"id"`
	ProjectID   int64  `json:"project_id"`
	Name        string `json:"name"`
	CreditCode  string `json:"credit_code"`
	LegalPerson string `json:"legal_person"`
	OpenStatus  string `json:"open_status"`
	Industry    string `json:"industry"`
	Address     string `json:"address"`
	// RegisteredCapital 注册资本原文（"6500万元"），RegisteredCapitalWan 为归一后的万元数值，
	// 用于按资金规模筛目标（如 CNVD 事件型要求注册资金 ≥ 5000 万）。
	RegisteredCapital    string             `json:"registered_capital"`
	RegisteredCapitalWan float64            `json:"registered_capital_wan"`
	ICPNumbers           []string           `json:"icp_numbers"`
	Domains              []EnterpriseDomain `json:"domains"`
	Source               string             `json:"source"`
	Status               string             `json:"status"`
	Notes                string             `json:"notes"`
	DigitalCount         int                `json:"digital_count"`
	CreatedAt            time.Time          `json:"created_at"`
	UpdatedAt            time.Time          `json:"updated_at"`
}

type EnterpriseInput struct {
	Name                 string             `json:"name"`
	CreditCode           string             `json:"credit_code"`
	LegalPerson          string             `json:"legal_person"`
	OpenStatus           string             `json:"open_status"`
	Industry             string             `json:"industry"`
	Address              string             `json:"address"`
	RegisteredCapital    string             `json:"registered_capital"`
	RegisteredCapitalWan float64            `json:"registered_capital_wan"`
	ICPNumbers           []string           `json:"icp_numbers"`
	Domains              []EnterpriseDomain `json:"domains"`
	Source               string             `json:"source"`
	Status               string             `json:"status"`
	Notes                string             `json:"notes"`
}

type EnterpriseFilter struct {
	ProjectID int64
	Query     string
	Status    string
	// MinRegisteredCapitalWan > 0 时只返回注册资金不低于该值（万元）的企业。
	MinRegisteredCapitalWan float64
	Page                    int
	PageSize                int
}

type EnterpriseRepo interface {
	List(ctx context.Context, f EnterpriseFilter) ([]*EnterpriseEntity, int64, error)
	Get(ctx context.Context, id int64) (*EnterpriseEntity, error)
	Upsert(ctx context.Context, projectID int64, in EnterpriseInput) (*EnterpriseEntity, error)
	Delete(ctx context.Context, id int64) (bool, error)
	// UpsertMany 批量导入，返回新增/更新计数；空名称跳过。
	UpsertMany(ctx context.Context, projectID int64, rows []EnterpriseInput, source string) (inserted, updated int, err error)
	// AlignedDigitalAssets 返回同项目下 company 与该企业名相等的数字资产名单。
	AlignedDigitalAssets(ctx context.Context, projectID int64, name string) ([]*DigitalAsset, error)
}

type enterpriseRepo struct{ r *Repo }

func (r *Repo) Enterprises() EnterpriseRepo { return &enterpriseRepo{r: r} }

const enterpriseColumns = `e.id, e.project_id, e.name, e.credit_code, e.legal_person,
	e.open_status, e.industry, e.address, e.registered_capital, coalesce(e.registered_capital_wan, 0),
	e.icp_numbers, e.domains, e.source, e.status,
	e.notes, e.created_at, e.updated_at,
	(select count(*) from digital_assets d
	  where d.project_id = e.project_id and d.company = e.name) as digital_count`

func scanEnterprise(row interface{ Scan(...any) error }) (*EnterpriseEntity, error) {
	var (
		e          EnterpriseEntity
		icpB, domB []byte
	)
	if err := row.Scan(&e.ID, &e.ProjectID, &e.Name, &e.CreditCode, &e.LegalPerson,
		&e.OpenStatus, &e.Industry, &e.Address, &e.RegisteredCapital, &e.RegisteredCapitalWan,
		&icpB, &domB, &e.Source, &e.Status,
		&e.Notes, &e.CreatedAt, &e.UpdatedAt, &e.DigitalCount); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	_ = json.Unmarshal(icpB, &e.ICPNumbers)
	_ = json.Unmarshal(domB, &e.Domains)
	if e.ICPNumbers == nil {
		e.ICPNumbers = []string{}
	}
	if e.Domains == nil {
		e.Domains = []EnterpriseDomain{}
	}
	e.CreatedAt, e.UpdatedAt = timeFromPG(&e.CreatedAt), timeFromPG(&e.UpdatedAt)
	return &e, nil
}

func (r *enterpriseRepo) List(ctx context.Context, f EnterpriseFilter) ([]*EnterpriseEntity, int64, error) {
	page, pageSize := vulnPage(f.Page, f.PageSize)
	w := newWhereBuilder(1)
	if f.ProjectID > 0 {
		w.parts = append(w.parts, "e.project_id = "+w.ph())
		w.args = append(w.args, f.ProjectID)
	}
	if s := strings.TrimSpace(f.Query); s != "" {
		like := "%" + s + "%"
		ph := w.ph()
		w.parts = append(w.parts, "(e.name ilike "+ph+" or e.credit_code ilike "+ph+" or e.legal_person ilike "+ph+")")
		w.args = append(w.args, like)
	}
	if s := strings.TrimSpace(f.Status); s != "" {
		w.parts = append(w.parts, "e.status = "+w.ph())
		w.args = append(w.args, s)
	}
	if f.MinRegisteredCapitalWan > 0 {
		w.parts = append(w.parts, "coalesce(e.registered_capital_wan, 0) >= "+w.ph())
		w.args = append(w.args, f.MinRegisteredCapitalWan)
	}
	cond := w.String()

	var total int64
	if err := r.r.pool.QueryRow(ctx, `select count(*) from enterprise_entities e where `+cond, w.args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args := append(append([]any{}, w.args...), pageSize, (page-1)*pageSize)
	rows, err := r.r.pool.Query(ctx, fmt.Sprintf(`
select %s from enterprise_entities e
 where %s
 order by e.updated_at desc, e.id desc
 limit $%d offset $%d`, enterpriseColumns, cond, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []*EnterpriseEntity{}
	for rows.Next() {
		e, err := scanEnterprise(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}

func (r *enterpriseRepo) Get(ctx context.Context, id int64) (*EnterpriseEntity, error) {
	return scanEnterprise(r.r.pool.QueryRow(ctx,
		`select `+enterpriseColumns+` from enterprise_entities e where e.id = $1`, id))
}

func (r *enterpriseRepo) Upsert(ctx context.Context, projectID int64, in EnterpriseInput) (*EnterpriseEntity, error) {
	name := strings.Join(strings.Fields(in.Name), " ")
	if projectID <= 0 || name == "" {
		return nil, errors.New("project_id 与企业名必填")
	}
	status := strings.TrimSpace(in.Status)
	if status == "" {
		status = "unverified"
	}
	if status != "unverified" && status != "verified" && status != "ignored" {
		return nil, errors.New("status 只能是 unverified / verified / ignored")
	}
	source := strings.TrimSpace(in.Source)
	if source == "" {
		source = "manual"
	}
	icp, _ := json.Marshal(nonNilStrings(in.ICPNumbers))
	domains, _ := json.Marshal(nonNilDomains(in.Domains))

	var id int64
	if err := r.r.pool.QueryRow(ctx, `
insert into enterprise_entities (project_id, name, credit_code, legal_person, open_status,
                                 industry, address, registered_capital, registered_capital_wan,
                                 icp_numbers, domains, source, status, notes)
values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb,$12,$13,$14)
on conflict (project_id, name) do update
   set credit_code = excluded.credit_code,
       legal_person = excluded.legal_person,
       open_status = case when excluded.open_status = '' then enterprise_entities.open_status else excluded.open_status end,
       industry = excluded.industry,
       address = excluded.address,
       -- 注册资本只有 qcc 采集填充：其他来源/手工编辑传空时保留原值，
       -- 不然一次非 qcc 的重复采集或一次保存就会把已有数据清掉
       registered_capital = case when excluded.registered_capital = '' then enterprise_entities.registered_capital else excluded.registered_capital end,
       registered_capital_wan = case when coalesce(excluded.registered_capital_wan, 0) = 0 then enterprise_entities.registered_capital_wan else excluded.registered_capital_wan end,
       icp_numbers = excluded.icp_numbers,
       domains = excluded.domains,
       source = case when excluded.source = 'manual' then enterprise_entities.source else excluded.source end,
       status = excluded.status,
       notes = excluded.notes,
       updated_at = now()
returning id`,
		projectID, name, strings.TrimSpace(in.CreditCode), strings.TrimSpace(in.LegalPerson),
		strings.TrimSpace(in.OpenStatus), strings.TrimSpace(in.Industry), strings.TrimSpace(in.Address),
		strings.TrimSpace(in.RegisteredCapital), in.RegisteredCapitalWan,
		string(icp), string(domains), source, status, strings.TrimSpace(in.Notes)).Scan(&id); err != nil {
		return nil, err
	}
	return r.Get(ctx, id)
}

func (r *enterpriseRepo) Delete(ctx context.Context, id int64) (bool, error) {
	tag, err := r.r.pool.Exec(ctx, `delete from enterprise_entities where id = $1`, id)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func (r *enterpriseRepo) UpsertMany(ctx context.Context, projectID int64, rows []EnterpriseInput, source string) (int, int, error) {
	if projectID <= 0 {
		return 0, 0, errors.New("project_id 必填")
	}
	inserted, updated := 0, 0
	tx, err := r.r.pool.Begin(ctx)
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback(ctx)
	for _, in := range rows {
		name := strings.Join(strings.Fields(in.Name), " ")
		if name == "" {
			continue
		}
		if in.Source == "" {
			in.Source = source
		}
		if in.Status == "" {
			in.Status = "unverified"
		}
		icp, _ := json.Marshal(nonNilStrings(in.ICPNumbers))
		domains, _ := json.Marshal(nonNilDomains(in.Domains))
		var isInsert bool
		if err := tx.QueryRow(ctx, `
insert into enterprise_entities (project_id, name, credit_code, legal_person, open_status,
                                 industry, address, registered_capital, registered_capital_wan,
                                 icp_numbers, domains, source, status, notes)
values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb,$12,$13,$14)
on conflict (project_id, name) do update
   set credit_code = excluded.credit_code,
       legal_person = excluded.legal_person,
       registered_capital = excluded.registered_capital,
       registered_capital_wan = excluded.registered_capital_wan,
       icp_numbers = excluded.icp_numbers,
       domains = excluded.domains,
       source = excluded.source,
       status = excluded.status,
       notes = excluded.notes,
       updated_at = now()
returning (xmax = 0)`,
			projectID, name, in.CreditCode, in.LegalPerson, in.OpenStatus, in.Industry,
			in.Address, in.RegisteredCapital, in.RegisteredCapitalWan,
			string(icp), string(domains), in.Source, in.Status, in.Notes).Scan(&isInsert); err != nil {
			return inserted, updated, err
		}
		if isInsert {
			inserted++
		} else {
			updated++
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, 0, err
	}
	return inserted, updated, nil
}

func (r *enterpriseRepo) AlignedDigitalAssets(ctx context.Context, projectID int64, name string) ([]*DigitalAsset, error) {
	rows, err := r.r.pool.Query(ctx, `
select id, project_id, kind, name, company, platform, source, status, batch_id, created_at
  from digital_assets
 where project_id = $1 and company = $2
 order by id desc`, projectID, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*DigitalAsset{}
	for rows.Next() {
		var (
			a         DigitalAsset
			createdAt time.Time
		)
		if err := rows.Scan(&a.ID, &a.ProjectID, &a.Kind, &a.Name, &a.Company,
			&a.Platform, &a.Source, &a.Status, &a.BatchID, &createdAt); err != nil {
			return nil, err
		}
		a.CreatedAt = timeFromPG(&createdAt)
		out = append(out, &a)
	}
	return out, rows.Err()
}

func nonNilStrings(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

func nonNilDomains(v []EnterpriseDomain) []EnterpriseDomain {
	if v == nil {
		return []EnterpriseDomain{}
	}
	return v
}
