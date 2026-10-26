package repo

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// 图标与聚类视图。
//
// 图标本身按 sha256 去重存一份字节（同图只存一次），站点上只留 sha256 + mmh3 两个引用。
// 聚类视图直接 group by sites.icon_sha256 / tech 数组，不额外维护汇总表。

// IconInput 是一张待入库的图标。
type IconInput struct {
	SHA256      string
	MMH3        int64
	ContentType string
	Size        int
	Data        []byte
}

// IconCluster 是按图标聚类的一行。
type IconCluster struct {
	SHA256     string    `json:"icon_sha256"`
	MMH3       int64     `json:"icon_mmh3"`
	SiteCount  int64     `json:"site_count"`
	SampleHost string    `json:"sample_host"`
	SampleName string    `json:"sample_title"`
	LastSeen   time.Time `json:"last_seen"`
}

// TechCluster 是按技术栈聚类的一行。
type TechCluster struct {
	Name      string `json:"name"`
	SiteCount int64  `json:"site_count"`
}

// AppOption 是「按指纹筛选」下拉的候选：指纹规则名或技术栈名 + 命中站点数。
type AppOption struct {
	Name      string `json:"name"`
	Category  string `json:"category"`
	SiteCount int    `json:"site_count"`
}

// ClusterRepo 负责图标存取与两个聚类视图。
type ClusterRepo interface {
	UpsertIcon(ctx context.Context, in IconInput) error
	AttachIconToSite(ctx context.Context, siteID int64, sha256 string, mmh3 int64) error
	GetIcon(ctx context.Context, sha256 string) (*IconInput, error)

	IconClusters(ctx context.Context, projectID int64, q, app string, page, pageSize int) ([]*IconCluster, int64, error)
	TechClusters(ctx context.Context, projectID int64, q, app string, page, pageSize int) ([]*TechCluster, int64, error)
	AppOptions(ctx context.Context, q string, limit int) ([]*AppOption, error)
}

type clusterRepo struct{ r *Repo }

func (r *Repo) Clusters() ClusterRepo { return &clusterRepo{r: r} }

func (c *clusterRepo) UpsertIcon(ctx context.Context, in IconInput) error {
	if in.SHA256 == "" {
		return errors.New("图标 sha256 为空")
	}
	if in.ContentType == "" {
		in.ContentType = "image/x-icon"
	}
	// 同一个 sha256 只存一份字节；已有就不覆盖
	_, err := c.r.pool.Exec(ctx, `
		insert into asset_icons (sha256, mmh3, content_type, size_bytes, data)
		values ($1,$2,$3,$4,$5)
		on conflict (sha256) do nothing`,
		in.SHA256, in.MMH3, in.ContentType, in.Size, in.Data)
	return err
}

func (c *clusterRepo) AttachIconToSite(ctx context.Context, siteID int64, sha256 string, mmh3 int64) error {
	_, err := c.r.pool.Exec(ctx,
		`update sites set icon_sha256 = $2, icon_mmh3 = $3 where id = $1`, siteID, sha256, mmh3)
	return err
}

func (c *clusterRepo) GetIcon(ctx context.Context, sha256 string) (*IconInput, error) {
	var in IconInput
	err := c.r.pool.QueryRow(ctx,
		`select sha256, coalesce(mmh3,0), content_type, size_bytes, data
		   from asset_icons where sha256 = $1`, sha256).
		Scan(&in.SHA256, &in.MMH3, &in.ContentType, &in.Size, &in.Data)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &in, nil
}

func (c *clusterRepo) IconClusters(ctx context.Context, projectID int64, q, app string, page, pageSize int) ([]*IconCluster, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 500 {
		pageSize = 60
	}
	b := newWhereBuilder(1)
	b.parts = append(b.parts, "s.icon_sha256 IS NOT NULL")
	if projectID > 0 {
		b.parts = append(b.parts, "s.project_id = "+b.ph())
		b.args = append(b.args, projectID)
	}
	if q != "" {
		b.parts = append(b.parts, "s.host ILIKE "+b.ph())
		b.args = append(b.args, "%"+q+"%")
	}
	if app != "" {
		b.parts = append(b.parts, appExistsCond(b.ph(), b.ph()))
		b.args = append(b.args, strings.ToLower(app), "%"+escapeLike(strings.ToLower(app))+"%")
	}

	var total int64
	if err := c.r.pool.QueryRow(ctx,
		`select count(*) from (select 1 from sites s where `+b.String()+` group by s.icon_sha256) t`,
		b.args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	args := append(append([]any{}, b.args...), pageSize, (page-1)*pageSize)
	stmt := `select s.icon_sha256,
	                coalesce(max(s.icon_mmh3), 0),
	                count(*) as site_count,
	                (array_agg(s.host order by s.last_seen desc))[1],
	                coalesce((array_agg(coalesce(s.title,'') order by s.last_seen desc))[1], ''),
	                max(s.last_seen)
	           from sites s
	          where ` + b.String() + `
	          group by s.icon_sha256
	          order by count(*) desc, s.icon_sha256`
	stmt += " limit $%d offset $%d"
	rows, err := c.r.pool.Query(ctx, fmt.Sprintf(stmt, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := []*IconCluster{}
	for rows.Next() {
		var ic IconCluster
		if err := rows.Scan(&ic.SHA256, &ic.MMH3, &ic.SiteCount, &ic.SampleHost, &ic.SampleName, &ic.LastSeen); err != nil {
			return nil, 0, err
		}
		ic.LastSeen = ic.LastSeen.UTC()
		out = append(out, &ic)
	}
	return out, total, rows.Err()
}

func (c *clusterRepo) TechClusters(ctx context.Context, projectID int64, q, app string, page, pageSize int) ([]*TechCluster, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 500 {
		pageSize = 60
	}
	b := newWhereBuilder(1)
	b.parts = append(b.parts, "jsonb_array_length(s.tech) > 0")
	if projectID > 0 {
		b.parts = append(b.parts, "s.project_id = "+b.ph())
		b.args = append(b.args, projectID)
	}
	if q != "" {
		b.parts = append(b.parts, "s.host ILIKE "+b.ph())
		b.args = append(b.args, "%"+q+"%")
	}
	if app != "" {
		b.parts = append(b.parts, appExistsCond(b.ph(), b.ph()))
		b.args = append(b.args, strings.ToLower(app), "%"+escapeLike(strings.ToLower(app))+"%")
	}

	// 一个站点在同一技术名下只算一次
	var total int64
	if err := c.r.pool.QueryRow(ctx,
		`select count(distinct t.name)
		   from sites s, jsonb_array_elements_text(s.tech) as t(name)
		  where `+b.String(), b.args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	args := append(append([]any{}, b.args...), pageSize, (page-1)*pageSize)
	stmt := `select t.name, count(distinct s.id) as site_count
	           from sites s, jsonb_array_elements_text(s.tech) as t(name)
	          where ` + b.String() + `
	          group by t.name
	          order by count(distinct s.id) desc, t.name`
	stmt += " limit $%d offset $%d"
	rows, err := c.r.pool.Query(ctx, fmt.Sprintf(stmt, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := []*TechCluster{}
	for rows.Next() {
		var tc TechCluster
		if err := rows.Scan(&tc.Name, &tc.SiteCount); err != nil {
			return nil, 0, err
		}
		out = append(out, &tc)
	}
	return out, total, rows.Err()
}

// AppOptions 给「按指纹筛选」下拉出候选：指纹规则命中（fingerprint_hits×rules）
// 与站点技术栈（sites.tech）取并集，按命中站点数倒序。q 对名称做 ILIKE 前缀外的
// 包含匹配，limit 截断候选数。计数是两种来源的站点数之和，用于排序与展示，
// 与 app 谓词的精确口径可能有出入（同站点双源计数）。
func (c *clusterRepo) AppOptions(ctx context.Context, q string, limit int) ([]*AppOption, error) {
	if limit < 1 || limit > 1000 {
		limit = 200
	}
	pattern := "%" + escapeLike(q) + "%"
	rows, err := c.r.pool.Query(ctx, `
		SELECT u.name, max(u.category), sum(u.site_count)::int
		  FROM (
		        SELECT fr.name, fr.category, count(DISTINCT fh.site_id) AS site_count
		          FROM fingerprint_hits fh
		          JOIN fingerprint_rules fr ON fr.id = fh.rule_id
		         GROUP BY fr.name, fr.category
		        UNION ALL
		        SELECT x.tech, '', count(DISTINCT s.id)
		          FROM sites s, jsonb_array_elements_text(s.tech) x(tech)
		         WHERE x.tech <> ''
		         GROUP BY x.tech
		       ) u
		 WHERE ($1 = '' OR u.name ILIKE $2)
		 GROUP BY u.name
		 ORDER BY sum(u.site_count) DESC, u.name
		 LIMIT $3`, q, pattern, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*AppOption{}
	for rows.Next() {
		var o AppOption
		if err := rows.Scan(&o.Name, &o.Category, &o.SiteCount); err != nil {
			return nil, err
		}
		out = append(out, &o)
	}
	return out, rows.Err()
}
