package repo

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/models"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// ResultRepo 是 scan_results / result_dedup 的唯一数据入口。
//
// scan_results 是按 created_at 月分区的表，唯一索引必须带分区键，所以跨月去重
// 落在不分区的小表 result_dedup 上：写入时先占位再写结果，同事务内完成，
// 不会出现「去重记了、结果没写」或「去重丢了、重复全落库」的不一致。
type ResultRepo interface {
	Create(ctx context.Context, res *models.ScanResult) error
	CreateWithDedup(ctx context.Context, res *models.ScanResult) (bool, error)
	BatchCreate(ctx context.Context, results []models.ScanResult) error

	ListByTask(ctx context.Context, taskID, resultType string, page, pageSize int, search string, statusCode int) ([]*models.ScanResult, int64, error)
	ExportByTask(ctx context.Context, taskID, resultType string) ([]*models.ScanResult, error)
	StatsByTask(ctx context.Context, taskID string) (map[string]int64, error)

	ListSubdomains(ctx context.Context, taskID string, page, pageSize int, search string) ([]*models.ScanResult, int64, error)
	ServiceDataByHost(ctx context.Context, taskID string) (map[string]bson.M, error)
	AggregatePorts(ctx context.Context, taskID string, page, pageSize int, search string) ([]PortGroup, int64, error)

	SetTags(ctx context.Context, id string, tags []string) error
	AddTag(ctx context.Context, id, tag string) error
	RemoveTag(ctx context.Context, id, tag string) error
	UpdateSubdomainCDN(ctx context.Context, taskID, domain, provider string) error

	DeleteByTask(ctx context.Context, taskID string) error
	DeleteByIDs(ctx context.Context, ids []string) error
}

// PortGroup 是按 IP 聚合后的端口视图，对应前端端口页的一行。
type PortGroup struct {
	IP        string
	Host      string
	Ports     []string
	Services  []string
	CreatedAt time.Time
}

type resultRepo struct{ r *Repo }

const resultColumns = `id, task_id, workspace_id, type, data, tags, project, source, created_at, updated_at`

// dbExecutor 让插入语句能同时跑在连接池和事务上。
type dbExecutor interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// --- 读取 ---

func scanResultRow(row pgx.Row) (*models.ScanResult, error) {
	var (
		hexID, taskHex, wsHex string
		typ                   string
		rawData               []byte
		tags                  []string
		project, source       string
		createdAt, updatedAt  time.Time
	)
	if err := row.Scan(&hexID, &taskHex, &wsHex, &typ, &rawData, &tags, &project, &source,
		&createdAt, &updatedAt); err != nil {
		return nil, err
	}

	res := &models.ScanResult{
		Type:      models.ResultType(typ),
		Data:      decodeResultData(rawData),
		Tags:      tags,
		Project:   project,
		Source:    source,
		CreatedAt: createdAt.UTC(),
		UpdatedAt: updatedAt.UTC(),
	}

	var err error
	if res.ID, err = primitive.ObjectIDFromHex(hexID); err != nil {
		return nil, fmt.Errorf("结果 ID 非法(%q): %w", hexID, err)
	}
	if res.TaskID, err = primitive.ObjectIDFromHex(taskHex); err != nil {
		return nil, fmt.Errorf("结果 task_id 非法(%q): %w", taskHex, err)
	}
	if res.WorkspaceID, err = primitive.ObjectIDFromHex(wsHex); err != nil {
		return nil, fmt.Errorf("结果 workspace_id 非法(%q): %w", wsHex, err)
	}
	return res, nil
}

// decodeResultData 把 jsonb 解成 bson.M。
// PG 的 JSON 数字统一解成 float64，而 Mongo 时代下游有 int32/int64 的类型断言，
// 这里把整数值还原成 int64，保证响应体数字形态与改造前一致。
func decodeResultData(raw []byte) bson.M {
	if len(raw) == 0 {
		return bson.M{}
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return bson.M{}
	}
	if m, ok := normalizeJSONValue(v).(bson.M); ok {
		return m
	}
	return bson.M{}
}

func normalizeJSONValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		m := make(bson.M, len(t))
		for k, vv := range t {
			m[k] = normalizeJSONValue(vv)
		}
		return m
	case bson.M:
		m := make(bson.M, len(t))
		for k, vv := range t {
			m[k] = normalizeJSONValue(vv)
		}
		return m
	case []any:
		for i := range t {
			t[i] = normalizeJSONValue(t[i])
		}
		return t
	case float64:
		if t == math.Trunc(t) && math.Abs(t) < 1e15 {
			return int64(t)
		}
		return t
	default:
		return v
	}
}

// --- data 取值（写库时的列提取与去重键推导） ---

func dataString(data bson.M, key string) string {
	if v, ok := data[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func dataInt(data bson.M, key string) (int, bool) {
	v, ok := data[key]
	if !ok || v == nil {
		return 0, false
	}
	switch n := v.(type) {
	case int:
		return n, true
	case int32:
		return int(n), true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	case string:
		if i, err := strconv.Atoi(strings.TrimSpace(n)); err == nil {
			return i, true
		}
	}
	return 0, false
}

// dataIP 只接受合法 IP：库里的 ip 是 inet 列，主机名/域名一律留 NULL。
func dataIP(data bson.M, key string) string {
	s := strings.TrimSpace(dataString(data, key))
	if s == "" || net.ParseIP(s) == nil {
		return ""
	}
	return s
}

func nonNilData(data bson.M) bson.M {
	if data == nil {
		return bson.M{}
	}
	return data
}

// derived 是 scan_results 上为了建索引而冗余的列。
type derived struct {
	host, url, ip string
	port, status  any
}

func deriveColumns(data bson.M) derived {
	d := derived{
		host: dataString(data, "host"),
		url:  dataString(data, "url"),
		ip:   dataIP(data, "ip"),
	}
	if v, ok := dataInt(data, "port"); ok {
		d.port = v
	}
	if v, ok := dataInt(data, "status_code"); ok {
		d.status = v
	}
	return d
}

// BuildDedupKey 生成跨月去重键：task_id + type + 业务键。
func BuildDedupKey(taskID string, typ models.ResultType, parts ...string) string {
	var b strings.Builder
	b.WriteString(taskID)
	b.WriteByte('|')
	b.WriteString(string(typ))
	for _, p := range parts {
		b.WriteByte('|')
		b.WriteString(p)
	}
	return b.String()
}

// BuildDedupKeyFromData 用于没有明确业务键的类型：
// 对 data 做规范化 JSON 摘要（Go 的 map 序列化键有序，摘要稳定），
// 同样内容的重复发现会被收敛，内容不同的不会互相覆盖。
func BuildDedupKeyFromData(taskID string, typ models.ResultType, data bson.M) string {
	b, err := json.Marshal(nonNilData(data))
	if err != nil {
		b = []byte(fmt.Sprintf("%v", data))
	}
	sum := sha1.Sum(b)
	return BuildDedupKey(taskID, typ, "sha1:"+hex.EncodeToString(sum[:]))
}

// --- 写入 ---

func execInsert(ctx context.Context, ex dbExecutor, res *models.ScanResult) error {
	data, err := json.Marshal(nonNilData(res.Data))
	if err != nil {
		return fmt.Errorf("序列化结果 data 失败: %w", err)
	}
	d := deriveColumns(res.Data)

	const stmt = `insert into scan_results
        (id, task_id, workspace_id, type, data, tags, project, source, dedup_key,
         host, url, ip, port, status_code, created_at, updated_at)
      values ($1, $2, $3, $4, $5, $6, $7, $8, $9,
              nullif($10, ''), nullif($11, ''), nullif($12, '')::inet, $13, $14, $15, $16)`

	_, err = ex.Exec(ctx, stmt,
		res.ID.Hex(), res.TaskID.Hex(), res.WorkspaceID.Hex(), string(res.Type),
		data, textArray(res.Tags), res.Project, res.Source, res.DedupKey,
		d.host, d.url, d.ip, d.port, d.status,
		res.CreatedAt.UTC(), res.UpdatedAt.UTC())
	if err != nil {
		return fmt.Errorf("写入扫描结果失败: %w", err)
	}

	// 记账但不拦写：Create 语义是「每次出现都记一行」，这里只把键登记下来，
	// 让后续 CreateWithDedup 能认出这些行（对应 Mongo 版按条件查询去重的行为）。
	if res.DedupKey != "" {
		if _, err := ex.Exec(ctx,
			`insert into result_dedup (dedup_key, task_id, created_at) values ($1, $2, now())
			 on conflict (dedup_key) do nothing`,
			res.DedupKey, res.TaskID.Hex()); err != nil {
			return fmt.Errorf("登记去重键失败: %w", err)
		}
	}
	return nil
}

func (r *resultRepo) Create(ctx context.Context, res *models.ScanResult) error {
	now := time.Now()
	if res.ID.IsZero() {
		res.ID = primitive.NewObjectID()
	}
	if res.CreatedAt.IsZero() {
		res.CreatedAt = now
	}
	res.UpdatedAt = now
	return execInsert(ctx, r.r.pool, res)
}

func (r *resultRepo) CreateWithDedup(ctx context.Context, res *models.ScanResult) (bool, error) {
	// 没给去重键就退化成普通插入，语义与 Mongo 版「filter 为空」不同也不会误合并
	if res.DedupKey == "" {
		return true, r.Create(ctx, res)
	}

	now := time.Now()
	if res.ID.IsZero() {
		res.ID = primitive.NewObjectID()
	}
	if res.CreatedAt.IsZero() {
		res.CreatedAt = now
	}
	res.UpdatedAt = now

	tx, err := r.r.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var key string
	err = tx.QueryRow(ctx,
		`insert into result_dedup (dedup_key, task_id, created_at) values ($1, $2, now())
		 on conflict (dedup_key) do nothing
		 returning dedup_key`,
		res.DedupKey, res.TaskID.Hex()).Scan(&key)

	switch {
	case err == nil:
		// 首次出现：落结果行
		if err := execInsert(ctx, tx, res); err != nil {
			return false, err
		}
		return true, tx.Commit(ctx)

	case errors.Is(err, pgx.ErrNoRows):
		// 已出现过：按原 Mongo $set 语义刷新既有行（data/source/tags/project）
		data, mErr := json.Marshal(nonNilData(res.Data))
		if mErr != nil {
			return false, fmt.Errorf("序列化结果 data 失败: %w", mErr)
		}
		d := deriveColumns(res.Data)
		ct, uErr := tx.Exec(ctx,
			`update scan_results
			    set data = $3, source = $4, tags = $5, project = $6, updated_at = $7,
			        host = nullif($8, ''), url = nullif($9, ''), ip = nullif($10, '')::inet,
			        port = $11, status_code = $12
			  where task_id = $1 and type = $2 and dedup_key = $13`,
			res.TaskID.Hex(), string(res.Type), data, res.Source, textArray(res.Tags),
			res.Project, now, d.host, d.url, d.ip, d.port, d.status, res.DedupKey)
		if uErr != nil {
			return false, fmt.Errorf("刷新扫描结果失败: %w", uErr)
		}
		if ct.RowsAffected() == 0 {
			// 去重账本还在、结果行已被删除（例如清理过结果），补回一行
			if err := execInsert(ctx, tx, res); err != nil {
				return false, err
			}
		}
		return false, tx.Commit(ctx)

	default:
		return false, err
	}
}

func (r *resultRepo) BatchCreate(ctx context.Context, results []models.ScanResult) error {
	if len(results) == 0 {
		return nil
	}
	tx, err := r.r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	now := time.Now()
	for i := range results {
		if results[i].ID.IsZero() {
			results[i].ID = primitive.NewObjectID()
		}
		if results[i].CreatedAt.IsZero() {
			results[i].CreatedAt = now
		}
		results[i].UpdatedAt = now
		if err := execInsert(ctx, tx, &results[i]); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// --- 查询 ---

// likePattern 把用户输入转成 LIKE 模式，转义通配符（PG 的 LIKE 默认以反斜杠转义）。
func likePattern(search string) string {
	s := strings.ToLower(search)
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return "%" + s + "%"
}

// resultFilter 拼 where 子句。searchKeys 只来自代码内常量，不含用户输入。
func resultFilter(taskID, resultType string, statusCode int, search string, searchKeys ...string) (string, []any) {
	where := "task_id = $1"
	args := []any{taskID}

	if resultType != "" {
		args = append(args, resultType)
		where += fmt.Sprintf(" and type = $%d", len(args))
	}
	if statusCode > 0 {
		args = append(args, strconv.Itoa(statusCode))
		where += fmt.Sprintf(" and data->>'status' = $%d", len(args))
	}
	if search != "" {
		args = append(args, likePattern(search))
		n := len(args)
		conds := make([]string, 0, len(searchKeys)+1)
		for _, k := range searchKeys {
			conds = append(conds, fmt.Sprintf("lower(data->>'%s') like $%d", k, n))
		}
		conds = append(conds, fmt.Sprintf("lower(project) like $%d", n))
		where += " and (" + strings.Join(conds, " or ") + ")"
	}
	return where, args
}

func (r *resultRepo) listPaged(ctx context.Context, where string, args []any, page, pageSize int) ([]*models.ScanResult, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	args = append(args, pageSize, (page-1)*pageSize)
	stmt := "select " + resultColumns + " from scan_results where " + where +
		fmt.Sprintf(" order by created_at desc, id limit $%d offset $%d", len(args)-1, len(args))

	rows, err := r.r.pool.Query(ctx, stmt, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]*models.ScanResult, 0, pageSize)
	for rows.Next() {
		res, err := scanResultRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, rows.Err()
}

func (r *resultRepo) ListByTask(ctx context.Context, taskID, resultType string, page, pageSize int, search string, statusCode int) ([]*models.ScanResult, int64, error) {
	where, args := resultFilter(taskID, resultType, statusCode, search, "domain", "subdomain", "url", "ip", "company")

	var total int64
	if err := r.r.pool.QueryRow(ctx, "select count(*) from scan_results where "+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	list, err := r.listPaged(ctx, where, args, page, pageSize)
	if err != nil {
		return nil, 0, err
	}
	return list, total, nil
}

func (r *resultRepo) ExportByTask(ctx context.Context, taskID, resultType string) ([]*models.ScanResult, error) {
	where, args := resultFilter(taskID, resultType, 0, "", "domain", "subdomain", "url", "ip", "company")
	stmt := "select " + resultColumns + " from scan_results where " + where + " order by created_at desc, id"

	rows, err := r.r.pool.Query(ctx, stmt, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]*models.ScanResult, 0, 256)
	for rows.Next() {
		res, err := scanResultRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, rows.Err()
}

func (r *resultRepo) StatsByTask(ctx context.Context, taskID string) (map[string]int64, error) {
	rows, err := r.r.pool.Query(ctx,
		`select type, count(*) from scan_results where task_id = $1 group by type`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	stats := make(map[string]int64)
	for rows.Next() {
		var (
			typ string
			n   int64
		)
		if err := rows.Scan(&typ, &n); err != nil {
			return nil, err
		}
		stats[typ] = n
	}
	return stats, rows.Err()
}

func (r *resultRepo) ListSubdomains(ctx context.Context, taskID string, page, pageSize int, search string) ([]*models.ScanResult, int64, error) {
	where, args := resultFilter(taskID, string(models.ResultTypeSubdomain), 0, search, "subdomain", "domain", "title")

	var total int64
	if err := r.r.pool.QueryRow(ctx, "select count(*) from scan_results where "+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	list, err := r.listPaged(ctx, where, args, page, pageSize)
	if err != nil {
		return nil, 0, err
	}
	return list, total, nil
}

// ServiceDataByHost 取任务下全部 service 结果的 data，按 host 建索引，
// 供子域名列表补充 title / status_code / 指纹 / url。
func (r *resultRepo) ServiceDataByHost(ctx context.Context, taskID string) (map[string]bson.M, error) {
	rows, err := r.r.pool.Query(ctx,
		`select data from scan_results where task_id = $1 and type = $2 order by created_at`,
		taskID, string(models.ResultTypeService))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[string]bson.M)
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		data := decodeResultData(raw)
		host := dataString(data, "host")
		if host == "" {
			continue
		}
		// 同一 host 只保留第一条（通常是 443/80 那条），与 Mongo 版一致
		if _, exists := out[host]; !exists {
			out[host] = data
		}
	}
	return out, rows.Err()
}

func (r *resultRepo) AggregatePorts(ctx context.Context, taskID string, page, pageSize int, search string) ([]PortGroup, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}

	where := "task_id = $1 and type = $2"
	args := []any{taskID, string(models.ResultTypePort)}
	if search != "" {
		args = append(args, likePattern(search))
		n := len(args)
		where += fmt.Sprintf(` and (lower(data->>'ip') like $%d or lower(data->>'host') like $%d
		                         or lower(data->>'service') like $%d)`, n, n, n)
	}

	var total int64
	if err := r.r.pool.QueryRow(ctx,
		"select count(*) from (select 1 from scan_results where "+where+" group by data->>'ip') t",
		args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	args = append(args, pageSize, (page-1)*pageSize)
	stmt := `select coalesce(data->>'ip', '') as ip,
                    (array_agg(data->>'host' order by created_at desc))[1] as host,
                    array_agg(data->>'port' order by created_at) filter (
                        where coalesce(data->>'port', '') <> '') as ports,
                    array_agg(data->>'service' order by created_at) filter (
                        where coalesce(data->>'service', '') <> '') as services,
                    max(created_at) as created_at
               from scan_results
              where ` + where + `
              group by 1
              order by 5 desc, 1` + fmt.Sprintf(" limit $%d offset $%d", len(args)-1, len(args))

	rows, err := r.r.pool.Query(ctx, stmt, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := make([]PortGroup, 0, pageSize)
	for rows.Next() {
		var (
			g         PortGroup
			host      *string
			ports     []string
			services  []string
			createdAt time.Time
		)
		if err := rows.Scan(&g.IP, &host, &ports, &services, &createdAt); err != nil {
			return nil, 0, err
		}
		if host != nil {
			g.Host = *host
		}
		g.Ports = ports
		g.Services = services
		g.CreatedAt = createdAt.UTC()
		out = append(out, g)
	}
	return out, total, rows.Err()
}

// --- 更新与删除 ---

func (r *resultRepo) SetTags(ctx context.Context, id string, tags []string) error {
	_, err := r.r.pool.Exec(ctx,
		`update scan_results set tags = $2, updated_at = now() where id = $1::char(24)`,
		id, textArray(tags))
	return err
}

func (r *resultRepo) AddTag(ctx context.Context, id, tag string) error {
	_, err := r.r.pool.Exec(ctx,
		`update scan_results
		    set tags = case when $2 = any(tags) then tags else array_append(tags, $2) end,
		        updated_at = now()
		  where id = $1::char(24)`, id, tag)
	return err
}

func (r *resultRepo) RemoveTag(ctx context.Context, id, tag string) error {
	_, err := r.r.pool.Exec(ctx,
		`update scan_results set tags = array_remove(tags, $2), updated_at = now()
		  where id = $1::char(24)`, id, tag)
	return err
}

func (r *resultRepo) UpdateSubdomainCDN(ctx context.Context, taskID, domain, provider string) error {
	_, err := r.r.pool.Exec(ctx,
		`update scan_results
		    set data = data || jsonb_build_object('cdn', true, 'cdn_provider', $3::text),
		        updated_at = now()
		  where task_id = $1 and type = 'subdomain'
		    and (data->>'subdomain' = $2 or data->>'domain' = $2)`,
		taskID, domain, provider)
	return err
}

func (r *resultRepo) DeleteByTask(ctx context.Context, taskID string) error {
	tx, err := r.r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `delete from scan_results where task_id = $1`, taskID); err != nil {
		return err
	}
	// 去重账本必须一起清：否则同一任务重跑时会被残留的 dedup_key 判成重复
	if _, err := tx.Exec(ctx, `delete from result_dedup where task_id = $1`, taskID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (r *resultRepo) DeleteByIDs(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := r.r.pool.Exec(ctx,
		`delete from scan_results where id::text = any($1::text[])`, ids)
	return err
}
