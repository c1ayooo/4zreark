package repo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/models"

	"github.com/c1ayooo/4zreark/oid"
	"github.com/jackc/pgx/v5"
)

// NodeRepo 是扫描节点的仓储入口。
// 节点的业务键是 node_id（客户端上报的 UUID），id 只是库内主键，
// 所以「按 ID 找」要同时支持两种：先按 id，再按 node_id。
type NodeRepo interface {
	Create(ctx context.Context, n *models.ScannerNode) error
	GetByID(ctx context.Context, id string) (*models.ScannerNode, error)
	GetByNodeID(ctx context.Context, nodeID string) (*models.ScannerNode, error)
	List(ctx context.Context, nodeType, status string, page, pageSize int) ([]*models.ScannerNode, int64, error)
	UpdateFields(ctx context.Context, id string, fields map[string]any) error
	Delete(ctx context.Context, id string) error
	// Available 取「在线、未满载」的节点里当前任务最少的那个。
	Available(ctx context.Context, nodeType string, capabilities []string) (*models.ScannerNode, error)
	// Stats 返回按状态的数量与总数。
	Stats(ctx context.Context) (map[string]int64, int64, error)
	// MarkOffline 把心跳早于 before 的在线节点标成离线，返回受影响行数。
	MarkOffline(ctx context.Context, before time.Time) (int64, error)
}

type nodeRepo struct{ r *Repo }

const nodeColumns = `id, node_id, name, description, type, status, ip, port, version,
	capabilities, max_tasks, current_tasks, system_info, last_heartbeat,
	heartbeat_interval, tags, created_at, updated_at`

var nodeUpdatable = map[string]string{
	"node_id":            "node_id",
	"name":               "name",
	"description":        "description",
	"type":               "type",
	"status":             "status",
	"ip":                 "ip",
	"port":               "port",
	"version":            "version",
	"capabilities":       "capabilities",
	"max_tasks":          "max_tasks",
	"current_tasks":      "current_tasks",
	"system_info":        "system_info",
	"last_heartbeat":     "last_heartbeat",
	"heartbeat_interval": "heartbeat_interval",
	"tags":               "tags",
}

var nodeColumnConv = map[string]func(any) (any, error){
	"capabilities":   textArrayValue,
	"tags":           textArrayValue,
	"system_info":    systemInfoValue,
	"last_heartbeat": timeValue,
	"type":           stringValue,
	"status":         stringValue,
}

func systemInfoValue(v any) (any, error) {
	switch x := v.(type) {
	case nil:
		return []byte("{}"), nil
	case models.NodeSystemInfo:
		return json.Marshal(x)
	default:
		return jsonb(v)
	}
}

func scanNode(row pgx.Row) (*models.ScannerNode, error) {
	var (
		n        models.ScannerNode
		hexID    string
		nodeType string
		status   string
		infoB    []byte
		beat     *time.Time
		created  time.Time
		updated  time.Time
	)
	err := row.Scan(&hexID, &n.NodeID, &n.Name, &n.Description, &nodeType, &status, &n.IP, &n.Port,
		&n.Version, &n.Capabilities, &n.MaxTasks, &n.CurrentTasks, &infoB, &beat,
		&n.HeartbeatInterval, &n.Tags, &created, &updated)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if n.ID, err = objectIDFromHex(hexID); err != nil {
		return nil, err
	}
	n.Type = models.NodeType(nodeType)
	n.Status = models.NodeStatus(status)
	if len(infoB) > 0 {
		_ = json.Unmarshal(infoB, &n.SystemInfo)
	}
	n.LastHeartbeat = timeFromPG(beat)
	n.CreatedAt = timeFromPG(&created)
	n.UpdatedAt = timeFromPG(&updated)
	return &n, nil
}

func (r *nodeRepo) Create(ctx context.Context, n *models.ScannerNode) error {
	if n.ID.IsZero() {
		n.ID = oid.NewObjectID()
	}
	if n.CreatedAt.IsZero() {
		n.CreatedAt = time.Now()
	}
	if n.UpdatedAt.IsZero() {
		n.UpdatedAt = n.CreatedAt
	}
	if n.HeartbeatInterval == 0 {
		n.HeartbeatInterval = 30
	}
	info, err := systemInfoValue(n.SystemInfo)
	if err != nil {
		return err
	}

	_, err = r.r.pool.Exec(ctx,
		`insert into scanner_nodes (`+nodeColumns+`)
		 values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`,
		n.ID.Hex(), n.NodeID, n.Name, n.Description, string(n.Type), string(n.Status), n.IP, n.Port,
		n.Version, textArray(n.Capabilities), n.MaxTasks, n.CurrentTasks, info,
		timeToPG(n.LastHeartbeat), n.HeartbeatInterval, textArray(n.Tags),
		n.CreatedAt.UTC(), n.UpdatedAt.UTC())
	if isUniqueViolation(err) {
		return ErrDuplicate
	}
	return err
}

func (r *nodeRepo) GetByID(ctx context.Context, id string) (*models.ScannerNode, error) {
	if _, err := idFromString(id); err != nil {
		return nil, ErrNotFound
	}
	return scanNode(r.r.pool.QueryRow(ctx, `select `+nodeColumns+` from scanner_nodes where id = $1`, id))
}

func (r *nodeRepo) GetByNodeID(ctx context.Context, nodeID string) (*models.ScannerNode, error) {
	return scanNode(r.r.pool.QueryRow(ctx, `select `+nodeColumns+` from scanner_nodes where node_id = $1`, nodeID))
}

func (r *nodeRepo) List(ctx context.Context, nodeType, status string, page, pageSize int) ([]*models.ScannerNode, int64, error) {
	page, pageSize = vulnPage(page, pageSize)

	const where = `where ($1 = '' or type = $1) and ($2 = '' or status = $2)`
	var total int64
	if err := r.r.pool.QueryRow(ctx, `select count(*) from scanner_nodes `+where, nodeType, status).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := r.r.pool.Query(ctx,
		`select `+nodeColumns+` from scanner_nodes `+where+`
		  order by created_at desc limit $3 offset $4`,
		nodeType, status, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []*models.ScannerNode
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, n)
	}
	return out, total, rows.Err()
}

func (r *nodeRepo) UpdateFields(ctx context.Context, id string, fields map[string]any) error {
	if _, err := idFromString(id); err != nil {
		return ErrNotFound
	}
	if len(fields) == 0 {
		return nil
	}

	sets := make([]string, 0, len(fields)+1)
	args := make([]any, 0, len(fields)+2)
	i := 1
	for k, v := range fields {
		col, ok := nodeUpdatable[k]
		if !ok {
			continue
		}
		val := v
		if c, ok := nodeColumnConv[col]; ok {
			var err error
			if val, err = c(v); err != nil {
				return fmt.Errorf("字段 %s 取值非法: %w", k, err)
			}
		}
		sets = append(sets, fmt.Sprintf("%s = $%d", col, i))
		args = append(args, val)
		i++
	}
	if len(sets) == 0 {
		return nil
	}
	sets = append(sets, "updated_at = now()")
	args = append(args, id)

	tag, err := r.r.pool.Exec(ctx,
		"update scanner_nodes set "+strings.Join(sets, ", ")+fmt.Sprintf(" where id = $%d", i), args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *nodeRepo) Delete(ctx context.Context, id string) error {
	if _, err := idFromString(id); err != nil {
		return ErrNotFound
	}
	tag, err := r.r.pool.Exec(ctx, `delete from scanner_nodes where id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *nodeRepo) Available(ctx context.Context, nodeType string, capabilities []string) (*models.ScannerNode, error) {
	// max_tasks = 0 视为不接任务，否则 current < max 这个条件永远不成立会让人困惑。
	rows, err := r.r.pool.Query(ctx,
		`select `+nodeColumns+` from scanner_nodes
		  where status = 'online'
		    and max_tasks > 0
		    and current_tasks < max_tasks
		    and ($1 = '' or type = $1)
		    and ($2::text[] = '{}' or capabilities @> $2::text[])
		  order by current_tasks, last_heartbeat desc nulls last
		  limit 1`, nodeType, textArray(capabilities))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, err
		}
		return nil, ErrNotFound
	}
	return scanNode(rows)
}

func (r *nodeRepo) Stats(ctx context.Context) (map[string]int64, int64, error) {
	rows, err := r.r.pool.Query(ctx,
		`select status, count(*) from scanner_nodes group by status`)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := make(map[string]int64, 4)
	var total int64
	for rows.Next() {
		var (
			st string
			n  int64
		)
		if err := rows.Scan(&st, &n); err != nil {
			return nil, 0, err
		}
		out[st] = n
		total += n
	}
	return out, total, rows.Err()
}

func (r *nodeRepo) MarkOffline(ctx context.Context, before time.Time) (int64, error) {
	tag, err := r.r.pool.Exec(ctx,
		`update scanner_nodes set status = 'offline', updated_at = now()
		  where status = 'online' and (last_heartbeat is null or last_heartbeat < $1)`,
		before.UTC())
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
