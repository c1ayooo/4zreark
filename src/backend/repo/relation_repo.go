package repo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
)

// 关系图谱（G5）。表在 schema_governance 里已建好，这里补读写。
//
// 边类型（与 relations_type_chk 对齐）：
//   same_ip        同 IP
//   same_icon      同图标 sha256
//   same_fp        同技术栈（每个 tech 一条关系）
//   domain_parent  父域 → 子域（同一项目内）
//
// same_cert / cname 目前没有数据来源（sites 不存证书、CNAME），不生成。
//
// 证据口径：每条边必须挂两侧站点各自的原始记录；没有 raw_record 的站点
// 不参与建边（无证据不出边）。

const maxRelationGroup = 200

type relationSite struct {
	ID         int64
	ProjectID  int64
	Host       string
	IP         string
	IconSHA256 string
	CertSHA256 string
	FinalHost  string
	Tech       []string
	RecordID   *int64
}

type relationPair struct {
	Type       string
	Key        string
	Left       relationSite
	Right      relationSite
	Confidence float64
}

type RelationNode struct {
	ID        int64  `json:"id"`
	ProjectID int64  `json:"project_id"`
	Host      string `json:"host"`
	Value     string `json:"value"`
	Title     string `json:"title"`
	IP        string `json:"ip"`
}

type RelationEdge struct {
	ID         int64        `json:"id"`
	Type       string       `json:"type"`
	Key        string       `json:"key"`
	Confidence float64      `json:"confidence"`
	Left       RelationNode `json:"left"`
	Right      RelationNode `json:"right"`
}

type RelationGraph struct {
	Nodes      []RelationNode `json:"nodes"`
	Edges      []RelationEdge `json:"edges"`
	TotalEdges int64          `json:"total_edges"`
	Truncated  bool           `json:"truncated"`
}

type RelationIndexStatus struct {
	ByType   map[string]int64 `json:"by_type"`
	Edges    int64            `json:"edges"`
	Evidence int64            `json:"evidence"`
	Sites    int64            `json:"sites"`
}

type RelationRepo interface {
	// Rebuild 重建一个项目（projectID=0 表示全部项目）的关系边与证据。
	Rebuild(ctx context.Context, projectID int64) (map[string]int64, error)
	List(ctx context.Context, projectID int64, typ string, limit int) (*RelationGraph, error)
	Status(ctx context.Context, projectID int64) (*RelationIndexStatus, error)
}

type relationRepo struct{ r *Repo }

func (r *Repo) Relations() RelationRepo { return &relationRepo{r: r} }

func (r *relationRepo) Rebuild(ctx context.Context, projectID int64) (map[string]int64, error) {
	rows, err := r.r.pool.Query(ctx, `
SELECT s.id, s.project_id, lower(s.host), coalesce(s.ip::text, ''), coalesce(s.icon_sha256, ''),
       coalesce(s.cert_sha256, ''), coalesce(s.final_host, ''), s.tech,
       (SELECT rr.id FROM raw_records rr WHERE rr.site_id = s.id ORDER BY rr.observed_at DESC LIMIT 1)
  FROM sites s
 WHERE ($1 = 0 OR s.project_id = $1)`, projectID)
	if err != nil {
		return nil, err
	}
	sites := make([]relationSite, 0, 256)
	for rows.Next() {
		var s relationSite
		var tech []byte
		if err := rows.Scan(&s.ID, &s.ProjectID, &s.Host, &s.IP, &s.IconSHA256,
			&s.CertSHA256, &s.FinalHost, &tech, &s.RecordID); err != nil {
			rows.Close()
			return nil, err
		}
		if len(tech) > 0 {
			_ = json.Unmarshal(tech, &s.Tech)
		}
		sites = append(sites, s)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	pairs := buildRelationPairs(sites)

	tx, err := r.r.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `DELETE FROM relations WHERE ($1 = 0 OR project_id = $1)`, projectID); err != nil {
		return nil, err
	}

	stats := map[string]int64{}
	for _, p := range pairs {
		var relationID int64
		err := tx.QueryRow(ctx, `
INSERT INTO relations (project_id, type, key, left_site_id, right_site_id, confidence)
VALUES ($1,$2,$3,$4,$5,$6)
ON CONFLICT (project_id, type, key, left_site_id, right_site_id) DO NOTHING
RETURNING id`,
			p.Left.ProjectID, p.Type, p.Key, p.Left.ID, p.Right.ID, p.Confidence).Scan(&relationID)
		if err != nil {
			if isNoRows(err) {
				continue
			}
			return nil, fmt.Errorf("写入关系失败: %w", err)
		}
		stats[p.Type]++
		for _, s := range []relationSite{p.Left, p.Right} {
			if s.RecordID == nil {
				continue
			}
			if _, err := tx.Exec(ctx, `
INSERT INTO relation_evidence (relation_id, record_id, note)
VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`, relationID, *s.RecordID, p.Type+" evidence"); err != nil {
				return nil, fmt.Errorf("写入关系证据失败: %w", err)
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return stats, nil
}

func isNoRows(err error) bool { return errors.Is(err, pgx.ErrNoRows) }

// buildRelationPairs 是纯函数：给定站点快照产出关系边。
// 每个分组用「第一个站点 ↔ 其余站点」的星形边，避免组内笛卡尔积。
func buildRelationPairs(sites []relationSite) []relationPair {
	out := make([]relationPair, 0)
	seen := map[string]bool{}
	add := func(typ, key string, group []relationSite, confidence float64) {
		if len(group) < 2 {
			return
		}
		sort.Slice(group, func(i, j int) bool { return group[i].ID < group[j].ID })
		if len(group) > maxRelationGroup {
			group = group[:maxRelationGroup]
		}
		hub := group[0]
		for i := 1; i < len(group); i++ {
			left, right := hub, group[i]
			if left.ID > right.ID {
				left, right = right, left
			}
			if left.RecordID == nil || right.RecordID == nil {
				continue
			}
			id := fmt.Sprintf("%s\x00%s\x00%d\x00%d", typ, key, left.ID, right.ID)
			if seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, relationPair{Type: typ, Key: key, Left: left, Right: right, Confidence: confidence})
		}
	}

	byIP := map[string][]relationSite{}
	byIcon := map[string][]relationSite{}
	byTech := map[string][]relationSite{}
	byCert := map[string][]relationSite{}
	byCSeg := map[string][]relationSite{}
	byHost := map[int64]map[string]relationSite{}

	for _, s := range sites {
		if s.IP != "" {
			k := fmt.Sprintf("%d|%s", s.ProjectID, s.IP)
			byIP[k] = append(byIP[k], s)
			// C 段：同一 /24 内不同 IP 视为相邻资产（内网横向的常见跳板路径）。
			if seg := cSegment(s.IP); seg != "" {
				k := fmt.Sprintf("%d|%s", s.ProjectID, seg)
				byCSeg[k] = append(byCSeg[k], s)
			}
		}
		if s.IconSHA256 != "" {
			k := fmt.Sprintf("%d|%s", s.ProjectID, s.IconSHA256)
			byIcon[k] = append(byIcon[k], s)
		}
		if s.CertSHA256 != "" {
			k := fmt.Sprintf("%d|%s", s.ProjectID, s.CertSHA256)
			byCert[k] = append(byCert[k], s)
		}
		for _, t := range s.Tech {
			t = strings.ToLower(strings.TrimSpace(t))
			if t == "" {
				continue
			}
			k := fmt.Sprintf("%d|%s", s.ProjectID, t)
			byTech[k] = append(byTech[k], s)
		}
		if byHost[s.ProjectID] == nil {
			byHost[s.ProjectID] = map[string]relationSite{}
		}
		byHost[s.ProjectID][s.Host] = s
	}

	for k, g := range byIP {
		add("same_ip", strings.SplitN(k, "|", 2)[1], g, 0.9)
	}
	for k, g := range byCert {
		add("same_cert", strings.SplitN(k, "|", 2)[1], g, 0.95)
	}
	for k, g := range byCSeg {
		add("same_c_segment", strings.SplitN(k, "|", 2)[1], g, 0.5)
	}
	for k, g := range byIcon {
		add("same_icon", strings.SplitN(k, "|", 2)[1], g, 0.8)
	}
	for k, g := range byTech {
		add("same_fp", strings.SplitN(k, "|", 2)[1], g, 0.6)
	}

	// redirect：A 的落地页是 B 的 host。每个源站各自成边（多个源跳同一目标时
	// 不能只保留最后一条），只连项目内已存在的站点。
	for _, s := range sites {
		if s.FinalHost == "" || s.FinalHost == s.Host {
			continue
		}
		if dst, ok := byHost[s.ProjectID][s.FinalHost]; ok && dst.ID != s.ID {
			add("redirect", s.FinalHost, []relationSite{s, dst}, 0.7)
		}
	}

	// 父域 → 子域：只连项目内「已存在的直接祖先」。
	for _, hosts := range byHost {
		for host, child := range hosts {
			parent := host
			for {
				idx := strings.Index(parent, ".")
				if idx < 0 {
					break
				}
				parent = parent[idx+1:]
				if parentSite, ok := hosts[parent]; ok && parentSite.ID != child.ID {
					add("domain_parent", parent, []relationSite{parentSite, child}, 1.0)
					break
				}
			}
		}
	}
	return out
}

func (r *relationRepo) List(ctx context.Context, projectID int64, typ string, limit int) (*RelationGraph, error) {
	if limit <= 0 {
		limit = 500
	}
	if limit > 5000 {
		limit = 5000
	}
	rows, err := r.r.pool.Query(ctx, `
SELECT r.id, r.type, r.key, r.confidence,
       l.id, l.project_id, l.host, coalesce(l.value, ''), coalesce(l.title, ''), coalesce(l.ip::text, ''),
       rr.id, rr.project_id, rr.host, coalesce(rr.value, ''), coalesce(rr.title, ''), coalesce(rr.ip::text, '')
  FROM relations r
  JOIN sites l  ON l.id = r.left_site_id
  JOIN sites rr ON rr.id = r.right_site_id
 WHERE ($1 = 0 OR r.project_id = $1) AND ($2 = '' OR r.type = $2)
 ORDER BY r.id
 LIMIT $3`, projectID, typ, limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	graph := &RelationGraph{Nodes: []RelationNode{}, Edges: []RelationEdge{}}
	if err := r.r.pool.QueryRow(ctx,
		`SELECT count(*) FROM relations WHERE ($1 = 0 OR project_id = $1) AND ($2 = '' OR type = $2)`,
		projectID, typ).Scan(&graph.TotalEdges); err != nil {
		return nil, err
	}
	nodeSeen := map[int64]bool{}
	for rows.Next() {
		var e RelationEdge
		var l, rr RelationNode
		if err := rows.Scan(&e.ID, &e.Type, &e.Key, &e.Confidence,
			&l.ID, &l.ProjectID, &l.Host, &l.Value, &l.Title, &l.IP,
			&rr.ID, &rr.ProjectID, &rr.Host, &rr.Value, &rr.Title, &rr.IP); err != nil {
			return nil, err
		}
		if len(graph.Edges) >= limit {
			graph.Truncated = true
			break
		}
		e.Left, e.Right = l, rr
		graph.Edges = append(graph.Edges, e)
		for _, n := range []RelationNode{l, rr} {
			if !nodeSeen[n.ID] {
				nodeSeen[n.ID] = true
				graph.Nodes = append(graph.Nodes, n)
			}
		}
	}
	return graph, rows.Err()
}

func (r *relationRepo) Status(ctx context.Context, projectID int64) (*RelationIndexStatus, error) {
	out := &RelationIndexStatus{ByType: map[string]int64{}}
	rows, err := r.r.pool.Query(ctx,
		`SELECT type, count(*) FROM relations WHERE ($1 = 0 OR project_id = $1) GROUP BY 1 ORDER BY 2 DESC`,
		projectID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var typ string
		var n int64
		if err := rows.Scan(&typ, &n); err != nil {
			rows.Close()
			return nil, err
		}
		out.ByType[typ] = n
		out.Edges += n
	}
	rows.Close()

	if err := r.r.pool.QueryRow(ctx, `
SELECT (SELECT count(*) FROM relation_evidence e JOIN relations r ON r.id = e.relation_id
         WHERE ($1 = 0 OR r.project_id = $1)),
       (SELECT count(*) FROM sites WHERE ($1 = 0 OR project_id = $1))`, projectID).
		Scan(&out.Evidence, &out.Sites); err != nil {
		return nil, err
	}
	return out, nil
}

// cSegment 取 IPv4 的 /24 前缀（"10.0.1." 这种形式，前三位点号结尾）。
// IPv6 没有 C 段概念，直接返回空串，不参与建边。
func cSegment(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ""
	}
	for _, p := range parts {
		if p == "" {
			return ""
		}
	}
	return parts[0] + "." + parts[1] + "." + parts[2] + "."
}
