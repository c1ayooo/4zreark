package repo

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// 资产星图：把 sites / site_endpoints 展开成一张可用于分层布局的图。
//
// 与资产列表的区别：列表按 kind 聚合分页；星图要的是完整结构，所以一次性
// 取回（有上限）并保留父子关系。边统一是「父→子」并带 rel，前端不需要再翻转。
//
// 层级：
//
//	project → root_domain → subdomain → service → endpoint
//	                    ↘ ip ↗
//
// host 本身就是 IP 时跳过域名层，直接 project → ip → service。

// 单次建图最多取多少个站点。超出的部分不静默截断——响应里带 truncated 标记。
const maxGraphSites = 2000

type AssetGraphNode struct {
	Key                string   `json:"key"`
	Kind               string   `json:"kind"` // project|root_domain|subdomain|ip|service|endpoint
	Label              string   `json:"label"`
	ProjectID          int64    `json:"project_id,omitempty"`
	SiteID             int64    `json:"site_id,omitempty"`
	Host               string   `json:"host,omitempty"`
	Port               int      `json:"port,omitempty"`
	Protocol           string   `json:"protocol,omitempty"`
	IP                 string   `json:"ip,omitempty"`
	Title              string   `json:"title,omitempty"`
	StatusCode         int      `json:"status_code,omitempty"`
	Method             string   `json:"method,omitempty"`
	Path               string   `json:"path,omitempty"`
	State              string   `json:"state,omitempty"`
	VerificationStatus string   `json:"verification_status,omitempty"`
	Tech               []string `json:"tech,omitempty"`
}

type AssetGraphEdge struct {
	Src string `json:"src"`
	Dst string `json:"dst"`
	Rel string `json:"rel"` // owns | contains | resolves | exposes | routes
}

type AssetGraphData struct {
	Nodes     []*AssetGraphNode         `json:"nodes"`
	Edges     []*AssetGraphEdge         `json:"edges"`
	Truncated bool                      `json:"truncated"`
	Limit     int                       `json:"limit"`
	Summary   bool                      `json:"summary,omitempty"`
	Counts    map[string]map[string]int `json:"counts,omitempty"`
	Totals    map[string]int            `json:"totals,omitempty"`
}

// SummarizeAssetGraph 保留项目/根域名（纯 IP 资产时保留前 12 个 IP），
// 把子域、服务、入口、路由折叠成计数。星图首屏只需要这份摘要。
func SummarizeAssetGraph(g *AssetGraphData) *AssetGraphData {
	if g == nil {
		return nil
	}
	nodeByKey := make(map[string]*AssetGraphNode, len(g.Nodes))
	for _, n := range g.Nodes {
		nodeByKey[n.Key] = n
	}

	totals := make(map[string]int)
	for _, n := range g.Nodes {
		totals[n.Kind]++
	}

	children := make(map[string][]*AssetGraphEdge)
	parentOf := make(map[string]string)
	for _, e := range g.Edges {
		children[e.Src] = append(children[e.Src], e)
		if _, ok := parentOf[e.Dst]; !ok {
			parentOf[e.Dst] = e.Src
		}
	}

	var roots []*AssetGraphNode
	for _, n := range g.Nodes {
		if n.Kind == "root_domain" {
			roots = append(roots, n)
		}
	}
	visible := make([]*AssetGraphNode, 0, len(roots)+1)
	for _, n := range g.Nodes {
		if n.Kind == "project" {
			visible = append(visible, n)
		}
	}
	visible = append(visible, roots...)
	if len(roots) == 0 {
		ipCount := 0
		for _, n := range g.Nodes {
			if n.Kind == "ip" && ipCount < 12 {
				visible = append(visible, n)
				ipCount++
			}
		}
	}

	visibleSet := make(map[string]bool, len(visible))
	for _, n := range visible {
		visibleSet[n.Key] = true
	}

	counts := make(map[string]map[string]int, len(visible))
	for _, root := range visible {
		tally := make(map[string]int)
		seen := make(map[string]bool)
		stack := append([]*AssetGraphEdge(nil), children[root.Key]...)
		for len(stack) > 0 {
			e := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if seen[e.Dst] {
				continue
			}
			seen[e.Dst] = true
			if child, ok := nodeByKey[e.Dst]; ok {
				tally[child.Kind]++
			}
			stack = append(stack, children[e.Dst]...)
		}
		counts[root.Key] = tally
	}

	edges := make([]*AssetGraphEdge, 0, len(visible))
	edgeSeen := make(map[string]bool)
	for _, e := range g.Edges {
		if !visibleSet[e.Dst] {
			continue
		}
		src := e.Src
		guard := make(map[string]bool)
		for src != "" && !visibleSet[src] && parentOf[src] != "" && !guard[src] {
			guard[src] = true
			src = parentOf[src]
		}
		if src == "" || !visibleSet[src] || src == e.Dst {
			continue
		}
		key := src + "|" + e.Dst
		if edgeSeen[key] {
			continue
		}
		edgeSeen[key] = true
		edges = append(edges, &AssetGraphEdge{Src: src, Dst: e.Dst, Rel: e.Rel})
	}

	return &AssetGraphData{
		Nodes:     visible,
		Edges:     edges,
		Truncated: g.Truncated,
		Limit:     g.Limit,
		Summary:   true,
		Counts:    counts,
		Totals:    totals,
	}
}

// BuildAssetGraph 生成资产星图。q 只使用 ProjectID 与 Q 两个字段。
func (a *AssetRepo) BuildAssetGraph(ctx context.Context, q AssetQuery) (*AssetGraphData, error) {
	if a == nil || a.r == nil {
		return nil, errUninitialized()
	}
	g := &AssetGraphData{
		Nodes: []*AssetGraphNode{},
		Edges: []*AssetGraphEdge{},
		Limit: maxGraphSites,
	}

	w, err := a.buildAssetWhere(AssetQuery{ProjectID: q.ProjectID, Q: q.Q})
	if err != nil {
		return nil, err
	}

	// 先取站点 id（受上限约束），再拉站点 + 入口明细。
	args := append(append([]any{}, w.args...), maxGraphSites+1)
	idRows, err := a.r.pool.Query(ctx,
		`SELECT s.id FROM sites s JOIN projects p ON p.id = s.project_id WHERE `+w.String()+
			` ORDER BY s.first_seen DESC, s.id DESC LIMIT $`+strconv.Itoa(len(args)),
		args...)
	if err != nil {
		return nil, fmt.Errorf("查询星图站点失败: %w", err)
	}
	ids := make([]int64, 0, maxGraphSites)
	for idRows.Next() {
		var id int64
		if err := idRows.Scan(&id); err != nil {
			idRows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	idRows.Close()
	if err := idRows.Err(); err != nil {
		return nil, err
	}
	if len(ids) > maxGraphSites {
		ids = ids[:maxGraphSites]
		g.Truncated = true
	}
	if len(ids) == 0 {
		return g, nil
	}

	rows, err := a.r.pool.Query(ctx, `
SELECT s.id, s.project_id, p.name, s.host, s.port, s.protocol,
       COALESCE(host(s.ip),''), s.http_status, COALESCE(s.title,''), COALESCE(s.state,''),
       COALESCE(s.verification_status,''), COALESCE(s.tech,'[]'::jsonb),
       COALESCE(e.scheme,''), COALESCE(e.port,0), COALESCE(e.status_code,0)
FROM sites s
JOIN projects p ON p.id = s.project_id
LEFT JOIN site_endpoints e ON e.site_id = s.id
WHERE s.id = ANY($1)
ORDER BY s.id, e.port`, ids)
	if err != nil {
		return nil, fmt.Errorf("查询星图明细失败: %w", err)
	}
	defer rows.Close()

	nodes := map[string]*AssetGraphNode{}
	edges := map[string]bool{}

	addNode := func(n *AssetGraphNode) *AssetGraphNode {
		if existing, ok := nodes[n.Key]; ok {
			return existing
		}
		nodes[n.Key] = n
		g.Nodes = append(g.Nodes, n)
		return n
	}
	addEdge := func(src, dst, rel string) {
		if src == "" || dst == "" || src == dst {
			return
		}
		k := src + "\x00" + rel + "\x00" + dst
		if edges[k] {
			return
		}
		edges[k] = true
		g.Edges = append(g.Edges, &AssetGraphEdge{Src: src, Dst: dst, Rel: rel})
	}

	var curSite int64 = -1
	var serviceKey, hostParentKey string

	for rows.Next() {
		var (
			siteID, projectID   int64
			projectName, host   string
			port, httpStatus    int
			protocol, ip, title string
			state, verification string
			techB               []byte
			scheme              string
			epPort, epStatus    int
		)
		if err := rows.Scan(&siteID, &projectID, &projectName, &host, &port, &protocol,
			&ip, &httpStatus, &title, &state, &verification, &techB,
			&scheme, &epPort, &epStatus); err != nil {
			return nil, fmt.Errorf("解析星图明细失败: %w", err)
		}

		if siteID != curSite {
			curSite = siteID
			serviceKey, hostParentKey = "", ""

			projectKey := "p:" + strconv.FormatInt(projectID, 10)
			addNode(&AssetGraphNode{Key: projectKey, Kind: "project", Label: projectName, ProjectID: projectID})

			hostKey, layerKind := classifyHost(host)
			var parentKey string
			if layerKind == "ip" {
				ipNode := addNode(&AssetGraphNode{
					Key: hostKey, Kind: "ip", Label: host, ProjectID: projectID, Host: host, IP: host,
				})
				addEdge(projectKey, ipNode.Key, "owns")
				parentKey = ipNode.Key
			} else {
				root := hostKey
				rootNode := addNode(&AssetGraphNode{
					Key: "d:" + root, Kind: "root_domain", Label: root, ProjectID: projectID, Host: root,
				})
				addEdge(projectKey, rootNode.Key, "owns")
				parentKey = rootNode.Key
				if !strings.EqualFold(host, root) {
					subNode := addNode(&AssetGraphNode{
						Key: "h:" + host, Kind: "subdomain", Label: host, ProjectID: projectID, Host: host,
					})
					addEdge(rootNode.Key, subNode.Key, "contains")
					parentKey = subNode.Key
				}
				if ip != "" {
					ipNode := addNode(&AssetGraphNode{
						Key: "i:" + ip, Kind: "ip", Label: ip, ProjectID: projectID, IP: ip,
					})
					addEdge(parentKey, ipNode.Key, "resolves")
				}
			}

			serviceKey = "s:" + strconv.FormatInt(siteID, 10)
			tech := stringArrayFromJSON(techB)
			addNode(&AssetGraphNode{
				Key: serviceKey, Kind: "service", Label: host + ":" + strconv.Itoa(port),
				ProjectID: projectID, SiteID: siteID, Host: host, Port: port,
				Protocol: protocol, IP: ip, Title: title, StatusCode: httpStatus,
				State: state, VerificationStatus: verification, Tech: tech,
			})
			addEdge(parentKey, serviceKey, "exposes")
			hostParentKey = serviceKey
		}

		if scheme != "" && epPort > 0 {
			epKey := "e:" + strconv.FormatInt(siteID, 10) + ":" + scheme + ":" + strconv.Itoa(epPort)
			addNode(&AssetGraphNode{
				Key: epKey, Kind: "endpoint", Label: scheme + "://" + host + ":" + strconv.Itoa(epPort),
				ProjectID: projectID, SiteID: siteID, Host: host, Port: epPort,
				Protocol: scheme, StatusCode: epStatus, State: state,
			})
			addEdge(hostParentKey, epKey, "routes")
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// 路由节点：挂在对应的 service 下。星图只展示每个站点最近的 20 条，
	// 避免爬虫把画布撑爆；完整列表走 /api/assets/routes。
	routes, err := a.RoutesForSites(ctx, ids, 20)
	if err != nil {
		return nil, fmt.Errorf("查询星图路由失败: %w", err)
	}
	for _, r := range routes {
		parent := "s:" + strconv.FormatInt(r.SiteID, 10)
		if _, ok := nodes[parent]; !ok {
			continue
		}
		key := "rt:" + strconv.FormatInt(r.ID, 10)
		addNode(&AssetGraphNode{
			Key: key, Kind: "route", Label: r.Method + " " + r.Path,
			ProjectID: r.ProjectID, SiteID: r.SiteID,
			Method: r.Method, Path: r.Path, StatusCode: r.StatusCode, State: "reachable",
		})
		addEdge(parent, key, "routes")
	}
	return g, nil
}

// classifyHost 决定 host 落在哪一层：
//   - IP 字面量 → 直接作为 ip 节点（跳过域名层）
//   - 域名 → eTLD+1（根域名）；host 本身是根域名时由调用方合并
func classifyHost(host string) (key, kind string) {
	h := strings.TrimSpace(host)
	if h == "" {
		return "unknown", "domain"
	}
	if net.ParseIP(h) != nil {
		return h, "ip"
	}
	root, err := publicsuffix.EffectiveTLDPlusOne(strings.ToLower(h))
	if err != nil || root == "" {
		return strings.ToLower(h), "domain"
	}
	return root, "domain"
}
