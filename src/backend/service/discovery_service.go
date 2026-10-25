package service

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/internal/recon/ctlog"
	"github.com/c1ayooo/4zreark/internal/recon/subdomain"
	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service/notify"
)

// DiscoveryService 是巡航的「新内容发现」层：对每个项目按天做一轮被动源
// 反查（测绘引擎 live 反查 + crt.sh 证书透明），diff 掉已有资产/种子/候选后，
// 新内容落 asset_candidates 等人工确认。全程不接触目标主机——符合巡航
// 「纯被动、绝不影响目标」原则。
//
// 节奏：每项目每 24h ± 抖动一轮；测绘引擎查询受 engine_budget 按天额度
// 约束；crt.sh 每项目每天至多查 5 个根域（防止单项目刷爆 crt.sh）。
type DiscoveryService struct {
	candidates func() repo.AssetCandidateRepo
	cycle      *CycleService
	notify     *notify.NotifyManager

	stopOnce sync.Once
	stopCh   chan struct{}
}

var (
	discoveryOnce sync.Once
	discoverySvc  *DiscoveryService
)

func GetDiscoveryService() *DiscoveryService {
	discoveryOnce.Do(func() {
		discoverySvc = &DiscoveryService{
			candidates: func() repo.AssetCandidateRepo { return repo.Default().AssetCandidates() },
			cycle:      NewCycleService(),
			notify:     notify.GetGlobalManager(),
			stopCh:     make(chan struct{}),
		}
	})
	return discoverySvc
}

// Start 启动每日发现循环；启动后延迟 5 分钟错开进程启动高峰。
func (s *DiscoveryService) Start() {
	go func() {
		select {
		case <-time.After(5 * time.Minute):
		case <-s.stopCh:
			return
		}
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
			if err := s.RunOnce(ctx); err != nil {
				log.Printf("[Discovery] 发现轮失败: %v", err)
			}
			cancel()
			// 24h ± 30min 抖动，避免多实例同拍
			jitter := time.Duration(rand.Intn(60)-30) * time.Minute
			select {
			case <-s.stopCh:
				return
			case <-time.After(24*time.Hour + jitter):
			}
		}
	}()
}

func (s *DiscoveryService) Stop() {
	s.stopOnce.Do(func() { close(s.stopCh) })
}

// RunOnce 对全部项目各跑一轮发现。返回汇总统计。
func (s *DiscoveryService) RunOnce(ctx context.Context) error {
	projects, err := repo.NewAssetRepo().ListProjectOptions(ctx)
	if err != nil {
		return err
	}
	for _, p := range projects {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		// 项目暂停采集时跳过发现轮（恢复后再纳入）
		if paused, err := repo.NewAssetRepo().IsProjectPaused(ctx, p.ID); err == nil && paused {
			continue
		}
		summary, err := s.RunForProject(ctx, p.ID)
		if err != nil {
			log.Printf("[Discovery] 项目 %s(%d) 发现失败: %v", p.Name, p.ID, err)
			_ = repo.Default().RecordDiscoveryRun(ctx, p.ID, 0, 0, 0, err.Error())
			continue
		}
		_ = repo.Default().RecordDiscoveryRun(ctx, p.ID, summary.FromCTLog, summary.FromEngines, int(summary.NewCount), "")
		if summary.NewCount > 0 {
			log.Printf("[Discovery] 项目 %s 发现 %d 个新候选（crt.sh %d / 引擎 %d）",
				p.Name, summary.NewCount, summary.FromCTLog, summary.FromEngines)
		}
	}
	return nil
}

// DiscoverySummary 一轮发现的回执。
type DiscoverySummary struct {
	Sources     int   `json:"sources"`
	FromCTLog   int   `json:"from_ctlog"`
	FromEngines int   `json:"from_engines"`
	FromPassive int   `json:"from_passive"`
	NewCount    int64 `json:"new_count"`
}

// discoveryRootsCap 发现轮每项目最多展开的根域数（与 crt.sh 配额共用，
// 两个源都按这份根域清单走）。
const discoveryRootsCap = 5

// collectDiscoveryRoots 挑出参与本轮发现的启用 domain 种子根域（纯函数）。
// 禁用种子不参与发现轮：用户关掉的种子不该继续烧配额。
func collectDiscoveryRoots(seeds []*repo.Seed, cap int) []string {
	roots := make([]string, 0, cap)
	seen := map[string]bool{}
	for _, seed := range seeds {
		if !seed.Enabled || seed.Kind != "domain" || len(roots) >= cap {
			continue
		}
		root := normalizeDiscoverDomain(seed.Value)
		if root == "" || seen[root] {
			continue
		}
		seen[root] = true
		roots = append(roots, root)
	}
	return roots
}

// RunForProject 对单个项目执行一轮被动发现。
func (s *DiscoveryService) RunForProject(ctx context.Context, projectID int64) (*DiscoverySummary, error) {
	seeds, err := repo.Default().Seeds().ListSeeds(ctx, projectID)
	if err != nil {
		return nil, err
	}
	if len(seeds) == 0 {
		return &DiscoverySummary{}, nil
	}

	summary := &DiscoverySummary{}
	discovered := map[string]repo.AssetCandidate{} // key: domain

	roots := collectDiscoveryRoots(seeds, discoveryRootsCap)

	// 源 1：crt.sh 证书透明（每项目至多 discoveryRootsCap 个根域，防刷 crt.sh）
	for _, root := range roots {
		names, err := ctlog.QuerySubdomains(ctx, root)
		if err != nil {
			log.Printf("[Discovery] crt.sh 查询 %s 失败（跳过）: %v", root, err)
			continue
		}
		for _, n := range names {
			discovered[n] = repo.AssetCandidate{Kind: "domain", Value: n, Source: "crtsh", Confidence: 60}
			summary.FromCTLog++
		}
		// crt.sh 慢：查询间隔 3s，绝不给 crt.sh 施压
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}

	// 源 2：测绘引擎 live 反查——复用 CycleService.expandDomainLive 的单种子口径，
	// 只取域名结果（引擎查询进 engine_budget 按天额度）。
	for _, seed := range seeds {
		if !seed.Enabled || seed.Kind != "domain" {
			continue
		}
		root := normalizeDiscoverDomain(seed.Value)
		if root == "" {
			continue
		}
		if _, seen := discovered[root]; seen {
			continue
		}
		targets, _, err := s.cycle.expandDomainLive(ctx, projectID, root, seed.Capability, 100)
		if err != nil {
			continue
		}
		for _, t := range targets {
			host := normalizeDiscoverDomain(t.Host)
			if host == "" {
				continue
			}
			if _, seen := discovered[host]; !seen {
				discovered[host] = repo.AssetCandidate{Kind: "domain", Value: host, Source: "engine", Confidence: 55}
				summary.FromEngines++
			}
		}
	}
	// 源 3：免 key 公开被动 DNS 聚合（OTX/RapidDNS/HackerTarget + 国内三源）。
	// 复用 recon 包的 Enumerate：去重/归一化/按源容错都在里面，出网走 recon 代理。
	// 与 crt.sh 共用同一份根域清单；这些源很轻，间隔 2s 即可。
	for _, root := range roots {
		res, err := subdomain.Enumerate(ctx, root, subdomain.Options{
			EnablePassiveDNS:   true,
			EnableCNPassiveDNS: true,
			Limit:              200,
			Timeout:            30 * time.Second,
		})
		if err != nil {
			log.Printf("[Discovery] 被动源聚合 %s 失败（跳过）: %v", root, err)
			continue
		}
		for src, e := range res.Errors { // 有源失败只记日志，不拖累其他源
			log.Printf("[Discovery] 被动源 %s/%s 失败: %v", root, src, e)
		}
		for _, h := range res.Hits {
			host := normalizeDiscoverDomain(h.Name)
			if host == "" {
				continue
			}
			if _, seen := discovered[host]; !seen {
				discovered[host] = repo.AssetCandidate{Kind: "domain", Value: host, Source: "passive", Confidence: 50}
				summary.FromPassive++
			}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	if summary.FromCTLog > 0 || summary.FromEngines > 0 || summary.FromPassive > 0 {
		summary.Sources = 1
	}

	// Diff：减去已有站点 host、种子值、pending 候选——只留真正的新内容。
	existing, err := s.knownDomains(ctx, projectID)
	if err != nil {
		return nil, err
	}
	items := make([]repo.AssetCandidate, 0, len(discovered))
	for v, c := range discovered {
		if existing[v] {
			continue
		}
		items = append(items, c)
	}
	if len(items) == 0 {
		return summary, nil
	}
	inserted, err := s.candidates().UpsertCandidates(ctx, projectID, items)
	if err != nil {
		return nil, err
	}
	summary.NewCount = inserted
	if inserted > 0 {
		pending, _ := s.candidates().CountPending(ctx, projectID)
		name := ""
		if p, err := repo.NewAssetRepo().GetProject(ctx, projectID); err == nil {
			name = p.Name
		}
		s.notify.NotifyAssetChange("巡航发现新资产候选", fmt.Sprintf(
			"项目「%s」本轮发现 %d 个新资产候选，当前待确认 %d 个。前往项目「发现候选」面板批量确认。",
			name, inserted, pending),
			map[string]interface{}{"link": fmt.Sprintf("/projects/%d", projectID)})
	}
	return summary, nil
}

// knownDomains 汇总三类「已见」域名：sites 已有 host 归一、种子值、pending 候选值。
func (s *DiscoveryService) knownDomains(ctx context.Context, projectID int64) (map[string]bool, error) {
	known := map[string]bool{}

	rows, err := repo.Default().Pool().Query(ctx,
		`select distinct lower(host) from sites where project_id = $1 limit 50000`, projectID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			rows.Close()
			return nil, err
		}
		known[h] = true
		// 站点 host 是子域时，其注册域也算已见（引擎反查常返回注册域本身）
		if parts := strings.Split(h, "."); len(parts) > 2 {
			known[strings.Join(parts[len(parts)-2:], ".")] = true
		}
	}
	rows.Close()

	seeds, err := repo.Default().Seeds().ListSeeds(ctx, projectID)
	if err != nil {
		return nil, err
	}
	for _, seed := range seeds {
		if seed.Kind == "domain" {
			known[normalizeDiscoverDomain(seed.Value)] = true
		}
	}

	candidates, err := s.candidates().ListCandidates(ctx, projectID, string(repo.CandidatePending), 1000)
	if err != nil {
		return nil, err
	}
	for _, c := range candidates {
		known[strings.ToLower(c.Value)] = true
	}
	return known, nil
}

// normalizeDiscoverDomain 归一化发现域名：小写、去协议/路径/端口、去尾部点。
func normalizeDiscoverDomain(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.TrimPrefix(v, "https://")
	v = strings.TrimPrefix(v, "http://")
	if i := strings.IndexAny(v, "/:"); i >= 0 {
		v = v[:i]
	}
	v = strings.TrimSuffix(v, ".")
	v = strings.TrimPrefix(v, "*.")
	if v == "" || !strings.Contains(v, ".") {
		return ""
	}
	return v
}

// AcceptOrReject 统一入口：accept=true 走候选转种子，false 仅标记拒绝。
func (s *DiscoveryService) AcceptOrReject(ctx context.Context, projectID int64, ids []int64, accept bool) (int64, error) {
	if accept {
		return s.AcceptCandidates(ctx, projectID, ids)
	}
	return repo.Default().AssetCandidates().DecideCandidates(ctx, projectID, ids, false)
}

// AcceptCandidates 人工确认候选：建 domain 种子（后续巡航周期会对它做展开/探测）。
func (s *DiscoveryService) AcceptCandidates(ctx context.Context, projectID int64, ids []int64) (int64, error) {
	updated, err := repo.Default().AssetCandidates().DecideCandidates(ctx, projectID, ids, true)
	if err != nil {
		return 0, err
	}
	// 接受的 domain 候选转成种子，纳入巡航与资产展开
	candidates, err := repo.Default().AssetCandidates().ListCandidates(ctx, projectID, string(repo.CandidateAccepted), 500)
	if err != nil {
		return updated, err
	}
	accepted := map[int64]bool{}
	for _, id := range ids {
		accepted[id] = true
	}
	for _, c := range candidates {
		if !accepted[c.ID] || c.Kind != "domain" {
			continue
		}
		// 种子已存在时 CreateSeed 报错，忽略即可（幂等）
		_ = repo.Default().Seeds().CreateSeed(ctx, &repo.Seed{
			ProjectID: projectID, Kind: "domain", Value: c.Value, Enabled: true,
		})
	}
	return updated, nil
}
