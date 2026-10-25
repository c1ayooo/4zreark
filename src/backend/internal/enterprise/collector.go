package enterprise

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

// CollectorStore 是采集器需要的最小持久化接口，由 repo 层实现。
// 与 4zreco 的 *Store 解耦，避免能力包感知具体数据库。
type CollectorStore interface {
	CreateJob(ctx context.Context, job Job) (Job, error)
	FinishJob(ctx context.Context, id, status, errMsg string) error
	SaveEntity(ctx context.Context, e *Entity) (bool, error)
	SaveDomain(ctx context.Context, jobID, domain, site, icp, entityName string) (bool, error)
	SaveDigitalCandidates(ctx context.Context, jobID, source string, hits []DigitalHit) (int64, error)
	BumpJob(ctx context.Context, id string, nodes, entities, domains, digital int) error
}

// Collector BFS 编排器（移植自 4zreco internal/enterprise/collector.go）：
// 深度/节点/速率硬限制 + 取消 + 进度落库。
// 投资与分支只作为候选情报，域名进入 candidate 资产，不自动等同授权范围。
type Collector struct {
	store       CollectorStore
	log         *log.Logger
	mu          sync.Mutex
	running     map[string]*runningJob
	rateLimit   time.Duration
	pageSize    int
	maxPageWalk int
	maxNodes    int
	// maxDigitalPerEntity 单实体数字资产拉取上限（sink 启用时生效）。
	maxDigitalPerEntity int
}
type runningJob struct {
	cancel context.CancelFunc
}

func NewCollector(store CollectorStore, lg *log.Logger) *Collector {
	if lg == nil {
		lg = log.Default()
	}
	return &Collector{
		store: store, log: lg, running: map[string]*runningJob{},
		rateLimit: 800 * time.Millisecond, pageSize: 10, maxPageWalk: 5, maxNodes: 200,
		maxDigitalPerEntity: 50,
	}
}

// SetRateLimit 调整上游请求间隔（测试与调试用；<=0 表示不限速）。
func (c *Collector) SetRateLimit(d time.Duration) { c.rateLimit = d }

// Start 启动后台 BFS 采集任务，立即返回 job（status=running）。
func (c *Collector) Start(ctx context.Context, provider Provider, job Job, root CompanyRef) (Job, error) {
	return c.start(ctx, provider, job, root, nil)
}

// StartWithDigitalSink 启动 BFS 并在每个实体详情后顺带拉取数字资产入候选池。
// sink 为 nil 等价 Start；拉取失败只记日志，不影响域名采集。
func (c *Collector) StartWithDigitalSink(ctx context.Context, provider Provider, job Job, root CompanyRef, sink DigitalAssetsProvider) (Job, error) {
	return c.start(ctx, provider, job, root, sink)
}

func (c *Collector) start(ctx context.Context, provider Provider, job Job, root CompanyRef, sink DigitalAssetsProvider) (Job, error) {
	if job.Depth < 1 {
		job.Depth = 1
	}
	if job.Depth > 3 {
		job.Depth = 3
	}
	if job.MaxNodes < 1 {
		job.MaxNodes = 20
	}
	if job.MaxNodes > c.maxNodes {
		job.MaxNodes = c.maxNodes
	}
	created, err := c.store.CreateJob(ctx, job)
	if err != nil {
		return Job{}, err
	}
	runCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	c.mu.Lock()
	c.running[created.ID] = &runningJob{cancel: cancel}
	c.mu.Unlock()
	go c.run(runCtx, provider, created, root, sink)
	return created, nil
}

// Cancel 取消运行中的任务。
func (c *Collector) Cancel(jobID string) bool {
	c.mu.Lock()
	rj, ok := c.running[jobID]
	c.mu.Unlock()
	if !ok {
		return false
	}
	rj.cancel()
	return true
}

func (c *Collector) forget(jobID string) {
	c.mu.Lock()
	delete(c.running, jobID)
	c.mu.Unlock()
}

func (c *Collector) run(ctx context.Context, provider Provider, job Job, root CompanyRef, sink DigitalAssetsProvider) {
	defer c.forget(job.ID)
	status, msg := "done", ""
	if _, err := c.walk(ctx, provider, job, root, sink); err != nil {
		if ctx.Err() != nil {
			status, msg = "canceled", "用户取消"
		} else {
			status, msg = "error", err.Error()
		}
	}
	if err := c.store.FinishJob(context.Background(), job.ID, status, msg); err != nil {
		c.log.Printf("[enterprise] 任务 %s 状态落库失败: %v", job.ID, err)
	}
}

// walk 从根企业开始逐层展开：detail → 域名入候选 → （可选）数字资产入候选池 → 子公司(分支/投资)入队。
func (c *Collector) walk(ctx context.Context, provider Provider, job Job, root CompanyRef, sink DigitalAssetsProvider) ([]string, error) {
	type item struct {
		ref        CompanyRef
		depth      int
		entityType string
		parentID   string
	}
	queue := []item{{ref: root, depth: 0, entityType: "root"}}
	visited := map[string]bool{root.ExtID: true}
	nodes := 0
	targets := make([]string, 0)
	targetSeen := map[string]bool{}

	for len(queue) > 0 {
		if err := ctx.Err(); err != nil {
			return targets, err
		}
		if nodes >= job.MaxNodes {
			return targets, fmt.Errorf("达到节点上限 %d，任务中止（可调大 max_nodes 后重试）", job.MaxNodes)
		}
		cur := queue[0]
		queue = queue[1:]

		detail, err := provider.Detail(ctx, cur.ref.ExtID)
		if err != nil {
			return targets, fmt.Errorf("获取企业详情失败(%s): %w", cur.ref.Name, err)
		}
		if err := c.pace(ctx); err != nil {
			return targets, err
		}
		nodes++
		name := cur.ref.Name
		if detail != nil && detail.Name != "" {
			name = detail.Name
		}
		e := &Entity{
			JobID: job.ID, ExtID: cur.ref.ExtID, Name: name, EntityType: cur.entityType,
			ParentExtID: cur.parentID, Depth: cur.depth,
		}
		if detail != nil {
			e.LegalPerson, e.OpenStatus, e.Phone, e.Email = detail.LegalPerson, detail.OpenStatus, detail.Phone, detail.Email
		}
		inserted, err := c.store.SaveEntity(ctx, e)
		if err != nil {
			return targets, fmt.Errorf("保存企业实体失败: %w", err)
		}
		entities, domains := 0, 0
		if inserted {
			entities = 1
		}
		if detail != nil {
			for _, d := range detail.Domains {
				if ok, err := c.store.SaveDomain(ctx, job.ID, d.Domain, d.Site, d.ICP, name); err == nil && ok {
					domains++
				}
				if normalized := normalizeDomain(d.Domain); normalized != "" && !targetSeen[normalized] {
					targetSeen[normalized] = true
					targets = append(targets, normalized)
				}
			}
		}
		// 关联域名/备案：翻页受 maxPageWalk 限制
		for page := 1; page <= c.maxPageWalk; page++ {
			if err := c.pace(ctx); err != nil {
				return targets, err
			}
			hits, more, err := provider.Domains(ctx, cur.ref.ExtID, page, c.pageSize)
			if err != nil {
				c.log.Printf("[enterprise] 域名列表失败(%s): %v", cur.ref.ExtID, err)
				break
			}
			for _, d := range hits {
				if ok, err := c.store.SaveDomain(ctx, job.ID, d.Domain, d.Site, d.ICP, name); err == nil && ok {
					domains++
				}
				if normalized := normalizeDomain(d.Domain); normalized != "" && !targetSeen[normalized] {
					targetSeen[normalized] = true
					targets = append(targets, normalized)
				}
			}
			if !more {
				break
			}
		}
		// 顺带采集数字资产（APP/小程序/公众号/新媒体）入候选池；失败不致命。
		digital := 0
		if sink != nil {
			if err := c.pace(ctx); err != nil {
				return targets, err
			}
			hits, _, err := sink.DigitalAssets(ctx, cur.ref.ExtID, 1, c.maxDigitalPerEntity)
			if err != nil {
				c.log.Printf("[enterprise] 数字资产拉取失败(%s): %v", cur.ref.ExtID, err)
			} else {
				for i := range hits {
					if hits[i].EntityName == "" {
						hits[i].EntityName = name
					}
				}
				if n, serr := c.store.SaveDigitalCandidates(ctx, job.ID, provider.Name(), hits); serr != nil {
					c.log.Printf("[enterprise] 数字资产入池失败(%s): %v", cur.ref.ExtID, serr)
				} else {
					digital = int(n)
				}
			}
		}
		if err := c.store.BumpJob(ctx, job.ID, 1, entities, domains, digital); err != nil {
			return targets, err
		}

		// 展开下一层：分支机构 + 对外投资
		if cur.depth < job.Depth {
			children, err := c.collectChildren(ctx, provider, cur.ref.ExtID, job.ExpandGroup)
			if err != nil {
				return targets, err
			}
			for _, ch := range children {
				if visited[ch.ExtID] {
					continue
				}
				visited[ch.ExtID] = true
				queue = append(queue, item{
					ref: ch.CompanyRef, depth: cur.depth + 1,
					entityType: ch.entType, parentID: cur.ref.ExtID,
				})
			}
		}
	}
	return targets, nil
}

type childRef struct {
	CompanyRef
	entType string
}

// collectChildren 抓取分支+投资（以及可选的集团成员）列表，翻页受 maxPageWalk 硬限制。
func (c *Collector) collectChildren(ctx context.Context, provider Provider, extID string, expandGroup bool) ([]childRef, error) {
	specs := []struct {
		typ string
		fn  func(ctx context.Context, extID string, page, size int) ([]CompanyRef, bool, error)
	}{
		{"branch", provider.Branches},
		{"invest", provider.Investments},
	}
	// 集团成员（兄弟公司）是可选项：数据源实现 GroupCompaniesProvider 且请求开启才展开。
	if expandGroup {
		if gc, ok := provider.(GroupCompaniesProvider); ok {
			specs = append(specs, struct {
				typ string
				fn  func(ctx context.Context, extID string, page, size int) ([]CompanyRef, bool, error)
			}{"group", gc.GroupCompanies})
		}
	}
	var out []childRef
	for _, spec := range specs {
		for page := 1; page <= c.maxPageWalk; page++ {
			if err := c.pace(ctx); err != nil {
				return nil, err
			}
			refs, more, err := spec.fn(ctx, extID, page, c.pageSize)
			if err != nil {
				// 列表失败不致命：记录后继续其余类型
				c.log.Printf("[enterprise] %s 列表失败(%s): %v", spec.typ, extID, err)
				break
			}
			for _, r := range refs {
				if r.ExtID == "" {
					continue
				}
				out = append(out, childRef{CompanyRef: r, entType: spec.typ})
			}
			if !more {
				break
			}
		}
	}
	return out, nil
}

// pace 上游请求节流，尊重取消。
func (c *Collector) pace(ctx context.Context) error {
	if c.rateLimit <= 0 {
		return nil
	}
	t := time.NewTimer(c.rateLimit)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// NormalizeDomain 供仓储层复用同一套域名规范化。
func NormalizeDomain(v string) string { return normalizeDomain(v) }
