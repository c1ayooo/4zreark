package service

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/repo"
)

// SeedCollectionService 种子收集队列：多选/全选种子（域名/公司(ICP)/证书组织）
// 排队做 live 收集，单 worker 串行推进（慢速原则；引擎查询受按天额度约束）。
// 展开结果 diff 已有后落 asset_candidates（与巡航 v2 同口径：新内容人工确认）。
type SeedCollectionService struct {
	cycle *CycleService

	queue    chan string
	workerMu sync.Mutex
	workerOn bool
	stopOnce sync.Once
	stopCh   chan struct{}
}

const (
	collectQueueSize  = 100
	collectJobTimeout = 10 * time.Minute
)

var (
	collectOnce sync.Once
	collectSvc  *SeedCollectionService
)

func GetSeedCollectionService() *SeedCollectionService {
	collectOnce.Do(func() {
		collectSvc = &SeedCollectionService{
			cycle:  NewCycleService(),
			queue:  make(chan string, collectQueueSize),
			stopCh: make(chan struct{}),
		}
	})
	return collectSvc
}

var ErrCollectQueueFull = fmt.Errorf("收集队列已满（%d），请稍后再试", collectQueueSize)

// liveCapableKinds 有 live 收集路径的种子种类。
var liveCapableKinds = map[string]bool{"domain": true, "company": true, "cert": true}

// Enqueue 把种子加入收集队列。返回 (入队数, 跳过说明)。
func (s *SeedCollectionService) Enqueue(ctx context.Context, projectID int64, seedIDs []int64, all bool) (int, []string, error) {
	seeds, err := repo.Default().Seeds().ListSeeds(ctx, projectID)
	if err != nil {
		return 0, nil, err
	}
	byID := map[int64]*repo.Seed{}
	for _, sd := range seeds {
		byID[sd.ID] = sd
	}

	var targets []*repo.Seed
	skipped := []string{}
	if all {
		for _, sd := range seeds {
			if liveCapableKinds[sd.Kind] && sd.Enabled {
				targets = append(targets, sd)
			}
		}
	} else {
		for _, id := range seedIDs {
			sd, ok := byID[id]
			if !ok {
				skipped = append(skipped, fmt.Sprintf("种子 %d 不属于该项目", id))
				continue
			}
			if !sd.Enabled {
				skipped = append(skipped, fmt.Sprintf("%s（已禁用）", sd.Value))
				continue
			}
			if !liveCapableKinds[sd.Kind] {
				skipped = append(skipped, fmt.Sprintf("%s（%s 无收集能力）", sd.Value, sd.Kind))
				continue
			}
			targets = append(targets, sd)
		}
	}
	if len(targets) == 0 {
		return 0, skipped, nil
	}

	// 去重：同一种子已有 queued/running 任务时跳过
	existing, err := repo.Default().SeedCollection().ListJobs(ctx, projectID, 200)
	if err != nil {
		return 0, skipped, err
	}
	active := map[int64]bool{}
	for _, j := range existing {
		if j.Status == "queued" || j.Status == "running" {
			active[j.SeedID] = true
		}
	}

	s.ensureWorker()
	enqueued := 0
	for _, sd := range targets {
		if active[sd.ID] {
			skipped = append(skipped, fmt.Sprintf("%s（已在队列中）", sd.Value))
			continue
		}
		if len(s.queue) >= cap(s.queue) {
			skipped = append(skipped, fmt.Sprintf("%s（队列已满）", sd.Value))
			continue
		}
		job, err := repo.Default().SeedCollection().CreateJob(ctx, projectID, sd.ID, sd.Kind, sd.Value)
		if err != nil {
			skipped = append(skipped, fmt.Sprintf("%s（入库失败: %v）", sd.Value, err))
			continue
		}
		select {
		case s.queue <- job.ID:
			enqueued++
		default:
			// 通道满：用独立短超时收尾，请求 ctx 取消不该把任务留在 queued
			s.finishJob(job.ID, "error", 0, "队列通道满")
			skipped = append(skipped, fmt.Sprintf("%s（队列已满）", sd.Value))
		}
	}
	return enqueued, skipped, nil
}

// ensureWorker 懒启动单 worker；启动前先恢复上次进程残留的任务。
func (s *SeedCollectionService) ensureWorker() {
	s.workerMu.Lock()
	defer s.workerMu.Unlock()
	if s.workerOn {
		return
	}
	s.workerOn = true
	s.recoverStuckJobs()
	go func() {
		for {
			select {
			case <-s.stopCh:
				return
			case id := <-s.queue:
				s.runJob(id)
			}
		}
	}()
	log.Printf("[SeedCollect] 收集 worker 已启动")
}

// recoverStuckJobs 把上次进程残留的 running/queued 任务重新排入通道。
// 通道是纯内存的，重启即丢；不恢复的话这些任务永远停在原地，
// 还会一直计入 collect_active 并挡住同种子的再次入队。
func (s *SeedCollectionService) recoverStuckJobs() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	repos := repo.Default()
	if _, err := repos.SeedCollection().ResetStaleRunning(ctx); err != nil {
		log.Printf("[SeedCollect] 恢复残留 running 任务失败: %v", err)
		return
	}
	ids, err := repos.SeedCollection().ListQueuedJobIDs(ctx, collectQueueSize)
	if err != nil {
		log.Printf("[SeedCollect] 读取残留 queued 任务失败: %v", err)
		return
	}
	for _, id := range ids {
		select {
		case s.queue <- id:
		default:
			log.Printf("[SeedCollect] 残留任务 %s 超出通道容量，留待下次入队", id)
		}
	}
	if len(ids) > 0 {
		log.Printf("[SeedCollect] 已恢复 %d 个残留收集任务", len(ids))
	}
}

// finishJob 用独立短超时收尾：工作 ctx 超时后它仍能把任务落账，
// 否则任务永远停在 running。
func (s *SeedCollectionService) finishJob(jobID, status string, found int, errMsg string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = repo.Default().SeedCollection().FinishJob(ctx, jobID, status, found, errMsg)
}

// runJob 执行单个收集任务：按 ID claim → kind 分发 live 展开 → diff → 候选。
func (s *SeedCollectionService) runJob(jobID string) {
	ctx, cancel := context.WithTimeout(context.Background(), collectJobTimeout)
	defer cancel()
	repos := repo.Default()

	job, err := repos.SeedCollection().ClaimJob(ctx, jobID)
	if err != nil {
		log.Printf("[SeedCollect] 认领任务 %s 失败: %v", jobID, err)
		return
	}
	if job == nil {
		// 已不在队列（重复消息/恢复重推后已被处理），直接丢弃
		log.Printf("[SeedCollect] 任务 %s 已不在队列中，跳过", jobID)
		return
	}

	seed, err := repos.Seeds().ListSeeds(ctx, job.ProjectID)
	if err != nil {
		s.finishJob(job.ID, "error", 0, "读取种子失败: "+err.Error())
		return
	}
	var target *repo.Seed
	for _, sd := range seed {
		if sd.ID == job.SeedID {
			target = sd
			break
		}
	}
	if target == nil {
		s.finishJob(job.ID, "error", 0, "种子已删除")
		return
	}

	var targets []repo.TargetInput
	var warnings []string
	switch job.Kind {
	case "domain":
		targets, warnings, err = s.cycle.expandDomainLive(ctx, job.ProjectID, normalizeDiscoverDomain(target.Value), target.Capability, 300)
	case "company":
		targets, warnings, err = s.cycle.expandCompanyLive(ctx, job.ProjectID, strings.TrimSpace(target.Value), target.Capability, 200)
	case "cert":
		targets, warnings, err = s.cycle.expandCertLive(ctx, job.ProjectID, target.Value, target.Capability, 200)
	default:
		s.finishJob(job.ID, "error", 0, "该种子种类无收集能力")
		return
	}
	if err != nil {
		s.finishJob(job.ID, "error", 0, "展开失败: "+err.Error())
		return
	}
	for _, w := range warnings {
		log.Printf("[SeedCollect] %s: %s", job.Value, w)
	}

	// diff 已有 → 候选（与 discovery 同口径）
	known, err := GetDiscoveryService().knownDomains(ctx, job.ProjectID)
	if err != nil {
		s.finishJob(job.ID, "error", 0, "读取已见域名失败: "+err.Error())
		return
	}
	items := make([]repo.AssetCandidate, 0, len(targets))
	seen := map[string]bool{}
	for _, t := range targets {
		host := normalizeDiscoverDomain(t.Host)
		if host == "" || known[host] || seen[host] {
			continue
		}
		seen[host] = true
		items = append(items, repo.AssetCandidate{
			Kind: "domain", Value: host, Source: "collect", Confidence: 55,
		})
	}
	inserted, err := repos.AssetCandidates().UpsertCandidates(ctx, job.ProjectID, items)
	if err != nil {
		s.finishJob(job.ID, "error", 0, "候选入库失败: "+err.Error())
		return
	}
	s.finishJob(job.ID, "done", int(inserted), "")
	log.Printf("[SeedCollect] %s (%s) 完成: 展开 %d 目标，新增候选 %d", job.Value, job.Kind, len(targets), inserted)
}

// CruiseStatus 巡航状态视图（前端可见性）：发现轮 + 站点巡检汇总。
type CruiseStatus struct {
	Discovery *repo.DiscoveryRun `json:"discovery"`
	Watch     struct {
		Reachable     int64 `json:"reachable"`
		Checked24h    int64 `json:"checked_24h"`
		Changed       int64 `json:"changed_total"`
		Pending       int64 `json:"candidates_pending"`
		CollectActive int64 `json:"collect_active"`
	} `json:"watch"`
}

// GetCruiseStatus 汇总某项目的巡航状态。
func (s *SeedCollectionService) GetCruiseStatus(ctx context.Context, projectID int64) (*CruiseStatus, error) {
	repos := repo.Default()
	st := &CruiseStatus{}
	d, err := repos.LastDiscoveryRun(ctx, projectID)
	if err != nil {
		return nil, err
	}
	st.Discovery = d
	if err := repos.Pool().QueryRow(ctx, `
select (select count(*) from sites where project_id=$1 and state='reachable'),
       (select count(*) from sites where project_id=$1 and content_checked_at >= now() - interval '24 hours'),
       (select count(*) from sites where project_id=$1 and content_changed_at is not null),
       (select count(*) from asset_candidates where project_id=$1 and status='pending'),
       (select count(*) from seed_collection_jobs where project_id=$1 and status in ('queued','running'))`,
		projectID).Scan(&st.Watch.Reachable, &st.Watch.Checked24h, &st.Watch.Changed,
		&st.Watch.Pending, &st.Watch.CollectActive); err != nil {
		return nil, err
	}
	return st, nil
}

// 编译期锚点：TaskConfig/TaskType 引用保持与慢爬路径一致。
var _ = models.TaskTypeCrawler
