// worker.go 周期调度共享 worker 骨架：30s tick 扫到期任务 → inflight 去重 →
// 有界并发执行。info_collect 与 recon 两套 worker 收敛到此（消除行为漂移：
// 此前 recon 侧缺退避、采集侧缺域名并行，互有长短无人对齐）。
package collect

import (
	"context"
	"log"
	"sync"
	"time"
)

// InflightRegistry 调度级 inflight 去重（防同任务重叠；供 RunNow 手动触发
// 与 worker 共享判重）。
type InflightRegistry struct {
	mu sync.Mutex
	m  map[string]bool
}

// NewInflightRegistry 创建注册表。
func NewInflightRegistry() *InflightRegistry {
	return &InflightRegistry{m: map[string]bool{}}
}

// Has 任务是否在跑。
func (r *InflightRegistry) Has(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.m[id]
}

// Add 标记任务在跑；已存在返回 false。
func (r *InflightRegistry) Add(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.m[id] {
		return false
	}
	r.m[id] = true
	return true
}

// Remove 清除任务在跑标记。
func (r *InflightRegistry) Remove(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.m, id)
}

// ScheduleTask 到期任务引用（按 ID 二次加载，避免 worker 持有整对象）。
type ScheduleTask struct {
	ID string
}

// WorkerOptions 共享 worker 配置。
type WorkerOptions struct {
	Name          string // 日志标识
	Tick          time.Duration
	MaxConcurrent int
	// Quiet 关闭到期扫描失败的日志（默认打一条,与宿主 log.Printf 习惯一致;
	// 原 4zreco 实现注入 zap Logger,4zrec 无 zap 依赖,降级为开关）。
	Quiet bool
	// Inflight 可选注入：与手动触发（RunNow）共享判重时传入 handler 级注册表；
	// nil 时 worker 内部自建（仅防 worker 内重叠）。
	Inflight *InflightRegistry
	// ListDue 返回当前到期任务（实现方负责各自的到期查询语义）。
	ListDue func() ([]ScheduleTask, error)
	// Execute 按 ID 执行单个任务（实现方自行二次加载与兜底）。
	Execute func(ctx context.Context, id string)
}

// RunScheduleWorker 阻塞运行直到 ctx 取消。
func RunScheduleWorker(ctx context.Context, opts WorkerOptions) {
	inflight := opts.Inflight
	if inflight == nil {
		inflight = NewInflightRegistry()
	}
	sem := make(chan struct{}, opts.MaxConcurrent)
	var wg sync.WaitGroup
	defer wg.Wait()

	ticker := time.NewTicker(opts.Tick)
	defer ticker.Stop()
	for {
		due, err := opts.ListDue()
		if err == nil {
			for _, t := range due {
				if !inflight.Add(t.ID) {
					continue
				}
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					inflight.Remove(t.ID)
					return
				}
				wg.Add(1)
				go func(id string) {
					defer wg.Done()
					defer func() { <-sem }()
					defer inflight.Remove(id)
					opts.Execute(ctx, id)
				}(t.ID)
			}
		} else if !opts.Quiet {
			log.Printf("[collect:%s] 扫描到期任务失败: %v", opts.Name, err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
