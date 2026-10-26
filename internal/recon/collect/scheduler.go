// scheduler.go (source, domain) 工作单元轮转调度器：
//
// claim 三条件——该源 inflight 未超 / 距该源上次开工超 MinInterval / 全局
// worker 未超上限；轮转 pick 防单源占满；瞬态错误退避重试 1 次，同源连续
// 2 个单元瞬态失败短路该源剩余单元。等待间隔期间 worker 切去跑其他源的
// 可执行单元——固定 sleep 不再占用墙钟。
//
// Scheduler 实例内的源状态（上次开工时刻/瞬态连败）跨多次 RunUnits 保持，
// 主查询与 ICP 裂变两阶段天然共享源限速。
package collect

import (
	"context"
	"sync"
	"time"
)

// Unit 一个可执行工作单元（引擎子查询/裂变查询）。
type Unit struct {
	Source string // 引擎/源名（策略键）
	Label  string // 人读标识（日志）：engine · domain
	Run    func(ctx context.Context) error
}

// UnitOutcome 单元终态。
type UnitOutcome struct {
	Index      int
	Err        error // 最终错误（重试后仍失败；Skipped 时为跳过原因）
	Attempts   int
	Skipped    bool
	SkipReason string
}

// sourceState 调度器内跨阶段保持的源状态（读写一律持 Scheduler.mu）。
type sourceState struct {
	inflight        int
	lastStart       time.Time
	transientStreak int
	tripped         bool // 连续瞬态失败短路：该源剩余单元本轮跳过
}

// Scheduler 工作单元调度器。单实例绑定一轮调度（主查询 + 裂变共用）。
type Scheduler struct {
	mu     sync.Mutex
	states map[string]*sourceState
}

// NewScheduler 创建调度器。
func NewScheduler() *Scheduler {
	return &Scheduler{states: map[string]*sourceState{}}
}

func (s *Scheduler) state(source string) *sourceState {
	st, ok := s.states[source]
	if !ok {
		st = &sourceState{}
		s.states[source] = st
	}
	return st
}

// snapshot 持锁读取源状态与策略（锁内调用 PolicyFor——其内部自持 RWMutex，
// 无锁序环）。
func (s *Scheduler) eligibleLocked(unit Unit) bool {
	st := s.state(unit.Source)
	policy := PolicyFor(unit.Source)
	return !st.tripped &&
		st.inflight < policy.MaxInflight &&
		time.Since(st.lastStart) >= policy.MinInterval
}

// RunUnits 执行全部单元，返回与 units 等长的终态列表。
// maxWorkers<=0 按 min(8, len(units))。
func (s *Scheduler) RunUnits(ctx context.Context, units []Unit, maxWorkers int) []UnitOutcome {
	outcomes := make([]UnitOutcome, len(units))
	if len(units) == 0 {
		return outcomes
	}
	for i := range outcomes {
		outcomes[i].Index = i
	}
	workers := maxWorkers
	if workers <= 0 {
		workers = 8
	}
	if workers > len(units) {
		workers = len(units)
	}

	var (
		mu      sync.Mutex // 保护 pending / outcomes
		pending = make([]bool, len(units))
	)
	for i := range pending {
		pending[i] = true
	}
	jobs := make(chan int)

	// 生产者：轮转 pick 可执行单元；无可执行单元时等最早可开工时刻。
	go func() {
		defer close(jobs)
		cursor := 0
		for {
			mu.Lock()
			pick, pendCount := -1, 0
			n := len(units)
			for k := 0; k < n; k++ {
				idx := (cursor + k) % n
				if !pending[idx] {
					continue
				}
				s.mu.Lock()
				tripped := s.state(units[idx].Source).tripped
				s.mu.Unlock()
				if tripped { // 源已短路：pending 单元立即标记跳过
					pending[idx] = false
					outcomes[idx].Skipped = true
					outcomes[idx].SkipReason = "source circuit-open"
					continue
				}
				pendCount++
				s.mu.Lock()
				eligible := s.eligibleLocked(units[idx])
				s.mu.Unlock()
				if eligible && pick < 0 {
					pick = idx
				}
			}
			if pick < 0 && pendCount == 0 {
				mu.Unlock()
				return // 全部单元已终态
			}
			if pick < 0 {
				mu.Unlock()
				if !waitSlot(ctx, s, units, &mu, pending) {
					// ctx 取消：剩余单元全部标记跳过
					mu.Lock()
					for i := range pending {
						if pending[i] {
							pending[i] = false
							outcomes[i].Skipped = true
							outcomes[i].SkipReason = "canceled"
						}
					}
					mu.Unlock()
					return
				}
				continue
			}
			// claim：占 inflight、记开工时刻、摘出 pending
			s.mu.Lock()
			st := s.state(units[pick].Source)
			st.inflight++
			st.lastStart = time.Now()
			s.mu.Unlock()
			pending[pick] = false
			cursor = (pick + 1) % n
			mu.Unlock()

			select {
			case jobs <- pick:
			case <-ctx.Done():
				s.mu.Lock()
				s.state(units[pick].Source).inflight--
				s.mu.Unlock()
				mu.Lock()
				outcomes[pick].Skipped = true
				outcomes[pick].SkipReason = "canceled"
				mu.Unlock()
				return
			}
		}
	}()

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				out := s.runWithRetry(ctx, units[idx])
				s.mu.Lock()
				s.state(units[idx].Source).inflight--
				s.mu.Unlock()
				mu.Lock()
				outcomes[idx] = out
				outcomes[idx].Index = idx
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return outcomes
}

// runWithRetry 瞬态错误退避重试 1 次；同源连续 2 个单元瞬态终败短路该源
// （后续单元由生产者按 tripped 跳过——置 tripped 后把本调用时刻仍 pending
// 的同源单元标记 skipped 的动作由生产者下一轮巡检完成）。
func (s *Scheduler) runWithRetry(ctx context.Context, unit Unit) UnitOutcome {
	const maxAttempts = 2
	out := UnitOutcome{}
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			out.Skipped, out.SkipReason = true, "canceled"
			out.Attempts = attempt - 1
			return out
		}
		out.Attempts = attempt
		out.Err = nil
		err := unit.Run(ctx)
		if err == nil {
			s.mu.Lock()
			s.state(unit.Source).transientStreak = 0
			s.mu.Unlock()
			return out
		}
		out.Err = err
		if ClassifyError(err) != ErrorClassTransient {
			return out
		}
		if attempt < maxAttempts {
			select { // 退避 1s，期间响应取消
			case <-ctx.Done():
			case <-time.After(1 * time.Second):
			}
		}
	}
	// 瞬态终败：累计源连败，≥2 短路
	s.mu.Lock()
	st := s.state(unit.Source)
	st.transientStreak++
	if st.transientStreak >= 2 {
		st.tripped = true
	}
	s.mu.Unlock()
	return out
}

// waitSlot 等待到任一 pending 源的最早可开工时刻（含 inflight 归零）；返回
// false 表示 ctx 取消。mu 由调用方持有，函数内短暂释放。
func waitSlot(ctx context.Context, s *Scheduler, units []Unit, mu *sync.Mutex, pending []bool) bool {
	for {
		mu.Lock()
		earliest := time.Time{}
		pendLeft := false
		for idx := range units {
			if !pending[idx] {
				continue
			}
			pendLeft = true
			s.mu.Lock()
			st := s.state(units[idx].Source)
			if st.tripped {
				s.mu.Unlock()
				continue
			}
			next := st.lastStart.Add(PolicyFor(units[idx].Source).MinInterval)
			s.mu.Unlock()
			if earliest.IsZero() || next.Before(earliest) {
				earliest = next
			}
		}
		mu.Unlock()
		if !pendLeft {
			return true // 全部已有终态，回生产者收尾
		}
		wait := 50 * time.Millisecond
		if !earliest.IsZero() {
			wait = time.Until(earliest)
			if wait > 500*time.Millisecond {
				wait = 500 * time.Millisecond
			}
			if wait < 10*time.Millisecond {
				wait = 10 * time.Millisecond
			}
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(wait):
			return true
		}
	}
}

// Acquire 单条查询的源限速门（BFS 型流程用——查询间有数据依赖不能预展开成
// 工作单元时，逐条过闸仍共享该源的间隔/并发策略）。成功返回 release 函数。
func (s *Scheduler) Acquire(ctx context.Context, source string) (func(), error) {
	for {
		s.mu.Lock()
		st := s.state(source)
		policy := PolicyFor(source)
		if !st.tripped && st.inflight < policy.MaxInflight && time.Since(st.lastStart) >= policy.MinInterval {
			st.inflight++
			st.lastStart = time.Now()
			s.mu.Unlock()
			release := func() {
				s.mu.Lock()
				s.state(source).inflight--
				s.mu.Unlock()
			}
			return release, nil
		}
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}
