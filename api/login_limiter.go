package api

import (
	"sync"
	"time"
)

// failureLimiter 是极简的失败计数锁定器：窗口内失败满 max 失败即锁定到窗口结束。
// 并发安全。
//
// 审计 M10 的三条边界：
//   - cleanup 不再随每次请求全表遍历，改为低频周期清理（与请求量解耦，
//     每 window/4 至多一次），单条过期条目在查询路径上惰性删除；
//   - 容量硬上限 maxEntries：超限先清过期，仍超限则整体重置并只保留当前键，
//     唯一用户名刷条目无法再放大内存；
//   - 上限封顶后单次清理成本有界（maxEntries 条），锁内遍历不再随攻击增长。
type failureLimiter struct {
	mu          sync.Mutex
	max         int
	window      time.Duration
	maxEntries  int
	lastCleanup time.Time
	fails       map[string]*failureRecord
}

type failureRecord struct {
	count     int
	windowEnd time.Time
}

func newFailureLimiter(max int, window time.Duration) *failureLimiter {
	return &failureLimiter{
		max: max, window: window,
		maxEntries: 10000,
		fails:      make(map[string]*failureRecord),
	}
}

func (l *failureLimiter) blocked(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	rec, ok := l.fails[key]
	if !ok {
		return false
	}
	if now.After(rec.windowEnd) {
		delete(l.fails, key) // 惰性删除：只清查询命中的过期条目
		return false
	}
	return rec.count >= l.max
}

func (l *failureLimiter) fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	rec, ok := l.fails[key]
	if !ok || now.After(rec.windowEnd) {
		l.fails[key] = &failureRecord{count: 1, windowEnd: now.Add(l.window)}
	} else {
		rec.count++
	}
	// 容量硬上限是无条件 O(1) 检查，不挂在低频清理门槛上——
	// 否则海量唯一键可以在清理间隙里继续放大内存（单测实测过这个洞）。
	if len(l.fails) >= l.maxEntries {
		l.enforceCapacityLocked(now, key)
	}
}

func (l *failureLimiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fails, key)
}

// enforceCapacityLocked 容量兜底：先做一次（低频门槛内的）过期清理，
// 仍打满则整体重置、仅保留当前键——暴力攻击者换用户名刷条目的收益归零，
// 正常用户最多重新累计失败计数。重置本身是 O(1)（换新 map）。
func (l *failureLimiter) enforceCapacityLocked(now time.Time, key string) {
	if l.lastCleanup.IsZero() || now.Sub(l.lastCleanup) >= l.window/4 {
		l.lastCleanup = now
		for k, rec := range l.fails {
			if now.After(rec.windowEnd) {
				delete(l.fails, k)
			}
		}
	}
	if len(l.fails) < l.maxEntries {
		return
	}
	l.fails = map[string]*failureRecord{
		key: {count: 1, windowEnd: now.Add(l.window)},
	}
}
