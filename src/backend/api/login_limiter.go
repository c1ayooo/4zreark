package api

import (
	"sync"
	"time"
)

// failureLimiter 是极简的失败计数锁定器：窗口内失败满 max 失败即锁定到窗口结束。
// 并发安全；条目在窗口过期后惰性清理。
type failureLimiter struct {
	mu      sync.Mutex
	max     int
	window  time.Duration
	fails   map[string]*failureRecord
}

type failureRecord struct {
	count     int
	windowEnd time.Time
}

func newFailureLimiter(max int, window time.Duration) *failureLimiter {
	return &failureLimiter{max: max, window: window, fails: make(map[string]*failureRecord)}
}

func (l *failureLimiter) blocked(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.cleanupLocked(time.Now())
	rec, ok := l.fails[key]
	return ok && rec.count >= l.max && time.Now().Before(rec.windowEnd)
}

func (l *failureLimiter) fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	rec, ok := l.fails[key]
	if !ok || now.After(rec.windowEnd) {
		l.fails[key] = &failureRecord{count: 1, windowEnd: now.Add(l.window)}
		return
	}
	rec.count++
}

func (l *failureLimiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fails, key)
}

// cleanupLocked 顺手清掉过期条目，避免长期运行下的 map 膨胀。
func (l *failureLimiter) cleanupLocked(now time.Time) {
	for k, rec := range l.fails {
		if now.After(rec.windowEnd) {
			delete(l.fails, k)
		}
	}
}
