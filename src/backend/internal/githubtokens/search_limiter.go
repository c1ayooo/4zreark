package githubtokens

import (
	"context"
	"sync"
	"time"
)

// SearchLimiter — 进程级 GitHub Search API 共享滑动窗口限速器。
//
// GitHub 的 search 配额按账号（token）计：REST 搜索 30 次/分。平台内三个独立
// 消费方（泄露监控轮询、dork 交互查询、vulnintel repositories 搜索）各自打点
// 时互不知晓，叠加会触发 secondary rate limit（403）打断监控轮询。
// 本限速器按 token 维度共享窗口：同一账号的全部 search 请求合计限额，
// 换号（池轮换）自动获得新窗口，与账号级配额语义一致。

const (
	// DefaultSearchPerMinute GitHub REST search 桶账号级限额（30/min）。
	DefaultSearchPerMinute = 30
	searchWindow           = time.Minute
)

type searchTimestamps []time.Time

// SearchLimiter 按 token 共享的滑动窗口限速器。
type SearchLimiter struct {
	mu      sync.Mutex
	limit   int
	windows map[string]searchTimestamps
	nowFn   func() time.Time
}

// NewSearchLimiter 创建共享 search 限速器（limit ≤0 取默认 30/min）。
func NewSearchLimiter(limit int) *SearchLimiter {
	if limit <= 0 {
		limit = DefaultSearchPerMinute
	}
	return &SearchLimiter{
		limit:   limit,
		windows: map[string]searchTimestamps{},
		nowFn:   time.Now,
	}
}

// Acquire 阻塞直到 token 有 search 配额或 ctx 取消。token 为空直接放行
// （匿名请求按 IP 限速，无法按账号协调，交由调用方自身的保守间隔兜底）。
func (l *SearchLimiter) Acquire(ctx context.Context, token string) error {
	if l == nil || token == "" {
		return nil
	}
	for {
		wait, ok := l.tryAcquire(token)
		if ok {
			return nil
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// TryAcquire 非阻塞尝试；返回是否获得配额（不等待）。
func (l *SearchLimiter) TryAcquire(token string) bool {
	if l == nil || token == "" {
		return true
	}
	_, ok := l.tryAcquire(token)
	return ok
}

func (l *SearchLimiter) tryAcquire(token string) (time.Duration, bool) {
	now := l.nowFn()
	l.mu.Lock()
	defer l.mu.Unlock()
	window := l.pruneLocked(token, now)
	if len(window) < l.limit {
		l.windows[token] = append(window, now)
		return 0, true
	}
	// 窗口满：等待最早一次打点滑出窗口
	wait := window[0].Add(searchWindow).Sub(now)
	if wait < time.Millisecond {
		wait = time.Millisecond
	}
	return wait, false
}

func (l *SearchLimiter) pruneLocked(token string, now time.Time) searchTimestamps {
	window := l.windows[token]
	kept := window[:0]
	for _, ts := range window {
		if now.Sub(ts) < searchWindow {
			kept = append(kept, ts)
		}
	}
	l.windows[token] = kept
	return kept
}
