package miit

import (
	"context"
	"sync"
	"time"
)

// requestGate 全局请求节拍器：所有发往工信部的 HTTP 请求（token、验证码、查询）
// 共用同一个最小间隔。官方站风控严格，宁可慢也不能并发打。
//
// 先预约再等待：并发调用会按预约顺序排队，避免「同时醒来一起打」。
type requestGate struct {
	mu       sync.Mutex
	next     time.Time
	interval time.Duration
}

func newRequestGate(interval time.Duration) *requestGate {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	return &requestGate{interval: interval}
}

func (g *requestGate) wait(ctx context.Context) error {
	g.mu.Lock()
	now := time.Now()
	if g.next.Before(now) {
		g.next = now
	}
	wait := g.next.Sub(now)
	g.next = g.next.Add(g.interval)
	g.mu.Unlock()

	if wait <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (g *requestGate) setInterval(d time.Duration) {
	if d <= 0 {
		d = 5 * time.Second
	}
	g.mu.Lock()
	g.interval = d
	g.mu.Unlock()
}
