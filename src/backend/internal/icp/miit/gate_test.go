package miit

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestRequestGateSpacing(t *testing.T) {
	g := newRequestGate(80 * time.Millisecond)
	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := g.wait(context.Background()); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	// 第 1 个立即，后两个各等 80ms；留一点调度余量。
	if elapsed := time.Since(start); elapsed < 150*time.Millisecond {
		t.Fatalf("3 次请求间隔过短: %s（应 >= 160ms）", elapsed)
	}
}

func TestRequestGateCancel(t *testing.T) {
	g := newRequestGate(2 * time.Second)
	if err := g.wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := g.wait(ctx); err == nil {
		t.Fatal("等待中被取消应返回错误")
	}
}

func TestSetMinInterval(t *testing.T) {
	g := newRequestGate(time.Second)
	g.setInterval(0) // 非法值回落默认 5s
	g.mu.Lock()
	got := g.interval
	g.mu.Unlock()
	if got != 5*time.Second {
		t.Fatalf("非法间隔应回落 5s，实际 %s", got)
	}
}
