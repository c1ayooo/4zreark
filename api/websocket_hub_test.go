package api

import (
	"sync"
	"testing"
	"time"
)

// TestHubSlowClientBroadcast 回归 H1：广播剔除慢客户端时不能在读锁下写 map，
// 也不能对已关闭的 send 重复 close 或继续发送（否则线上直接 panic）。
func TestHubSlowClientBroadcast(t *testing.T) {
	h := NewHub()
	go h.Run()

	// 慢客户端：缓冲只有 1，且没有 writePump 消费。
	slow := &Client{send: make(chan []byte, 1), hub: h}
	h.register <- slow

	// 第一条塞满缓冲，第二条触发剔除，第三条在剔除后再广播。
	for _, payload := range []string{"one", "two", "three"} {
		h.broadcast <- []byte(payload)
	}

	// 客户端可能已被剔除，并发 pong 不得 panic。
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if h.enqueue(slow, []byte("pong")) {
				return
			}
		}()
	}
	wg.Wait()

	select {
	case h.unregister <- slow:
	case <-time.After(time.Second):
		t.Fatal("unregister 阻塞：Hub.Run 可能已退出")
	}

	h.Stop()
	select {
	case <-h.done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop 后 Hub.Run 未退出")
	}
}

// TestHubStopIdempotent 回归 M6：Stop 必须可重复调用且能终止监控广播协程。
func TestHubStopIdempotent(t *testing.T) {
	h := NewHub()
	go h.Run()
	go h.StartMonitorTask()

	h.Stop()
	h.Stop()

	select {
	case <-h.done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop 后 Hub.Run 未退出")
	}
}
