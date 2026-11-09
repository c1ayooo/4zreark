package service

// SentinelDynGate 哨兵动态并发闸（可慢不可挂的运行时部分）。
//
// 静态上限由 river MaxWorkers（config.yaml，全局口径 ≤2）兜底；这里在其下
// 再叠一层按内存水位自动降档的闸门：
//
//	MemAvailable ≥ 6GiB → 2（正常档）
//	3GiB ~ 6GiB        → 1（收紧）
//	< 3GiB             → 0（过载：新作业在闸口排队，已执行作业跑完不中断）
//
// 档位恢复后自动放行排队作业。之所以用轮询而非条件变量：实现简单且
// 降档是稀疏事件，2s 粒度足够。扫描器等非哨兵负载不经此闸——它们是
// 内存的主要释放者，保证不会出现全员等待的死锁。
//
// 跨进程（pocsmith）不共享闸门，靠自身 GOMEMLIMIT 护栏。

import (
	"context"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type dynGate struct {
	mu   sync.Mutex
	cap  int // 当前许可数
	used int
}

func (g *dynGate) Acquire(ctx context.Context) error {
	for {
		g.mu.Lock()
		if g.used < g.cap {
			g.used++
			g.mu.Unlock()
			return nil
		}
		g.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

func (g *dynGate) Release() {
	g.mu.Lock()
	if g.used > 0 {
		g.used--
	}
	g.mu.Unlock()
}

func (g *dynGate) SetLimit(n int) {
	g.mu.Lock()
	g.cap = n
	g.mu.Unlock()
}

// sentinelGate 是哨兵三队列（collect/judge/artifacts）共享的动态闸。
var sentinelGate = &dynGate{cap: 2}

var gateLimit int32 = 2 // 当前档位，仅用于日志去重

// gateLimitForMem 把可用内存映射为档位；返回 -1 表示采样失败（保持现状）。
func gateLimitForMem() (int, float64) {
	gib, ok := memAvailableGiB()
	if !ok {
		return -1, 0
	}
	switch {
	case gib < 3:
		return 0, gib
	case gib < 6:
		return 1, gib
	default:
		return 2, gib
	}
}

func memAvailableGiB() (float64, bool) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "MemAvailable:") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				kb, err := strconv.ParseFloat(f[1], 64)
				if err == nil {
					return kb / 1024 / 1024, true
				}
			}
		}
	}
	return 0, false
}

// StartSentinelGateWatchdog 周期采样内存并调整档位（哨兵队列启动时后台运行）。
func StartSentinelGateWatchdog(ctx context.Context) {
	go func() {
		t := time.NewTicker(20 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				lim, gib := gateLimitForMem()
				if lim < 0 {
					continue
				}
				if atomic.SwapInt32(&gateLimit, int32(lim)) != int32(lim) {
					sentinelGate.SetLimit(lim)
					log.Printf("[Sentinel] 动态并发档位 → %d（可用内存 %.1fGiB）", lim, gib)
				}
			}
		}
	}()
}
