// Package resilience 单元测试：熔断状态机 + 代理池，全部纯逻辑、不依赖真实网络。
// @file      : resilience_test.go
// @author    : c1ay
// @time      : 2026/10/23
// -------------------------------------------
package resilience

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------- Breaker：熔断状态机 ----------

// 连续失败达到阈值开闸；未达阈值保持闭合。
func TestBreakerOpensAfterConsecutiveFailures(t *testing.T) {
	b := NewBreaker("unit.test", WithCooldown(50*time.Millisecond))
	b.RecordFailure()
	b.RecordFailure()
	if st := b.State(); st != StateClosed {
		t.Fatalf("2 次失败应保持闭合，实际 %s", st)
	}
	if ok, _ := b.Allow(); !ok {
		t.Fatal("闭合状态应放行")
	}
	b.RecordFailure() // 第 3 次 → 开闸
	if st := b.State(); st != StateOpen {
		t.Fatalf("连续 3 次失败应开闸，实际 %s", st)
	}
	ok, retryAfter := b.Allow()
	if ok {
		t.Fatal("开闸状态应拒绝请求")
	}
	if retryAfter <= 0 || retryAfter > 50*time.Millisecond {
		t.Fatalf("retryAfter 应为冷却剩余时间 (0,50ms]，实际 %s", retryAfter)
	}
}

// 开闸 → 冷却后半开 → 探测成功 → 闭合，且失败计数/冷却复位。
func TestBreakerHalfOpenSuccessCloses(t *testing.T) {
	b := NewBreaker("unit.test", WithCooldown(30*time.Millisecond))
	for i := 0; i < 3; i++ {
		b.RecordFailure()
	}
	if b.State() != StateOpen {
		t.Fatal("应处于 open")
	}
	time.Sleep(45 * time.Millisecond) // 等过冷却期
	if st := b.State(); st != StateHalfOpen {
		t.Fatalf("冷却期满应呈现 half-open，实际 %s", st)
	}
	if ok, _ := b.Allow(); !ok {
		t.Fatal("half-open 应放行探测请求")
	}
	b.RecordSuccess() // 探测成功
	if st := b.State(); st != StateClosed {
		t.Fatalf("探测成功后应闭合，实际 %s", st)
	}
	// 闭合后冷却与计数应复位：再失败 2 次仍闭合，第 3 次才开闸。
	b.RecordFailure()
	b.RecordFailure()
	if b.State() != StateClosed {
		t.Fatal("复位后 2 次失败应保持闭合")
	}
}

// RecordBlocked 快速通道：不等连续 N 次，立即开闸。
func TestBreakerRecordBlockedImmediateOpen(t *testing.T) {
	b := NewBreaker("unit.test", WithCooldown(30*time.Millisecond))
	b.RecordSuccess() // 有过成功也不影响快速通道
	b.RecordBlocked()
	if st := b.State(); st != StateOpen {
		t.Fatalf("明确被封应立即开闸，实际 %s", st)
	}
	if ok, retryAfter := b.Allow(); ok || retryAfter <= 0 {
		t.Fatalf("开闸后应拒绝并给出 retryAfter，实际 ok=%v retryAfter=%s", ok, retryAfter)
	}
}

// half-open 探测失败 → 回 open 且冷却翻倍（指数退避，封顶上限）。
func TestBreakerExponentialBackoff(t *testing.T) {
	const base = 20 * time.Millisecond
	b := NewBreaker("unit.test", WithCooldown(base), WithMaxCooldown(160*time.Millisecond))

	last := base
	for step := 0; step < 5; step++ {
		// 开闸（首次用连续失败触发，后续用探测失败）
		if step == 0 {
			for i := 0; i < 3; i++ {
				b.RecordFailure()
			}
		} else {
			b.RecordFailure() // half-open 探测失败
		}
		if b.State() != StateOpen {
			t.Fatalf("第 %d 步应处于 open", step)
		}
		_, retryAfter := b.Allow()
		want := last * 2 // 每次探测失败冷却翻倍
		if want > 160*time.Millisecond {
			want = 160 * time.Millisecond
		}
		if step > 0 && (retryAfter < want-time.Duration(5)*time.Millisecond || retryAfter > want+30*time.Millisecond) {
			t.Fatalf("第 %d 次翻倍后冷却应约 %s，实际 %s", step, want, retryAfter)
		}
		time.Sleep(retryAfter + 15*time.Millisecond)
		if ok, _ := b.Allow(); !ok {
			t.Fatalf("冷却期满应放行探测（第 %d 步）", step)
		}
		last = retryAfter
	}
	// 上限验证：再失败一次后冷却不应超过 maxCooldown
	b.RecordFailure()
	_, retryAfter := b.Allow()
	if retryAfter > 160*time.Millisecond+30*time.Millisecond {
		t.Fatalf("冷却应封顶 160ms，实际 %s", retryAfter)
	}
}

// half-open 只放一个探测请求，其余并发请求仍被拒绝。
func TestBreakerHalfOpenSingleProbe(t *testing.T) {
	b := NewBreaker("unit.test", WithCooldown(25*time.Millisecond))
	b.RecordBlocked()
	time.Sleep(40 * time.Millisecond)
	if ok, _ := b.Allow(); !ok {
		t.Fatal("第一个请求应作为探测放行")
	}
	ok, retryAfter := b.Allow()
	if ok {
		t.Fatal("探测在途时第二个请求应被拒绝")
	}
	if retryAfter <= 0 {
		t.Fatalf("拒绝时应给出建议等待时长，实际 %s", retryAfter)
	}
	b.RecordSuccess() // 探测成功 → 闭合
	if ok, _ := b.Allow(); !ok {
		t.Fatal("闭合后应正常放行")
	}
}

// half-open 探测被封（RecordBlocked）同样冷却翻倍。
func TestBreakerBlockedDuringHalfOpenDoublesCooldown(t *testing.T) {
	b := NewBreaker("unit.test", WithCooldown(25*time.Millisecond))
	b.RecordBlocked()
	time.Sleep(40 * time.Millisecond)
	if ok, _ := b.Allow(); !ok {
		t.Fatal("冷却期满应放行探测")
	}
	b.RecordBlocked() // 探测也被封
	_, retryAfter := b.Allow()
	if retryAfter < 45*time.Millisecond {
		t.Fatalf("探测被封后冷却应翻倍至约 50ms，实际 %s", retryAfter)
	}
}

// BreakerSet：同一 host 复用同一个熔断器，不同 host 互相隔离。
func TestBreakerSetPerHost(t *testing.T) {
	set := NewBreakerSet(WithCooldown(time.Second))
	a1, a2 := set.Get("a.example"), set.Get("a.example")
	b := set.Get("b.example")
	if a1 != a2 {
		t.Fatal("同一 host 应复用同一个熔断器")
	}
	if a1 == b {
		t.Fatal("不同 host 应使用独立熔断器")
	}
	a1.RecordBlocked()
	if a1.State() != StateOpen {
		t.Fatal("a 开闸不应影响 b")
	}
	if ok, _ := b.Allow(); !ok {
		t.Fatal("b 不应被 a 的开闸波及")
	}
}

// CircuitOpenError：文案带建议等待秒数，且可通过 errors.Is/As 识别。
func TestCircuitOpenError(t *testing.T) {
	err := &CircuitOpenError{Host: "www.example.com", RetryAfter: 90 * time.Second}
	if !strings.Contains(err.Error(), "www.example.com") || !strings.Contains(err.Error(), "建议 90 秒后重试") {
		t.Fatalf("错误文案不符合预期: %s", err.Error())
	}
	wrapped := err
	if !errors.Is(wrapped, ErrCircuitOpen) {
		t.Fatal("应可通过 errors.Is(ErrCircuitOpen) 识别")
	}
	var ce *CircuitOpenError
	if !errors.As(wrapped, &ce) || ce.RetryAfter != 90*time.Second {
		t.Fatal("应可通过 errors.As 提取 retryAfter")
	}
	// 1 秒以内的等待也应至少显示 1 秒
	short := &CircuitOpenError{Host: "x", RetryAfter: 10 * time.Millisecond}
	if !strings.Contains(short.Error(), "建议 1 秒后重试") {
		t.Fatalf("过短等待应向上取整为 1 秒: %s", short.Error())
	}
}

// 并发压测（配合 -race）：Allow/Record 混合并发不出现数据竞争或死锁。
func TestBreakerConcurrent(t *testing.T) {
	b := NewBreaker("unit.test", WithCooldown(5*time.Millisecond))
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				if ok, _ := b.Allow(); ok {
					switch n % 3 {
					case 0:
						b.RecordSuccess()
					case 1:
						b.RecordFailure()
					default:
						b.RecordBlocked()
					}
				}
			}
		}(i)
	}
	wg.Wait()
}

// ---------- ProxyPool：代理池 ----------

// 逗号/换行分隔解析 + 去重 + 轮转。
func TestProxyPoolParseAndRotation(t *testing.T) {
	p := NewProxyPool("p1, p2\np3\np1")
	if p.Len() != 3 {
		t.Fatalf("应解析出去重后的 3 个出口，实际 %d", p.Len())
	}
	got := []string{p.Pick(), p.Pick(), p.Pick(), p.Pick()}
	want := []string{"p1", "p2", "p3", "p1"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("轮转顺序不符：got=%v want=%v", got, want)
		}
	}
}

// 空串 = 直连单车道：池内只有空条目，Pick 恒返回 ""。
func TestProxyPoolEmptySpecDirectLane(t *testing.T) {
	p := NewProxyPool("")
	if p.Len() != 1 {
		t.Fatalf("空串应构造直连单车道，实际 %d 个条目", p.Len())
	}
	for i := 0; i < 3; i++ {
		if got := p.Pick(); got != "" {
			t.Fatalf("直连车道应恒返回空串，实际 %q", got)
		}
	}
	p.Report("", OutcomeOK)
	if p.Banned("") {
		t.Fatal("成功后直连不应处于封禁")
	}
}

// 被封出口在轮转中被跳过。
func TestProxyPoolSkipsBanned(t *testing.T) {
	p := NewProxyPool("a,b")
	p.Report("a", OutcomeBlocked)
	for i := 0; i < 4; i++ {
		if got := p.Pick(); got != "b" {
			t.Fatalf("a 被封后应只选 b，第 %d 次实际 %q", i, got)
		}
	}
}

// 全部被封时回退直连（返回空串）；直连条目被封时同样返回空串交由熔断器节流。
func TestProxyPoolAllBannedFallbackDirect(t *testing.T) {
	p := NewProxyPool("a,b")
	p.Report("a", OutcomeBlocked)
	p.Report("b", OutcomeBlocked)
	if got := p.Pick(); got != "" {
		t.Fatalf("全部被封应回退直连空串，实际 %q", got)
	}

	// 直连单车道被封：Pick 返回 ""，让调用方走熔断等待。
	direct := NewProxyPool("")
	direct.Report("", OutcomeBlocked)
	if !direct.Banned("") {
		t.Fatal("直连条目被封后应处于封禁状态")
	}
	if got := direct.Pick(); got != "" {
		t.Fatalf("直连被封期间 Pick 应返回空串，实际 %q", got)
	}
}

// 冷却期满 → 半开试探一次 → 失败再封（时长翻倍）→ 再满 → 试探成功 → 恢复。
func TestProxyPoolHalfOpenProbeAndRecovery(t *testing.T) {
	p := NewProxyPool("a", WithBanDuration(30*time.Millisecond))

	p.Report("a", OutcomeBlocked) // 首次封 30ms
	if !p.Banned("a") {
		t.Fatal("blocked 后应封禁")
	}
	if got := p.Pick(); got != "" {
		t.Fatalf("封禁期间应回退直连，实际 %q", got)
	}
	time.Sleep(45 * time.Millisecond) // 等过冷却期
	if p.Banned("a") {
		t.Fatal("冷却期满不应再视为封禁")
	}
	if got := p.Pick(); got != "a" {
		t.Fatalf("冷却期满应半开放行该出口，实际 %q", got)
	}
	p.Report("a", OutcomeBlocked) // 试探失败 → 再封且翻倍（60ms）
	if !p.Banned("a") {
		t.Fatal("试探失败应再次封禁")
	}
	if got := p.Pick(); got != "" {
		t.Fatalf("再封期间应回退直连，实际 %q", got)
	}
	time.Sleep(75 * time.Millisecond) // 超过翻倍后的 60ms
	if got := p.Pick(); got != "a" {
		t.Fatalf("翻倍冷却期满应再次放行，实际 %q", got)
	}
	p.Report("a", OutcomeOK) // 试探成功 → 完全恢复
	if p.Banned("a") {
		t.Fatal("成功后应清除封禁")
	}
	if got := p.Pick(); got != "a" {
		t.Fatalf("恢复后应正常轮出，实际 %q", got)
	}
}

// 连续封禁时长指数翻倍且封顶。
func TestProxyPoolBanEscalation(t *testing.T) {
	const base = 30 * time.Millisecond
	p := NewProxyPool("a", WithBanDuration(base), WithMaxBanDuration(100*time.Millisecond))

	durations := []time.Duration{base, 2 * base, 100 * time.Millisecond, 100 * time.Millisecond} // 30 → 60 → 100(封顶自 120) → 100
	for i, want := range durations {
		p.Report("a", OutcomeBlocked)
		until := p.entries[0].bannedUntil
		d := time.Until(until)
		if d < want-time.Duration(10)*time.Millisecond || d > want+40*time.Millisecond {
			t.Fatalf("第 %d 次封禁时长应约 %s，实际 %s", i+1, want, d)
		}
		time.Sleep(want + 25*time.Millisecond) // 等过本次冷却再触发下一次
		p.Pick()                               // 半开放行该出口
	}
	// 成功后复位：再封应从基准时长重新开始
	p.Report("a", OutcomeOK)
	p.Report("a", OutcomeBlocked)
	if d := time.Until(p.entries[0].bannedUntil); d > base+40*time.Millisecond {
		t.Fatalf("成功复位后首次封禁应回到基准 %s，实际 %s", base, d)
	}
}

// 连续 ≥3 次普通失败触发短封；成功可清零计数。
func TestProxyPoolConsecutiveErrorBan(t *testing.T) {
	p := NewProxyPool("e", WithErrorBanDuration(30*time.Millisecond))
	p.Report("e", OutcomeError)
	p.Report("e", OutcomeError)
	if p.Banned("e") {
		t.Fatal("2 次失败不应封禁")
	}
	p.Report("e", OutcomeError) // 第 3 次 → 短封 30ms
	if !p.Banned("e") {
		t.Fatal("连续 3 次失败应短暂封禁")
	}
	time.Sleep(45 * time.Millisecond)
	p.Report("e", OutcomeOK) // 恢复并清零
	for i := 0; i < 2; i++ {
		p.Report("e", OutcomeError)
	}
	if p.Banned("e") {
		t.Fatal("清零后 2 次失败不应封禁")
	}
}

// PickExcluding：换道重试语义——排除当前出口后还有可用出口才返回 true。
func TestProxyPoolPickExcluding(t *testing.T) {
	p := NewProxyPool("a,b")
	if got, ok := p.PickExcluding("a"); !ok || got != "b" {
		t.Fatalf("排除 a 应选到 b，实际 %q ok=%v", got, ok)
	}
	// 单车道：排除直连后无其他出口
	direct := NewProxyPool("")
	if got, ok := direct.PickExcluding(""); ok || got != "" {
		t.Fatalf("单车道排除直连应无可选，实际 %q ok=%v", got, ok)
	}
	// 其余全被封时同样返回 false
	p.Report("b", OutcomeBlocked)
	if got, ok := p.PickExcluding("a"); ok || got != "" {
		t.Fatalf("b 被封后排除 a 应无可选，实际 %q ok=%v", got, ok)
	}
}

// 未知出口的 Report 直接忽略（防御式）。
func TestProxyPoolReportUnknownProxy(t *testing.T) {
	p := NewProxyPool("a")
	p.Report("ghost", OutcomeBlocked) // 不应 panic
	if p.Banned("ghost") {
		t.Fatal("未知出口不应产生状态")
	}
}

// 并发压测（配合 -race）：Pick/Report 混合并发不出现数据竞争或死锁。
func TestProxyPoolConcurrent(t *testing.T) {
	p := NewProxyPool("a,b,c,d")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				proxy := p.Pick()
				switch (n + j) % 3 {
				case 0:
					p.Report(proxy, OutcomeOK)
				case 1:
					p.Report(proxy, OutcomeBlocked)
				default:
					p.Report(proxy, OutcomeError)
				}
			}
		}(i)
	}
	wg.Wait()
}
