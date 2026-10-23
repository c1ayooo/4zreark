// Package resilience 采集风控基础设施：按上游 host 的熔断器 + 出站代理池。
// @file      : breaker.go
// @author    : c1ay
// @time      : 2026/10/23
// -------------------------------------------
// 参考 ARL-Next v1.4.3 的 ICP 纵深熔断理念（实现全部原创）。
//
// 官方数据源（工信部 ICP、企查查等）风控严格，出口被封后继续重试只会加重封禁，
// 因此在客户端层加两道闸：
//   - Breaker：per-host 熔断状态机（closed → open → half-open）。
//     连续失败达阈值、或收到「明确被封」类错误（创宇盾拦截、412 风控）立即开闸；
//     冷却期结束放一个探测请求，成功则闭合，失败则回 open 且冷却翻倍（指数退避，
//     上限 10min），给上游留出解封窗口，避免无意义的硬撞。
//   - ProxyPool：多出口轮转，被封出口按指数退避拉黑，全部被封时回退直连并交由
//     熔断器节流。见 proxypool.go。
//
// 典型接线：每次真实 HTTP 请求前 Allow()，被拒时把 CircuitOpenError 透传给调用方；
// 请求结束后按结果 RecordSuccess / RecordFailure / RecordBlocked。
package resilience

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// State 熔断器状态。
type State int

const (
	// StateClosed 闭合：正常放行，统计连续失败。
	StateClosed State = iota
	// StateOpen 打开：拒绝所有请求，等冷却期结束。
	StateOpen
	// StateHalfOpen 半开：冷却期结束，放行一个探测请求。
	StateHalfOpen
)

// String 返回状态的中文描述（日志友好）。
func (s State) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half-open"
	default:
		return fmt.Sprintf("unknown(%d)", int(s))
	}
}

// 熔断器默认参数：连续失败 3 次开闸，初始冷却 60s，退避上限 10min。
const (
	defaultFailThreshold = 3
	defaultCooldown      = 60 * time.Second
	defaultMaxCooldown   = 10 * time.Minute
)

// ErrCircuitOpen 熔断打开期间的拒绝哨兵错误，供调用方 errors.Is 识别。
// 具体错误为 *CircuitOpenError（含 host 与建议等待时长，用 errors.As 提取）。
var ErrCircuitOpen = errors.New("熔断保护中")

// CircuitOpenError 熔断打开期间请求被拒的错误：携带目标 host 与建议等待时长。
type CircuitOpenError struct {
	Host       string        // 被熔断的上游 host
	RetryAfter time.Duration // 建议等待时长（当前冷却的剩余时间）
}

// Error 实现 error 接口；文案带「建议 N 秒后重试」，调用方直接落日志/状态即可读。
func (e *CircuitOpenError) Error() string {
	secs := (e.RetryAfter + time.Second - 1) / time.Second // 向上取整到秒
	if secs < 1 {
		secs = 1
	}
	return fmt.Sprintf("目标 %s 处于熔断保护中（连续失败或被封禁），建议 %d 秒后重试", e.Host, secs)
}

// Unwrap 关联哨兵错误，支持 errors.Is(err, resilience.ErrCircuitOpen)。
func (e *CircuitOpenError) Unwrap() error { return ErrCircuitOpen }

// breakerOptions 熔断器可调参数集合（经 BreakerOption 注入）。
type breakerOptions struct {
	failThreshold int
	cooldown      time.Duration
	maxCooldown   time.Duration
}

// BreakerOption 熔断器构造选项。
type BreakerOption func(*breakerOptions)

// WithFailThreshold 自定义连续失败开闸阈值（默认 3，非正值回落默认）。
func WithFailThreshold(n int) BreakerOption {
	return func(o *breakerOptions) {
		if n > 0 {
			o.failThreshold = n
		}
	}
}

// WithCooldown 自定义初始冷却时长（默认 60s，非正值回落默认）。
func WithCooldown(d time.Duration) BreakerOption {
	return func(o *breakerOptions) {
		if d > 0 {
			o.cooldown = d
		}
	}
}

// WithMaxCooldown 自定义指数退避上限（默认 10min，非正值回落默认）。
func WithMaxCooldown(d time.Duration) BreakerOption {
	return func(o *breakerOptions) {
		if d > 0 {
			o.maxCooldown = d
		}
	}
}

// Breaker 单个上游 host 的熔断器（并发安全）。
//
// 状态机：
//
//	closed --连续失败 ≥ N 或 RecordBlocked--> open
//	open    --冷却期结束--> half-open（放一个探测）
//	half-open --探测成功--> closed（冷却复位）
//	half-open --探测失败--> open（冷却翻倍，指数退避至上限）
type Breaker struct {
	mu    sync.Mutex
	host  string
	opts  breakerOptions
	state State

	fails    int           // closed 期间的连续失败计数
	openedAt time.Time     // 进入 open 的时刻
	cooldown time.Duration // 当前生效的冷却时长（指数退避后）
	probing  bool          // half-open 探测在途标记
}

// NewBreaker 创建按 host 的熔断器；host 仅用于错误信息与日志。
func NewBreaker(host string, opts ...BreakerOption) *Breaker {
	o := breakerOptions{
		failThreshold: defaultFailThreshold,
		cooldown:      defaultCooldown,
		maxCooldown:   defaultMaxCooldown,
	}
	for _, opt := range opts {
		opt(&o)
	}
	if o.maxCooldown < o.cooldown {
		o.maxCooldown = o.cooldown
	}
	return &Breaker{host: host, opts: o, cooldown: o.cooldown}
}

// Allow 判断是否放行一个请求。
//
// 返回 (true, 0) 表示放行；open 状态下冷却未到返回 (false, 冷却剩余时长)；
// 冷却结束后首次调用会转入 half-open 并放行唯一探测，其余并发请求仍被拒绝。
func (b *Breaker) Allow() (ok bool, retryAfter time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	switch b.state {
	case StateClosed:
		return true, 0
	case StateOpen:
		remain := b.openedAt.Add(b.cooldown).Sub(now)
		if remain > 0 {
			return false, remain
		}
		// 冷却结束 → half-open：只放一个探测请求。
		b.state = StateHalfOpen
		b.probing = true
		return true, 0
	case StateHalfOpen:
		if b.probing {
			// 已有探测在途：其余请求继续拒绝，按保守值给出等待建议。
			return false, b.opts.cooldown
		}
		b.probing = true
		return true, 0
	}
	return true, 0
}

// RecordSuccess 记录一次成功：任意状态下都直接闭合（真实成功是更强的证据），
// 连续失败与退避冷却一并复位。
func (b *Breaker) RecordSuccess() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.state = StateClosed
	b.fails = 0
	b.cooldown = b.opts.cooldown
	b.probing = false
	b.openedAt = time.Time{}
}

// RecordFailure 记录一次普通失败（网络错误/5xx 等）：
// closed 下累加连续失败，达阈值开闸；half-open 下视为探测失败，回 open 并冷却翻倍。
func (b *Breaker) RecordFailure() {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch b.state {
	case StateClosed:
		b.fails++
		if b.fails >= b.opts.failThreshold {
			b.tripOpen(time.Now(), false)
		}
	case StateHalfOpen:
		b.tripOpen(time.Now(), true)
	default: // open：已开闸，无需再计
	}
}

// RecordBlocked 记录一次「明确被封」（创宇盾拦截、412 风控等）：
// 走快速通道直接开闸，不等连续 N 次；half-open 下的封禁同样冷却翻倍。
func (b *Breaker) RecordBlocked() {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch b.state {
	case StateClosed:
		b.tripOpen(time.Now(), false)
	case StateHalfOpen:
		b.tripOpen(time.Now(), true)
	default: // open：保持原冷却，不重复延长
	}
}

// State 返回当前状态；open 且冷却已过时返回 half-open（等待探测请求到来）。
func (b *Breaker) State() State {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.state == StateOpen && !b.openedAt.Add(b.cooldown).After(time.Now()) {
		return StateHalfOpen
	}
	return b.state
}

// Host 返回熔断器绑定的上游 host。
func (b *Breaker) Host() string { return b.host }

// tripOpen 开闸（须持锁）。escalate=true 表示探测失败，冷却翻倍（指数退避，封顶上限）。
func (b *Breaker) tripOpen(now time.Time, escalate bool) {
	b.state = StateOpen
	b.probing = false
	b.fails = 0
	b.openedAt = now
	if escalate {
		b.cooldown *= 2
		if b.cooldown > b.opts.maxCooldown {
			b.cooldown = b.opts.maxCooldown
		}
	}
}

// BreakerSet per-host 熔断器集合：按 host 惰性取/建，同一 host 共享同一个熔断器。
type BreakerSet struct {
	mu       sync.Mutex
	breakers map[string]*Breaker
	opts     []BreakerOption
}

// NewBreakerSet 创建熔断器集合；opts 透传给每个新建的 Breaker。
func NewBreakerSet(opts ...BreakerOption) *BreakerSet {
	return &BreakerSet{breakers: map[string]*Breaker{}, opts: opts}
}

// Get 取 host 对应的熔断器，不存在则按集合选项新建。
func (s *BreakerSet) Get(host string) *Breaker {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b, ok := s.breakers[host]; ok {
		return b
	}
	b := NewBreaker(host, s.opts...)
	s.breakers[host] = b
	return b
}
