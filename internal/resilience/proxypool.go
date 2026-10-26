// Package resilience 采集风控基础设施。
// @file      : proxypool.go
// @author    : c1ay
// @time      : 2026/10/23
// -------------------------------------------
// 出站代理池：多出口轮转 + 按指数退避的封禁管理。
//
// 语义约定：
//   - spec 为空串时为「直连单车道」：池内只有一个空条目，Pick 恒返回 ""（直连）；
//   - 每个出口（含直连条目）被封时带 bannedUntil：首次 10min，连续封禁翻倍，上限 1h；
//   - Pick 只在非 banned 出口中轮转；全部 banned 时回退返回 ""（直连）并记日志，
//     由调用方的熔断器负责节流（直连条目自身被封时同样返回 ""，等待熔断窗口）；
//   - 冷却期满后的首次 Pick 视为「半开试探」：放行该出口并标记 probing，
//     若 Report(blocked) 则再次封禁且时长翻倍，Report(ok) 则完全恢复。
package resilience

import (
	"log"
	"strings"
	"sync"
	"time"
)

// Outcome 上游请求结果分类（供 ProxyPool.Report 使用）。
type Outcome string

const (
	// OutcomeOK 请求成功：清除该出口的封禁与错误计数。
	OutcomeOK Outcome = "ok"
	// OutcomeBlocked 明确被封（创宇盾拦截、412 风控等）：立即封禁该出口。
	OutcomeBlocked Outcome = "blocked"
	// OutcomeError 普通失败（网络错误/5xx）：连续多次才短暂封禁。
	OutcomeError Outcome = "error"
)

// 代理池默认参数：封禁 10min 起、翻倍上限 1h；连续 3 次普通失败短封 30s。
const (
	defaultBanDuration    = 10 * time.Minute
	defaultMaxBanDuration = time.Hour
	defaultErrorBan       = 30 * time.Second
	errorBanThreshold     = 3
)

// proxyEntry 单个出口的状态。
type proxyEntry struct {
	raw          string    // 出口串；空串 = 直连
	bannedUntil  time.Time // 封禁截止时刻；零值 = 未封禁
	banCount     int       // 连续封禁次数（指数退避基数，成功后清零）
	consecErrors int       // 连续普通失败计数（达阈值短封）
	probing      bool      // 冷却期满后的试探在途标记
}

func (e *proxyEntry) banned(now time.Time) bool {
	return e.bannedUntil.After(now)
}

// ProxyPool 出站代理池（并发安全）。
type ProxyPool struct {
	mu      sync.Mutex
	entries []*proxyEntry
	next    int // 轮转游标（指向下次开始探测的下标）

	banDuration    time.Duration
	maxBanDuration time.Duration
	errorBan       time.Duration
}

// ProxyOption 代理池构造选项。
type ProxyOption func(*ProxyPool)

// WithBanDuration 自定义首次封禁时长（默认 10min，非正值回落默认）。
func WithBanDuration(d time.Duration) ProxyOption {
	return func(p *ProxyPool) {
		if d > 0 {
			p.banDuration = d
		}
	}
}

// WithMaxBanDuration 自定义封禁时长上限（默认 1h，非正值回落默认）。
func WithMaxBanDuration(d time.Duration) ProxyOption {
	return func(p *ProxyPool) {
		if d > 0 {
			p.maxBanDuration = d
		}
	}
}

// WithErrorBanDuration 自定义连续失败短封时长（默认 30s，非正值回落默认）。
func WithErrorBanDuration(d time.Duration) ProxyOption {
	return func(p *ProxyPool) {
		if d > 0 {
			p.errorBan = d
		}
	}
}

// NewProxyPool 从逗号/换行分隔的代理串构造代理池。
// 空串 = 直连单车道（池内只有空条目）；自动去重、剔除空白项、保序。
func NewProxyPool(spec string, opts ...ProxyOption) *ProxyPool {
	p := &ProxyPool{
		banDuration:    defaultBanDuration,
		maxBanDuration: defaultMaxBanDuration,
		errorBan:       defaultErrorBan,
	}
	for _, opt := range opts {
		opt(p)
	}
	if p.maxBanDuration < p.banDuration {
		p.maxBanDuration = p.banDuration
	}

	seen := map[string]bool{}
	for _, raw := range strings.FieldsFunc(spec, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r'
	}) {
		raw = strings.TrimSpace(raw)
		if raw == "" || seen[raw] {
			continue
		}
		seen[raw] = true
		p.entries = append(p.entries, &proxyEntry{raw: raw})
	}
	if len(p.entries) == 0 {
		// 空串/全是空白：直连单车道。
		p.entries = []*proxyEntry{{raw: ""}}
	}
	return p
}

// Pick 轮转选择一个非 banned 的出口；全部 banned 时回退直连（返回 ""）并记日志。
// 冷却期满的出口被选中时即「半开试探」，其结果由 Report 回填。
func (p *ProxyPool) Pick() string {
	if raw, ok := p.pickFrom(""); ok {
		return raw
	}
	log.Printf("[resilience] 所有出口均被封禁，回退直连（由熔断器节流）")
	return ""
}

// PickExcluding 换道重试专用：在排除 exclude 的出口中挑一个可用的。
// 没有其他可用出口时返回 ("", false)，调用方据此放弃同一请求内的重试。
func (p *ProxyPool) PickExcluding(exclude string) (string, bool) {
	return p.pickFrom(exclude)
}

// pickFrom 内核：从 next 游标起轮转一圈，跳过 exclude 与 ban 未到期的出口；
// 选中「冷却刚满」的出口时标记 probing（半开试探）。found=false 表示无可选出口。
func (p *ProxyPool) pickFrom(exclude string) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := len(p.entries)
	now := time.Now()
	for i := 0; i < n; i++ {
		idx := (p.next + i) % n
		e := p.entries[idx]
		if e.raw == exclude {
			continue
		}
		if e.banned(now) {
			continue
		}
		if !e.bannedUntil.IsZero() {
			// 曾被封禁且冷却刚满：本次选中即半开试探。
			e.probing = true
		}
		p.next = (idx + 1) % n
		return e.raw, true
	}
	return "", false
}

// Report 回填出口的请求结果：
//   - ok：清除封禁/封禁计数/错误计数，完全恢复；
//   - blocked：立即封禁，时长按连续封禁次数翻倍（10min → 20min → …，上限 1h）；
//   - error：连续 ≥3 次普通失败时短暂封禁（默认 30s，不参与翻倍）。
func (p *ProxyPool) Report(proxy string, outcome Outcome) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var e *proxyEntry
	for _, cand := range p.entries {
		if cand.raw == proxy {
			e = cand
			break
		}
	}
	if e == nil {
		return // 不在池内的出口（理论上不会发生）：直接忽略
	}
	now := time.Now()
	switch outcome {
	case OutcomeOK:
		e.bannedUntil = time.Time{}
		e.banCount = 0
		e.consecErrors = 0
		e.probing = false
	case OutcomeBlocked:
		e.probing = false
		e.banCount++
		e.consecErrors = 0
		d := p.banDuration
		for i := 1; i < e.banCount && d < p.maxBanDuration; i++ {
			d *= 2
		}
		if d > p.maxBanDuration {
			d = p.maxBanDuration
		}
		e.bannedUntil = now.Add(d)
		log.Printf("[resilience] 出口 %s 被封禁 %s（第 %d 次连续封禁）", describe(proxy), d, e.banCount)
	case OutcomeError:
		e.probing = false
		e.consecErrors++
		if e.consecErrors >= errorBanThreshold {
			e.bannedUntil = now.Add(p.errorBan)
			e.consecErrors = 0
			log.Printf("[resilience] 出口 %s 连续失败 %d 次，短暂封禁 %s", describe(proxy), errorBanThreshold, p.errorBan)
		}
	}
}

// Len 返回池内出口总数（含直连条目）。
func (p *ProxyPool) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.entries)
}

// Banned 查询出口当前是否处于封禁中（观测/测试用）。
func (p *ProxyPool) Banned(proxy string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	for _, e := range p.entries {
		if e.raw == proxy {
			return e.banned(now)
		}
	}
	return false
}

func describe(proxy string) string {
	if proxy == "" {
		return "直连"
	}
	return proxy
}
