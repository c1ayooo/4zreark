package subdomain

import (
	"fmt"
	"strings"
	"sync"

	"golang.org/x/net/publicsuffix"
)

// EngineQueryGuard 是测绘引擎的防烧额度闸门：
//
//  1. 按（引擎, 注册域）去重——引擎语法本身就是按注册域匹配（domain="example.com"），
//     拿子域重复查询要么无意义要么返回重复数据，同一注册域只查一次；
//  2. 每引擎总量硬上限——超过 maxPerEngine 次后跳过并说明原因。
//
// 守卫是任务级共享对象（子域模块按域名创建多个扫描器实例，全部挂同一个守卫），
// 跨任务不共享：每个任务一条干净额度。
type EngineQueryGuard struct {
	mu           sync.Mutex
	queried      map[string]bool // key: engine \x00 baseDomain
	count        map[string]int  // engine -> 已用次数
	maxPerEngine int
}

// NewEngineQueryGuard 创建守卫；maxPerEngine <= 0 时取默认 10。
func NewEngineQueryGuard(maxPerEngine int) *EngineQueryGuard {
	if maxPerEngine <= 0 {
		maxPerEngine = 10
	}
	return &EngineQueryGuard{
		queried:      make(map[string]bool),
		count:        make(map[string]int),
		maxPerEngine: maxPerEngine,
	}
}

// BaseDomain 把任意 host 规范成注册域（eTLD+1）；解析失败回落原值小写。
func BaseDomain(host string) string {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if h == "" {
		return ""
	}
	if root, err := publicsuffix.EffectiveTLDPlusOne(h); err == nil {
		return root
	}
	return h
}

// Allow 报告是否允许对（engine, host）发起一次引擎查询，不允许时返回原因。
func (g *EngineQueryGuard) Allow(engine, host string) (bool, string) {
	if g == nil {
		return true, ""
	}
	base := BaseDomain(host)
	key := engine + "\x00" + base
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.queried[key] {
		return false, fmt.Sprintf("注册域 %s 本任务已查过（引擎按注册域匹配，子域查询无意义）", base)
	}
	if g.count[engine] >= g.maxPerEngine {
		return false, fmt.Sprintf("已达本任务查询上限 %d 次", g.maxPerEngine)
	}
	g.queried[key] = true
	g.count[engine]++
	AddEngineUsage(engine, 1)
	return true, ""
}

// ---------------------------------------------------------------------------
// 进程级用量收集：worker 把守卫放行的查询累加到这里，任务结束时随
// scan_done 上报 master 落账（master 本地执行则直接落账）。
// ---------------------------------------------------------------------------

var engineUsageMu sync.Mutex
var engineUsage = map[string]int{}

// AddEngineUsage 累加一次引擎查询（worker/master 通用，放行即计数）。
func AddEngineUsage(engine string, n int) {
	engineUsageMu.Lock()
	engineUsage[engine] += n
	engineUsageMu.Unlock()
}

// TakeEngineUsage 取出并清零当前累计的引擎用量。
func TakeEngineUsage() map[string]int {
	engineUsageMu.Lock()
	out := engineUsage
	engineUsage = map[string]int{}
	engineUsageMu.Unlock()
	if len(out) == 0 {
		return nil
	}
	return out
}
