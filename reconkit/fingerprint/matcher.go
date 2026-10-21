package fingerprint

import (
	"sync"
	"time"
)

// CompiledRule 一条已解析启用的规则。
type CompiledRule struct {
	ID         string
	Name       string
	Category   string
	Expression string
	Expr       Expr
}

// Compiled 库的解析缓存：签名（条数+最新更新时间）不变即复用。
type Compiled struct {
	Signature string
	Rules     []CompiledRule
	Stamp     time.Time
}

var (
	cacheMu   sync.RWMutex
	cacheData *Compiled
)

// CachePut 写入缓存。
func CachePut(sig string, rules []CompiledRule) {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	cacheData = &Compiled{Signature: sig, Rules: rules, Stamp: time.Now()}
}

// CacheGet 读取缓存（TTL 60s，防止更新后不刷新）。
func CacheGet(sig string) ([]CompiledRule, bool) {
	cacheMu.RLock()
	defer cacheMu.RUnlock()
	if cacheData != nil && cacheData.Signature == sig && time.Since(cacheData.Stamp) < time.Minute {
		return cacheData.Rules, true
	}
	return nil, false
}

// CacheInvalidate 规则变更后强制失效。
func CacheInvalidate() {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	cacheData = nil
}

// MatchObservation 用规则集匹配一次探测。同一产品名多条规则命中（多来源
// wappalyzergo/webanalyze/dddd 各翻译一条变体）只保留首条，避免结果重复。
func MatchObservation(rules []CompiledRule, o Observation) []Match {
	matches := make([]Match, 0, 4)
	seen := make(map[string]bool, 8)
	for _, r := range rules {
		if r.Expr != nil && r.Expr.Eval(&o) {
			if seen[r.Name] {
				continue
			}
			seen[r.Name] = true
			conf := 0.9
			if r.Category != "" {
				conf = 0.95
			}
			matches = append(matches, Match{
				Product:     r.Name,
				Expression:  r.Expression,
				MatchedExpr: r.Expression,
				Confidence:  conf,
			})
		}
	}
	return matches
}
