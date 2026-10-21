// Package collect 信息收集周期任务的公共编排层：
//
//	budget.go    源策略（每源并发/最小间隔）与错误分级（鉴权/瞬态/其他）
//	scheduler.go (source, domain) 工作单元轮转调度器（源策略预算）
//	worker.go    周期调度共享 worker 骨架（tick / due 扫描 / inflight / 并发上限）
//
// 设计参照 AtlasX radar 的 budget/scheduler 语义按接口语义用 Go 重写（抄架构
// 不抄代码）；单机部署，不做租约续扫。
package collect

import (
	"strings"
	"sync"
	"time"
)

// SourcePolicy 单源执行策略：同时最多几路 + 两次开工最小间隔。
type SourcePolicy struct {
	MaxInflight int
	MinInterval time.Duration
}

// defaultPolicies 源分级内置表：
//   - 付费配额类（fofa/zoomeye/quake/shodan/hunter）：单飞 + 引擎专属间隔，
//     quake 实测「调用API过于频繁」阈值最敏感，给最大间隔；
//   - 免 key 类（otx/rapiddns/crtsh）：放宽并发与间隔；
//   - 未知源回退保守默认（单飞 1s）。
var defaultPolicies = map[string]SourcePolicy{
	"fofa":     {MaxInflight: 1, MinInterval: 1 * time.Second},
	"zoomeye":  {MaxInflight: 1, MinInterval: 1 * time.Second},
	"quake":    {MaxInflight: 1, MinInterval: 2 * time.Second},
	"shodan":   {MaxInflight: 1, MinInterval: 1 * time.Second},
	"hunter":   {MaxInflight: 1, MinInterval: 1 * time.Second},
	"otx":      {MaxInflight: 2, MinInterval: 200 * time.Millisecond},
	"rapiddns": {MaxInflight: 2, MinInterval: 200 * time.Millisecond},
	"crtsh":    {MaxInflight: 1, MinInterval: 1 * time.Second},
}

var policyMu sync.RWMutex

// PolicyFor 返回源策略（未知源回退保守默认）。
func PolicyFor(source string) SourcePolicy {
	policyMu.RLock()
	defer policyMu.RUnlock()
	if p, ok := defaultPolicies[strings.ToLower(strings.TrimSpace(source))]; ok {
		return p
	}
	return SourcePolicy{MaxInflight: 1, MinInterval: 1 * time.Second}
}

// SetPolicy 覆盖/新增源策略（系统设置热更与测试注入用；并发安全）。
func SetPolicy(source string, p SourcePolicy) {
	policyMu.Lock()
	defer policyMu.Unlock()
	defaultPolicies[strings.ToLower(strings.TrimSpace(source))] = p
}

// ErrorClass 错误分级：决定退避与终态语义。
type ErrorClass int

const (
	ErrorClassOther     ErrorClass = iota
	ErrorClassAuth                 // 鉴权/配额类：key 无效、欠费——需人工介入，触发退避与熔断
	ErrorClassTransient            // 瞬态限流/网络：调度器内重试，不触发调度级退避
)

// ClassifyError 按错误文案启发式分级（各引擎限流/鉴权报错文案不一，取并集
// 匹配；中英并收，匹配大小写不敏感）。瞬态优先（429 类文案不会误入鉴权）。
func ClassifyError(err error) ErrorClass {
	if err == nil {
		return ErrorClassOther
	}
	msg := strings.ToLower(err.Error())
	// 瞬态：限流/超时/网络抖动
	for _, m := range []string{
		"429", "too many requests", "rate limit", "ratelimit", "限流", "频繁",
		"timeout", "timed out", "deadline exceeded", "connection reset",
		"connection refused", "eof", "502", "503", "504", "临时",
	} {
		if strings.Contains(msg, m) {
			return ErrorClassTransient
		}
	}
	// 鉴权/配额：需人工介入
	for _, m := range []string{
		"api key", "apikey", "api-key", "token", "401", "403", "unauthorized",
		"forbidden", "invalid key", "key无效", "key 无效", "鉴权", "认证", "授权失败",
		"未配置", "余额", "欠费", "配额", "quota", "权限", "vip",
	} {
		if strings.Contains(msg, m) {
			return ErrorClassAuth
		}
	}
	return ErrorClassOther
}

// IsAuthError / IsTransientError 便捷判断。
func IsAuthError(err error) bool      { return ClassifyError(err) == ErrorClassAuth }
func IsTransientError(err error) bool { return ClassifyError(err) == ErrorClassTransient }
