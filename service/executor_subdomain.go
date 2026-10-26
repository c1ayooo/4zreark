package service

import (
	"context"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/internal/recon/spacemap"
	"github.com/c1ayooo/4zreark/models"

	"golang.org/x/net/publicsuffix"
)

func boolDefaultTrue(p *bool) bool { return p == nil || *p }

// baseDomain 把目标规范成可做派生的注册域：URL/host:port -> host -> eTLD+1。
func baseDomain(raw string) string {
	host, _ := splitTarget(raw)
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" || net.ParseIP(host) != nil {
		return ""
	}
	if root, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return root
	}
	return host
}

// resolveCandidates 并发做 DNS 解析，只保留能解析的候选（有界并发）。
func resolveCandidates(ctx context.Context, names []string, concurrency int) []string {
	if len(names) == 0 {
		return nil
	}
	if concurrency <= 0 {
		concurrency = 64
	}
	child, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	sem := make(chan struct{}, concurrency)
	var mu sync.Mutex
	var wg sync.WaitGroup
	out := make([]string, 0, len(names))

loop:
	for _, name := range names {
		select {
		case <-child.Done():
			break loop
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			defer func() { <-sem }()
			addrs, err := net.DefaultResolver.LookupHost(child, name)
			if err == nil && len(addrs) > 0 {
				mu.Lock()
				out = append(out, name)
				mu.Unlock()
			}
		}(name)
	}
	wg.Wait()
	sort.Strings(out)
	return out
}

// engineSourcesForTask 解析本任务可用的测绘引擎：任务级 key（fofa/hunter/quake）
// 优先，回落 sources 表（密文解密）/全局配置。只返回真正配了 key 的源——
// 没配的引擎查了也白查，还烧配额。返回（是否启用, 启用的源, 任务级 key 表）。
func (e *TaskExecutor) engineSourcesForTask(ctx context.Context, task *models.Task) (bool, []string, map[string]string) {
	// sources 表 + 全局配置
	keys := NewSourceService().EngineKeys(ctx)
	// 任务级 key 优先
	taskKeys := map[string]string{
		"fofa":   task.Config.FofaKey,
		"hunter": task.Config.HunterKey,
		"quake":  task.Config.QuakeKey,
	}
	for p, v := range taskKeys {
		if strings.TrimSpace(v) != "" {
			keys[p] = v
		}
	}

	candidates := task.Config.ThirdPartySources
	if len(candidates) == 0 {
		candidates = []string{"fofa", "hunter", "quake", "zoomeye", "shodan"}
	}

	enabled := make([]string, 0, len(candidates))
	for _, raw := range candidates {
		provider := strings.ToLower(strings.TrimSpace(raw))
		if !spacemap.ValidProvider(provider) {
			log.Printf("[TaskExecutor] spacemap: unsupported engine %q, skipped", raw)
			continue
		}
		if strings.TrimSpace(keys[provider]) == "" {
			log.Printf("[TaskExecutor] spacemap: engine %s not configured, skipped", provider)
			continue
		}
		enabled = append(enabled, provider)
	}
	return len(enabled) > 0, enabled, keys
}
