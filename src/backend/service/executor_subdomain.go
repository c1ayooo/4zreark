package service

import (
	"context"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/internal/recon/permute"
	"github.com/c1ayooo/4zreark/internal/recon/spacemap"
	reconsub "github.com/c1ayooo/4zreark/internal/recon/subdomain"
	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/scanner/subdomain"
	"github.com/c1ayooo/4zreark/scanner/webscan"

	"golang.org/x/net/publicsuffix"
)

// executeSubdomainScan 执行子域名扫描
func (e *TaskExecutor) executeSubdomainScan(task *models.Task, jobID int64) {
	log.Printf("[TaskExecutor] Executing subdomain scan for task: %s", task.ID.Hex())

	targets := task.Targets
	if len(targets) == 0 {
		e.failTask(task, jobID, "没有目标")
		return
	}

	// 任务级子域字典：前端选的 dictionaries.id，解析成词表；为空用内置词表。
	dictCtx, dictCancel := context.WithTimeout(context.Background(), 30*time.Second)
	subWordlist, derr := loadTaskDictionary(dictCtx, task.Config.SubdomainDictID, "subdomain", 5000)
	dictCancel()
	if derr != nil {
		e.failTask(task, jobID, "加载子域字典失败: "+derr.Error())
		return
	}
	if len(subWordlist) > 0 {
		log.Printf("[TaskExecutor] 使用任务字典 %s，子域词表 %d 条", task.Config.SubdomainDictID, len(subWordlist))
	}

	// 首先为每个非IP目标创建根域名记录
	results := make([]models.ScanResult, 0)

	// 初始化扫描器
	domainScanner := subdomain.NewDomainScanner(200)
	httpxScanner := webscan.NewHttpxScanner(30)

	log.Printf("[TaskExecutor] Using reconkit brute + passive sources for subdomain collection")

	for i, target := range targets {
		// 更新进度
		progress := int((float64(i) / float64(len(targets))) * 50)
		e.updateProgress(task, progress)

		// 跳过 IP 地址
		if isIPAddress(target) {
			result := models.ScanResult{
				TaskID:      task.ID,
				WorkspaceID: task.WorkspaceID,
				Type:        models.ResultTypeSubdomain,
				Source:      "直接输入",
				Data: map[string]interface{}{
					"subdomain":   target,
					"domain":      target,
					"full_domain": target,
					"ip":          target,
					"ips":         []string{target},
					"alive":       true,
				},
				CreatedAt: time.Now(),
			}
			results = append(results, result)
			continue
		}

		// 收集子域名
		subdomainSet := e.collectSubdomains(task, target, domainScanner, subWordlist)

		log.Printf("[TaskExecutor] Total unique subdomains collected: %d for %s", len(subdomainSet), target)

		// 转换为切片
		collectedSubdomains := make([]string, 0, len(subdomainSet))
		for sub := range subdomainSet {
			collectedSubdomains = append(collectedSubdomains, sub)
		}

		// 使用 httpx 丰富子域名信息
		log.Printf("[TaskExecutor] Enriching %d subdomains with HTTP info using httpx", len(collectedSubdomains))
		e.updateProgress(task, 50+int((float64(i)/float64(len(targets)))*40))

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		httpxResults := httpxScanner.EnrichSubdomains(ctx, collectedSubdomains)
		cancel()

		log.Printf("[TaskExecutor] Httpx enriched %d subdomains", len(httpxResults))

		for _, httpResult := range httpxResults {
			ip := ""
			if len(httpResult.IPs) > 0 {
				ip = httpResult.IPs[0]
			}

			result := models.ScanResult{
				TaskID:      task.ID,
				WorkspaceID: task.WorkspaceID,
				Type:        models.ResultTypeSubdomain,
				Source:      "ksubdomain+httpx",
				Data: map[string]interface{}{
					"subdomain":    httpResult.Host,
					"domain":       target,
					"full_domain":  httpResult.Host,
					"url":          httpResult.URL,
					"ip":           ip,
					"ips":          httpResult.IPs,
					"title":        httpResult.Title,
					"status_code":  httpResult.StatusCode,
					"web_server":   httpResult.WebServer,
					"technologies": httpResult.Technologies,
					"cdn":          httpResult.CDN,
					"cdn_name":     httpResult.CDNName,
					"alive":        httpResult.StatusCode > 0,
				},
				CreatedAt: time.Now(),
			}
			results = append(results, result)
		}
	}

	e.saveResults(task, results)
	e.completeTask(task, jobID, len(results))
}

// collectSubdomains 收集子域名：主动爆破 + 被动源 + 空间测绘 + 目标工件 + 候选派生。
//
// T11 起主动/被动/测绘三层都走 reconkit：
//   - brute：dnsres 解析池 + 泛解析基线过滤；
//   - passive：证书透明 + 公开被动 DNS + 国内被动源；
//   - spacemap：FOFA / Hunter / Quake / ZoomEye / Shodan（未配置的源自动跳过）。
func (e *TaskExecutor) collectSubdomains(task *models.Task, target string, domainScanner *subdomain.DomainScanner, wordlist []string) map[string]bool {
	subdomainSet := make(map[string]bool)

	base := baseDomain(target)

	// 使用 reconkit brute 收集子域名；任务配置了字典就用自定义词表。
	log.Printf("[TaskExecutor] Domain scanner scanning %s", target)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	var scanResult *subdomain.DomainScanResult
	if len(wordlist) > 0 {
		scanResult = domainScanner.CustomSubdomainScan(ctx, target, wordlist)
	} else {
		scanResult = domainScanner.QuickSubdomainScan(ctx, target)
	}
	cancel()
	for _, sub := range scanResult.Subdomains {
		subdomainSet[sub.FullDomain] = true
	}
	log.Printf("[TaskExecutor] Domain scanner found %d subdomains for %s", len(scanResult.Subdomains), target)

	if base == "" {
		subdomainSet[target] = true
		return subdomainSet
	}

	// 被动枚举（reconkit）：单源失败只记在 Errors，不影响其他源
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Minute)
	passive, passiveErr := reconsub.Enumerate(ctx2, base, reconsub.Options{
		EnableCT:           config.CrtShEnabled(),
		EnablePassiveDNS:   true,
		EnableCNPassiveDNS: true,
		Timeout:            45 * time.Second,
		Limit:              500,
	})
	cancel2()
	if passiveErr != nil {
		log.Printf("[TaskExecutor] Passive enumeration error for %s: %v", base, passiveErr)
	}
	if passive != nil {
		for _, hit := range passive.Hits {
			subdomainSet[hit.Name] = true
		}
		log.Printf("[TaskExecutor] Passive sources found %d subdomains for %s (per_source=%v, errors=%v)",
			len(passive.Hits), base, passive.PerSrc, passive.Errors)
	}

	// 空间测绘（reconkit spacemap）：任务指定源优先，否则全部已配置引擎
	e.collectEngineSources(task, base, &subdomainSet)

	// 添加原始域名
	subdomainSet[target] = true

	// 目标自身工件：robots.txt / sitemap.xml / crossdomain.xml / CSP / 证书 SAN
	if boolDefaultTrue(task.Config.SubdomainArtifacts) {
		ctx3, cancel3 := context.WithTimeout(context.Background(), 3*time.Minute)
		art := reconsub.CollectFromArtifacts(ctx3, base, nil, 500)
		cancel3()
		if art != nil {
			for _, h := range art.Hits {
				subdomainSet[h.Name] = true
			}
			log.Printf("[TaskExecutor] Artifacts found %d subdomains for %s (per_source=%v, errors=%d)",
				len(art.Hits), base, art.PerSrc, len(art.Errors))
		}
	}

	// 候选派生：已知子域提取 token -> 生成候选 -> DNS 过滤
	if boolDefaultTrue(task.Config.SubdomainPermute) {
		known := make([]string, 0, len(subdomainSet))
		for s := range subdomainSet {
			known = append(known, s)
		}
		sort.Strings(known)

		ctx4, cancel4 := context.WithTimeout(context.Background(), 3*time.Minute)
		if hasWildcardDNS(ctx4, base) {
			log.Printf("[TaskExecutor] Wildcard DNS detected on %s, skip permutation", base)
		} else {
			candidates := permute.Generate(known, base, 3000)
			resolved := resolveCandidates(ctx4, candidates, 64)
			for _, c := range resolved {
				subdomainSet[c] = true
			}
			log.Printf("[TaskExecutor] Permute generated=%d resolved=%d for %s", len(candidates), len(resolved), base)
		}
		cancel4()
	}

	return subdomainSet
}

// boolDefaultTrue 用于「未配置即开启」的开关：nil 表示调用方没显式关。
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

// hasWildcardDNS 用随机不存在的主机名做一次解析，判断是否泛解析。
// 泛解析下派生候选会全部「命中」，继续生成只会制造噪声。
func hasWildcardDNS(ctx context.Context, base string) bool {
	probe := fmt.Sprintf("zre-wildcard-%d.%s", time.Now().UnixNano(), base)
	addrs, err := net.DefaultResolver.LookupHost(ctx, probe)
	return err == nil && len(addrs) > 0
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

// collectEngineSources 用 reconkit spacemap 查询已配置的测绘引擎。
// key 解析顺序：任务级配置 → sources 表（密文解密）→ 全局配置。
// 单源未配置/报错只跳过当前源，不影响其他源。
func (e *TaskExecutor) collectEngineSources(task *models.Task, base string, out *map[string]bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// sources 表 + 全局配置
	keys := NewSourceService().EngineKeys(ctx)
	// 任务级 key 优先
	taskKeys := map[string]string{
		"fofa":   task.Config.FofaKey,
		"hunter": task.Config.HunterKey,
		"quake":  task.Config.QuakeKey,
	}

	client := spacemap.NewClient()
	client.KeyResolver = func(provider string) string {
		if v := strings.TrimSpace(taskKeys[provider]); v != "" {
			return v
		}
		return keys[provider]
	}

	sources := task.Config.ThirdPartySources
	if len(sources) == 0 {
		sources = []string{"fofa", "hunter", "quake", "zoomeye", "shodan"}
	}

	for _, raw := range sources {
		provider := strings.ToLower(strings.TrimSpace(raw))
		if !spacemap.ValidProvider(provider) {
			log.Printf("[TaskExecutor] spacemap: unsupported engine %q, skipped", raw)
			continue
		}
		if !client.SourceConfigured(provider) {
			log.Printf("[TaskExecutor] spacemap: engine %s not configured, skipped", provider)
			continue
		}
		results, _, _, err := client.SearchEngineAssets(ctx, provider, spacemap.DomainQuery(provider, base), 500, 1)
		if err != nil {
			log.Printf("[TaskExecutor] spacemap: engine %s error: %v", provider, err)
			continue
		}
		for _, r := range results {
			host := r.Domain
			if host == "" {
				host = r.Host
			}
			if host != "" {
				(*out)[host] = true
			}
		}
		log.Printf("[TaskExecutor] spacemap: engine %s found %d assets for %s", provider, len(results), base)
	}
}

// executeTakeoverScan 执行子域名接管检测扫描
func (e *TaskExecutor) executeTakeoverScan(task *models.Task, jobID int64) {
	log.Printf("[TaskExecutor] Executing takeover scan for task: %s", task.ID.Hex())

	targets := task.Targets
	if len(targets) == 0 {
		e.failTask(task, jobID, "没有目标")
		return
	}

	results := make([]models.ScanResult, 0)
	takeoverScanner := subdomain.NewTakeoverScanner(20)

	// 收集所有要检测的子域名
	allSubdomains := make([]string, 0)

	for i, target := range targets {
		progress := int((float64(i) / float64(len(targets))) * 50)
		e.updateProgress(task, progress)

		if isIPAddress(target) {
			continue
		}
		allSubdomains = append(allSubdomains, target)
	}

	if len(allSubdomains) == 0 {
		e.failTask(task, jobID, "没有有效的域名目标")
		return
	}

	log.Printf("[TaskExecutor] Checking %d domains for takeover vulnerabilities", len(allSubdomains))

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	e.updateProgress(task, 50)

	takeoverResults, err := takeoverScanner.ScanBatch(ctx, allSubdomains)
	if err != nil {
		log.Printf("[TaskExecutor] Takeover scan error: %v", err)
	}

	e.updateProgress(task, 90)

	for _, tr := range takeoverResults {
		if tr.Vulnerable {
			log.Printf("[TaskExecutor] Found vulnerable subdomain: %s (Service: %s)", tr.Domain, tr.Service)

			result := models.ScanResult{
				TaskID:      task.ID,
				WorkspaceID: task.WorkspaceID,
				Type:        models.ResultTypeTakeover,
				Source:      "takeover_scanner",
				Data: map[string]interface{}{
					"subdomain":    tr.Domain,
					"cname":        tr.CNAME,
					"provider":     tr.Service,
					"vulnerable":   tr.Vulnerable,
					"fingerprints": tr.Fingerprints,
					"reason":       tr.Reason,
					"discussion":   tr.Discussion,
					"severity":     "high",
				},
				CreatedAt: time.Now(),
			}
			results = append(results, result)
		}
	}

	log.Printf("[TaskExecutor] Takeover scan completed: %d vulnerable domains found", len(results))

	e.saveResults(task, results)
	e.completeTask(task, jobID, len(results))
}
