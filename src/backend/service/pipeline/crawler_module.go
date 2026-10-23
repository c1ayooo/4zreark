package pipeline

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/scanner/scope"
	"github.com/c1ayooo/4zreark/scanner/webscan"
)

// CrawlerModule URL爬虫模块
// 接收HTTP资产，执行URL爬虫，输出发现的URL
// 支持批量模式：收集所有URL后批量调用Katana
type CrawlerModule struct {
	BaseModule
	katanaScanner *webscan.KatanaScanner
	resultChan    chan interface{}
	concurrency   int
	useKatana     bool
	crawlDepth    int
	batchMode     bool          // 是否使用批量模式
	batchSize     int           // 批量大小
	batchTimeout  time.Duration // 批量收集超时
	scope         *scope.Scope
}

// SetScope 设置任务授权边界。
// SetRate 收紧 katana 的并发与速率，跟随任务级节奏。
func (m *CrawlerModule) SetRate(ratePerSec, concurrency int) {
	if m.katanaScanner == nil {
		return
	}
	if concurrency > 0 {
		m.concurrency = concurrency
		m.katanaScanner.Concurrency = concurrency
	}
	if ratePerSec > 0 {
		m.katanaScanner.RateLimit = ratePerSec
	}
}

func (m *CrawlerModule) SetScope(s *scope.Scope) { m.scope = s }

func (m *CrawlerModule) allowsURL(raw string) bool {
	return m.scope == nil || m.scope.AllowsURL(raw)
}

// NewCrawlerModule 创建爬虫模块
func NewCrawlerModule(ctx context.Context, nextModule ModuleRunner, concurrency int, useKatana bool) *CrawlerModule {
	if concurrency <= 0 {
		concurrency = 5
	}

	m := &CrawlerModule{
		BaseModule: BaseModule{
			name:       "Crawler",
			ctx:        ctx,
			nextModule: nextModule,
			dupChecker: NewDuplicateChecker(),
		},
		katanaScanner: webscan.NewKatanaScanner(),
		resultChan:    make(chan interface{}, 1000),
		concurrency:   concurrency,
		useKatana:     useKatana,
		crawlDepth:    3,
		batchMode:     true,             // 默认启用批量模式
		batchSize:     100,              // 默认每批100个URL
		batchTimeout:  30 * time.Second, // 批量收集等待30秒
	}
	return m
}

// SetCrawlDepth 设置爬取深度
func (m *CrawlerModule) SetCrawlDepth(depth int) {
	if depth > 0 {
		m.crawlDepth = depth
		m.katanaScanner.Depth = depth
	}
}

// SetBatchMode 设置批量模式
func (m *CrawlerModule) SetBatchMode(enabled bool, batchSize int) {
	m.batchMode = enabled
	if batchSize > 0 {
		m.batchSize = batchSize
	}
}

// ModuleRun 运行模块
func (m *CrawlerModule) ModuleRun() error {
	// 检查爬虫工具是否可用
	katanaAvailable := m.useKatana && m.katanaScanner.IsAvailable()

	if !katanaAvailable {
		log.Printf("[%s] No crawler available, passing through", m.name)
		return m.RunPassThrough()
	}

	log.Printf("[%s] Starting with Katana=%v, BatchMode=%v", m.name, katanaAvailable, m.batchMode)

	// 如果启用批量模式且Katana可用，使用批量处理
	if m.batchMode && katanaAvailable {
		return m.runBatchMode()
	}

	// 否则使用流式处理（逐个URL爬取）
	return m.runStreamMode()
}

// runBatchMode 批量模式：收集所有URL后批量调用Katana -list
func (m *CrawlerModule) runBatchMode() error {
	var nextModuleRun sync.WaitGroup

	// 启动下一个模块
	if m.nextModule != nil {
		nextModuleRun.Add(1)
		go func() {
			defer nextModuleRun.Done()
			if err := m.nextModule.ModuleRun(); err != nil {
				log.Printf("[%s] Next module error: %v", m.name, err)
			}
		}()
	}

	// 收集所有URL
	var urlsToScan []string
	urlSet := make(map[string]bool)

	log.Printf("[%s] Collecting URLs for batch crawling...", m.name)

	// 收集阶段：等待所有输入
	for {
		select {
		case <-m.ctx.Done():
			log.Printf("[%s] Context cancelled during collection", m.name)
			if m.nextModule != nil {
				m.nextModule.CloseInput()
			}
			nextModuleRun.Wait()
			return nil

		case data, ok := <-m.input:
			if !ok {
				// 输入通道关闭，开始处理收集的URL
				log.Printf("[%s] Input closed, collected %d URLs to crawl", m.name, len(urlsToScan))
				goto processBatch
			}

			// 子域扫描的 HTTP 探测结果本身就是可爬入口
			if sub, ok := data.(SubdomainResult); ok {
				if m.nextModule != nil {
					select {
					case <-m.ctx.Done():
					case m.nextModule.GetInput() <- sub:
					}
				}
				if sub.URL != "" && m.allowsURL(sub.URL) && !urlSet[sub.URL] {
					urlSet[sub.URL] = true
					urlsToScan = append(urlsToScan, sub.URL)
				}
				continue
			}

			// 处理 AssetHttp 类型
			asset, ok := data.(AssetHttp)
			if !ok {
				// 非预期类型，直接传递给下一个模块
				if m.nextModule != nil {
					select {
					case <-m.ctx.Done():
					case m.nextModule.GetInput() <- data:
					}
				}
				continue
			}

			// 先传递 AssetHttp 结果（确保 Web 服务数据被收集）
			if m.nextModule != nil {
				select {
				case <-m.ctx.Done():
				case m.nextModule.GetInput() <- asset:
				}
			}

			// 收集有效的HTTP URL
			if asset.URL != "" && m.allowsURL(asset.URL) && !urlSet[asset.URL] {
				urlSet[asset.URL] = true
				urlsToScan = append(urlsToScan, asset.URL)
			}
		}
	}

processBatch:
	if len(urlsToScan) == 0 {
		log.Printf("[%s] No URLs to crawl", m.name)
		if m.nextModule != nil {
			m.nextModule.CloseInput()
		}
		nextModuleRun.Wait()
		return nil
	}

	// 批量爬取
	log.Printf("[%s] Starting batch crawl for %d URLs", m.name, len(urlsToScan))

	m.batchCrawlWithKatana(urlsToScan)

	// 关闭下一个模块的输入
	if m.nextModule != nil {
		m.nextModule.CloseInput()
	}

	log.Printf("[%s] Batch crawl completed, waiting for next module", m.name)
	nextModuleRun.Wait()
	return nil
}

// batchCrawlWithKatana 使用Katana批量爬取
func (m *CrawlerModule) batchCrawlWithKatana(urls []string) {
	// 根据URL数量动态设置超时（每个URL最多3分钟）
	timeout := time.Duration(len(urls)*3) * time.Minute
	if timeout < 5*time.Minute {
		timeout = 5 * time.Minute
	}
	if timeout > 30*time.Minute {
		timeout = 30 * time.Minute
	}

	ctx, cancel := context.WithTimeout(m.ctx, timeout)
	defer cancel()

	log.Printf("[%s] Calling Katana.CrawlList with %d URLs (timeout: %v)", m.name, len(urls), timeout)

	result, err := m.katanaScanner.CrawlList(ctx, urls)
	if err != nil {
		// 超时/取消时 katana 已把部分结果写进输出文件并解析进 result，不能整批丢弃。
		if result == nil || len(result.URLs) == 0 {
			log.Printf("[%s] Katana batch crawl error: %v", m.name, err)
			return
		}
		log.Printf("[%s] Katana batch crawl error: %v（采用部分结果 %d 条）", m.name, err, len(result.URLs))
	}

	if result == nil {
		log.Printf("[%s] Katana batch crawl returned nil", m.name)
		return
	}

	log.Printf("[%s] Katana batch found %d URLs", m.name, len(result.URLs))

	// 发送爬取结果
	for _, url := range result.URLs {
		urlResult := UrlResult{
			Input:       url.Source,
			Output:      url.URL,
			Source:      "katana",
			Method:      url.Method,
			StatusCode:  url.StatusCode,
			ContentType: url.ContentType,
			Length:      url.Length,
			Tag:         url.Tag,
			Attribute:   url.Attribute,
			Referrer:    url.Source,
		}

		// URL去重
		if m.dupChecker.IsURLDuplicate(urlResult.Output) {
			continue
		}

		if m.nextModule != nil {
			select {
			case <-m.ctx.Done():
				return
			case m.nextModule.GetInput() <- urlResult:
			}
		}
	}
}

// runStreamMode 流式模式：逐个URL爬取（原有逻辑）
func (m *CrawlerModule) runStreamMode() error {
	var allWg sync.WaitGroup
	var resultWg sync.WaitGroup
	var nextModuleRun sync.WaitGroup

	// 并发控制
	sem := make(chan struct{}, m.concurrency)

	// 启动下一个模块
	if m.nextModule != nil {
		nextModuleRun.Add(1)
		go func() {
			defer nextModuleRun.Done()
			if err := m.nextModule.ModuleRun(); err != nil {
				log.Printf("[%s] Next module error: %v", m.name, err)
			}
		}()
	}

	// 结果处理协程
	resultWg.Add(1)
	go func() {
		defer resultWg.Done()
		for result := range m.resultChan {
			if urlResult, ok := result.(UrlResult); ok {
				// URL去重
				if m.dupChecker.IsURLDuplicate(urlResult.Output) {
					continue
				}
			}

			// 发送到下一个模块
			if m.nextModule != nil {
				select {
				case <-m.ctx.Done():
					return
				case m.nextModule.GetInput() <- result:
				}
			}
		}
		if m.nextModule != nil {
			m.nextModule.CloseInput()
		}
	}()

	// 处理输入
	for {
		select {
		case <-m.ctx.Done():
			allWg.Wait()
			close(m.resultChan)
			resultWg.Wait()
			nextModuleRun.Wait()
			return nil

		case data, ok := <-m.input:
			if !ok {
				allWg.Wait()
				close(m.resultChan)
				resultWg.Wait()
				log.Printf("[%s] Input closed, waiting for next module", m.name)
				nextModuleRun.Wait()
				return nil
			}

			// 处理 AssetHttp 类型
			asset, ok := data.(AssetHttp)
			if !ok {
				// 非预期类型，直接传递
				m.resultChan <- data
				continue
			}

			// 先传递 AssetHttp 结果（确保 Web 服务数据被收集）
			m.resultChan <- asset

			// 只处理有效的HTTP资产
			if asset.URL == "" {
				continue
			}

			allWg.Add(1)
			go func(a AssetHttp) {
				defer allWg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				m.crawlTarget(a)
			}(asset)
		}
	}
}

// crawlTarget 爬取目标
func (m *CrawlerModule) crawlTarget(asset AssetHttp) {
	if !m.allowsURL(asset.URL) {
		return
	}
	target := asset.URL

	log.Printf("[%s] Crawling %s", m.name, target)

	// 使用 Katana 爬取
	if m.useKatana {
		m.crawlWithKatana(target, asset)
	}
}

// crawlWithKatana 使用Katana爬取
func (m *CrawlerModule) crawlWithKatana(target string, asset AssetHttp) {
	ctx, cancel := context.WithTimeout(m.ctx, 10*time.Minute)
	defer cancel()

	result, err := m.katanaScanner.Crawl(ctx, target)
	if err != nil {
		// 超时/取消时保留已解析出的部分结果。
		if result == nil || len(result.URLs) == 0 {
			log.Printf("[%s] Katana error for %s: %v", m.name, target, err)
			return
		}
		log.Printf("[%s] Katana error for %s: %v（采用部分结果 %d 条）", m.name, target, err, len(result.URLs))
	}

	if result == nil {
		return
	}

	log.Printf("[%s] Katana found %d URLs for %s", m.name, len(result.URLs), target)

	skipped := 0
	for _, url := range result.URLs {
		// 非 JS 静态资源不进结果；JS 保留，里面的接口/路由需要继续分析。
		if scope.IsStaticAsset(url.URL) || scope.IsNoisyCrawlerURL(url.URL) {
			skipped++
			continue
		}
		// katana 的边界是注册域（-fs rdn），任务目标是子域时会爬出授权范围；
		// 产出侧按任务 scope 再拦一道，不让越界 URL 流向下游模块。
		if !m.allowsURL(url.URL) {
			skipped++
			continue
		}
		urlResult := UrlResult{
			Input:       target,
			Output:      url.URL,
			Source:      "katana",
			Method:      url.Method,
			StatusCode:  url.StatusCode,
			ContentType: url.ContentType,
			Length:      url.Length,
			Tag:         url.Tag,
			Attribute:   url.Attribute,
			Referrer:    url.Source,
		}

		select {
		case <-m.ctx.Done():
			return
		case m.resultChan <- urlResult:
		}
	}
}

// DirScanModule 目录扫描模块
// 接收HTTP资产，使用 Spray 执行目录爆破，输出发现的URL
type DirScanModule struct {
	BaseModule
	sprayScanner *webscan.SprayScanner
	resultChan   chan interface{}
	concurrency  int
	wordlist     []string
	batchMode    bool          // 批量模式
	batchSize    int           // 批量大小
	batchTimeout time.Duration // 批量收集超时
	enableBackup bool          // 扫描备份文件
	enableCommon bool          // 扫描通用文件
	scope        *scope.Scope
}

// SetRate 收紧 spray 的并发与速率，让它跟随任务级节奏。
// spray 自带 50 并发且默认不限速，不跟着任务走就等于绕过整条限速链。
func (m *DirScanModule) SetRate(ratePerSec, concurrency int) {
	if m.sprayScanner == nil {
		return
	}
	if concurrency > 0 {
		m.concurrency = concurrency
		m.sprayScanner.Concurrency = concurrency
	}
	if ratePerSec > 0 {
		m.sprayScanner.RateLimit = ratePerSec
	}
}

// SetScope 设置任务授权边界。
func (m *DirScanModule) SetScope(s *scope.Scope) { m.scope = s }

func (m *DirScanModule) allowsURL(raw string) bool {
	return m.scope == nil || m.scope.AllowsURL(raw)
}

// NewDirScanModule 创建目录扫描模块
func NewDirScanModule(ctx context.Context, nextModule ModuleRunner, concurrency int, wordlist []string) *DirScanModule {
	if concurrency <= 0 {
		concurrency = 20
	}

	m := &DirScanModule{
		BaseModule: BaseModule{
			name:       "DirScan",
			ctx:        ctx,
			nextModule: nextModule,
			dupChecker: NewDuplicateChecker(),
		},
		sprayScanner: webscan.NewSprayScanner(),
		resultChan:   make(chan interface{}, 500),
		concurrency:  concurrency,
		wordlist:     wordlist,
		batchMode:    true,             // 默认启用批量模式
		batchSize:    50,               // 每批50个URL
		batchTimeout: 30 * time.Second, // 批量收集等待30秒
		enableBackup: false,            // --bak 会把每个路径放大成多种备份变体，信息收集阶段默认关掉
		enableCommon: false,            // --common 同理，先拿到主路径再谈扩展探测
	}

	// 配置 Spray 扫描器
	if m.sprayScanner != nil {
		m.sprayScanner.Concurrency = concurrency
		m.sprayScanner.EnableBackup = m.enableBackup
		m.sprayScanner.EnableCommon = m.enableCommon
		// 设计口径：单目标字典扫描不超过 200 req/s；spray 的 --rate-limit 落地
		m.sprayScanner.RateLimit = 200
	}

	return m
}

// SetBatchMode 设置批量模式
func (m *DirScanModule) SetBatchMode(enabled bool, batchSize int) {
	m.batchMode = enabled
	if batchSize > 0 {
		m.batchSize = batchSize
	}
}

// SetScanOptions 设置扫描选项
func (m *DirScanModule) SetScanOptions(enableBackup, enableCommon bool) {
	m.enableBackup = enableBackup
	m.enableCommon = enableCommon
	if m.sprayScanner != nil {
		m.sprayScanner.EnableBackup = enableBackup
		m.sprayScanner.EnableCommon = enableCommon
	}
}

// ModuleRun 运行模块
func (m *DirScanModule) ModuleRun() error {
	// 检查 Spray 是否可用；不可用则透传，否则下游（结果收集器）永远收不到数据
	if m.sprayScanner == nil || !m.sprayScanner.IsAvailable() {
		log.Printf("[%s] Spray not available, passing through", m.name)
		return m.RunPassThrough()
	}

	// 报告模块开始
	m.ReportModuleStart(0)
	defer m.ReportModuleComplete()

	log.Printf("[%s] Using Spray for directory scanning (batch=%v)", m.name, m.batchMode)

	// 如果启用批量模式，使用批量处理
	if m.batchMode {
		return m.runBatchMode()
	}

	// 否则使用流式处理
	return m.runStreamMode()
}

// runBatchMode 批量模式：收集所有URL后批量调用Spray
func (m *DirScanModule) runBatchMode() error {
	var nextModuleRun sync.WaitGroup

	// 启动下一个模块
	if m.nextModule != nil {
		nextModuleRun.Add(1)
		go func() {
			defer nextModuleRun.Done()
			if err := m.nextModule.ModuleRun(); err != nil {
				log.Printf("[%s] Next module error: %v", m.name, err)
			}
		}()
	}

	// 收集所有URL
	var urlsToScan []string
	urlSet := make(map[string]bool)

	log.Printf("[%s] Collecting URLs for batch directory scanning...", m.name)

	// 收集阶段
	for {
		select {
		case <-m.ctx.Done():
			log.Printf("[%s] Context cancelled during collection", m.name)
			if m.nextModule != nil {
				m.nextModule.CloseInput()
			}
			nextModuleRun.Wait()
			return nil

		case data, ok := <-m.input:
			if !ok {
				log.Printf("[%s] Input closed, collected %d URLs to scan", m.name, len(urlsToScan))
				goto processBatch
			}

			// 报告进度
			m.ReportProgress(1, 0)

			// 处理 AssetHttp 类型
			asset, ok := data.(AssetHttp)
			if !ok {
				// 非预期类型，直接传递给下一个模块
				if m.nextModule != nil {
					select {
					case <-m.ctx.Done():
					case m.nextModule.GetInput() <- data:
					}
				}
				continue
			}

			// 先传递 AssetHttp 结果
			if m.nextModule != nil {
				select {
				case <-m.ctx.Done():
				case m.nextModule.GetInput() <- asset:
				}
			}

			// 收集有效的HTTP URL
			if asset.URL != "" && m.allowsURL(asset.URL) && !urlSet[asset.URL] {
				urlSet[asset.URL] = true
				urlsToScan = append(urlsToScan, asset.URL)
			}
		}
	}

processBatch:
	if len(urlsToScan) == 0 {
		log.Printf("[%s] No URLs to scan", m.name)
		if m.nextModule != nil {
			m.nextModule.CloseInput()
		}
		nextModuleRun.Wait()
		return nil
	}

	// 批量扫描
	log.Printf("[%s] Starting batch directory scan for %d URLs with Spray", m.name, len(urlsToScan))

	ctx, cancel := context.WithTimeout(m.ctx, 60*time.Minute)
	defer cancel()

	result, err := m.sprayScanner.ScanBatchWithWordlist(ctx, urlsToScan, m.wordlist)
	if err != nil {
		log.Printf("[%s] Spray batch scan error: %v", m.name, err)
	}

	if result != nil {
		entries := webscan.FilterSoft404Entries(ctx, result.Results, nil)
		log.Printf("[%s] Spray found %d results (%d after soft-404 filter)", m.name, len(result.Results), len(entries))

		for _, entry := range entries {
			// 输出有效的结果（排除根路径和无效状态码）
			// 保留: 2xx(成功), 3xx(重定向), 401(未授权), 403(禁止)
			validStatus := (entry.StatusCode >= 200 && entry.StatusCode < 400) ||
				entry.StatusCode == 401 || entry.StatusCode == 403

			// 跳过根路径（只有域名没有具体路径）
			isRootPath := entry.Path == "" || entry.Path == "/"

			if validStatus && !isRootPath {
				urlResult := UrlResult{
					Input:       entry.Host,
					Output:      entry.URL,
					Source:      "dirscan",
					Method:      "GET",
					StatusCode:  entry.StatusCode,
					ContentType: entry.ContentType,
					Length:      entry.BodyLength,
				}

				// 报告输出
				m.ReportOutput(1)

				if m.nextModule != nil {
					select {
					case <-m.ctx.Done():
						goto cleanup
					case m.nextModule.GetInput() <- urlResult:
					}
				}
			}
		}
	}

cleanup:
	if m.nextModule != nil {
		m.nextModule.CloseInput()
	}
	nextModuleRun.Wait()
	return nil
}

// runStreamMode 流式模式：逐个URL扫描
func (m *DirScanModule) runStreamMode() error {
	var allWg sync.WaitGroup
	var resultWg sync.WaitGroup
	var nextModuleRun sync.WaitGroup

	// 并发控制
	sem := make(chan struct{}, m.concurrency)

	// 启动下一个模块
	if m.nextModule != nil {
		nextModuleRun.Add(1)
		go func() {
			defer nextModuleRun.Done()
			if err := m.nextModule.ModuleRun(); err != nil {
				log.Printf("[%s] Next module error: %v", m.name, err)
			}
		}()
	}

	// 结果处理协程
	resultWg.Add(1)
	go func() {
		defer resultWg.Done()
		for result := range m.resultChan {
			// 报告输出
			m.ReportOutput(1)

			if m.nextModule != nil {
				select {
				case <-m.ctx.Done():
					return
				case m.nextModule.GetInput() <- result:
				}
			}
		}
		if m.nextModule != nil {
			m.nextModule.CloseInput()
		}
	}()

	// 处理输入
	for {
		select {
		case <-m.ctx.Done():
			allWg.Wait()
			close(m.resultChan)
			resultWg.Wait()
			nextModuleRun.Wait()
			return nil

		case data, ok := <-m.input:
			if !ok {
				allWg.Wait()
				close(m.resultChan)
				resultWg.Wait()
				log.Printf("[%s] Input closed, waiting for next module", m.name)
				nextModuleRun.Wait()
				return nil
			}

			// 报告进度
			m.ReportProgress(1, 0)

			// 处理 AssetHttp 类型
			asset, ok := data.(AssetHttp)
			if !ok {
				m.resultChan <- data
				continue
			}

			// 先将 AssetHttp 传递给下一个模块
			m.resultChan <- asset

			if asset.URL == "" {
				continue
			}

			allWg.Add(1)
			go func(a AssetHttp) {
				defer allWg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				m.scanWithSpray(a)
			}(asset)
		}
	}
}

// scanWithSpray 使用 Spray 扫描单个目标
func (m *DirScanModule) scanWithSpray(asset AssetHttp) {
	if !m.allowsURL(asset.URL) {
		return
	}
	target := asset.URL

	log.Printf("[%s] Scanning with Spray: %s", m.name, target)

	ctx, cancel := context.WithTimeout(m.ctx, 15*time.Minute)
	defer cancel()

	result, err := m.sprayScanner.ScanWithWordlist(ctx, target, m.wordlist)
	if err != nil {
		log.Printf("[%s] Spray error for %s: %v", m.name, target, err)
		return
	}

	if result == nil {
		return
	}

	entries := webscan.FilterSoft404(m.ctx, target, result.Results, nil)
	log.Printf("[%s] Spray found %d paths for %s (%d after soft-404 filter)", m.name, len(result.Results), target, len(entries))

	for _, entry := range entries {
		// 输出有效的结果（排除根路径和无效状态码）
		validStatus := (entry.StatusCode >= 200 && entry.StatusCode < 400) ||
			entry.StatusCode == 401 || entry.StatusCode == 403
		isRootPath := entry.Path == "" || entry.Path == "/"

		if validStatus && !isRootPath {
			urlResult := UrlResult{
				Input:       target,
				Output:      entry.URL,
				Source:      "dirscan",
				Method:      "GET",
				StatusCode:  entry.StatusCode,
				ContentType: entry.ContentType,
				Length:      entry.BodyLength,
			}

			select {
			case <-m.ctx.Done():
				return
			case m.resultChan <- urlResult:
			}
		}
	}
}
