package pipeline

import (
	"context"
	"log"
	"net"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/scanner/scope"
	"github.com/c1ayooo/4zreark/scanner/subdomain"
	"github.com/c1ayooo/4zreark/scanner/webscan"
)

// SubdomainScanModule 子域名扫描模块
// 使用综合扫描器：主动枚举（字典爆破）为主，第三方API为辅
type SubdomainScanModule struct {
	BaseModule
	httpxScanner    *webscan.HttpxScanner // HTTP 探测器
	resultChan      chan interface{}
	config          *subdomain.ActiveScannerConfig
	resolveIP       bool
	enableHTTPProbe bool // 是否进行 HTTP 探测
	dnsResolvers    []string
	scope           *scope.Scope
}

// SetScope 设置任务授权边界。
func (m *SubdomainScanModule) SetScope(s *scope.Scope) { m.scope = s }

func (m *SubdomainScanModule) allowsHost(host string) bool {
	return m.scope == nil || m.scope.AllowsHost(host)
}

// SubdomainScanConfig 子域名扫描配置
type SubdomainScanConfig struct {
	// 主动枚举配置
	BruteConcurrency int  // 字典爆破并发数 (默认 500)
	EnableBrute      bool // 是否启用字典爆破 (默认 true)
	EnableRecursive  bool // 是否启用递归爆破 (默认 false)
	RecursiveDepth   int  // 递归深度 (默认 2)
	// Wordlist 任务级子域字典；为空时用全局内置词表。
	Wordlist []string
	// LearnedWords 字典自学习热词，追加在词表之后。
	LearnedWords []string

	// API 配置
	EnableAPI     bool     // 是否启用第三方API (默认 true)
	APISources    []string // 启用的API源
	APIMaxResults int      // 每个API最大结果数 (默认 500)
	// EngineQueryMaxPerEngine 单任务内每个引擎最多查询的注册域数（防烧额度）。
	// <=0 取默认 10。任务侧所有扫描器实例共享同一个守卫。
	EngineQueryMaxPerEngine int

	// API 密钥
	FofaKey           string
	HunterKey         string
	QuakeKey          string
	SecurityTrailsKey string

	// 其他
	ResolveIP        bool // 是否解析IP (默认 true)
	VerifySubdomains bool // 是否验证子域名存活 (默认 true)
	EnableHTTPProbe  bool // 是否进行HTTP探测获取标题、状态码等 (默认 false)
}

// DefaultSubdomainScanConfig 默认配置
func DefaultSubdomainScanConfig() *SubdomainScanConfig {
	return &SubdomainScanConfig{
		BruteConcurrency: 20,
		EnableBrute:      true,
		EnableRecursive:  false,
		RecursiveDepth:   2,
		EnableAPI:        false, // 默认关闭API，只使用字典爆破
		APISources:       []string{},
		APIMaxResults:    500,

		EngineQueryMaxPerEngine: 10,
		ResolveIP:               true,
		VerifySubdomains:        true,
	}
}

// NewSubdomainScanModule 创建子域名扫描模块（新版本，使用综合扫描器）
func NewSubdomainScanModule(ctx context.Context, nextModule ModuleRunner, maxEnumTime int, resolveIP bool) *SubdomainScanModule {
	// 兼容旧接口，使用默认配置
	cfg := DefaultSubdomainScanConfig()
	cfg.ResolveIP = resolveIP
	return NewSubdomainScanModuleWithConfig(ctx, nextModule, cfg)
}

// NewSubdomainScanModuleWithHTTPProbe 创建子域名扫描模块（启用 HTTP 探测）
func NewSubdomainScanModuleWithHTTPProbe(ctx context.Context, nextModule ModuleRunner, maxEnumTime int, resolveIP bool, enableHTTPProbe bool) *SubdomainScanModule {
	cfg := DefaultSubdomainScanConfig()
	cfg.ResolveIP = resolveIP
	cfg.EnableHTTPProbe = enableHTTPProbe
	return NewSubdomainScanModuleWithConfig(ctx, nextModule, cfg)
}

// NewSubdomainScanModuleWithConfig 使用完整配置创建子域名扫描模块
func NewSubdomainScanModuleWithConfig(ctx context.Context, nextModule ModuleRunner, scanConfig *SubdomainScanConfig) *SubdomainScanModule {
	if scanConfig == nil {
		scanConfig = DefaultSubdomainScanConfig()
	}

	// 构建 ActiveScanner 配置
	activeCfg := &subdomain.ActiveScannerConfig{
		BruteConcurrency:  scanConfig.BruteConcurrency,
		EnableBrute:       scanConfig.EnableBrute,
		EnableRecursive:   scanConfig.EnableRecursive,
		RecursiveDepth:    scanConfig.RecursiveDepth,
		WildcardDetection: true,
		ResolveTimeout:    3,
		EnableAPI:         scanConfig.EnableAPI,
		APISources:        scanConfig.APISources,
		APIMaxResults:     scanConfig.APIMaxResults,
		VerifySubdomains:  scanConfig.VerifySubdomains,
		// 防烧额度闸门：每域名的扫描器实例共享同一个守卫（按注册域去重 + 上限）。
		EngineGuard:     subdomain.NewEngineQueryGuard(scanConfig.EngineQueryMaxPerEngine),
		EnableHTTPProbe: false,
		Wordlist:        scanConfig.Wordlist,
		LearnedWords:    scanConfig.LearnedWords,
		EngineKeys: map[string]string{
			"fofa":           scanConfig.FofaKey,
			"hunter":         scanConfig.HunterKey,
			"quake":          scanConfig.QuakeKey,
			"securitytrails": scanConfig.SecurityTrailsKey,
		},
	}

	// 创建 httpx 扫描器（如果启用 HTTP 探测）
	// 并发跟随爆破并发（由任务级 rate 推导），不再硬编码 30。
	var httpxScanner *webscan.HttpxScanner
	if scanConfig.EnableHTTPProbe {
		probeConcurrency := scanConfig.BruteConcurrency
		if probeConcurrency <= 0 {
			probeConcurrency = 10
		}
		httpxScanner = webscan.NewHttpxScanner(probeConcurrency)
	}

	m := &SubdomainScanModule{
		BaseModule: BaseModule{
			name:       "SubdomainScan",
			ctx:        ctx,
			nextModule: nextModule,
			dupChecker: NewDuplicateChecker(),
		},
		httpxScanner:    httpxScanner,
		resultChan:      make(chan interface{}, 2000), // 增大缓冲区
		config:          activeCfg,
		resolveIP:       scanConfig.ResolveIP,
		enableHTTPProbe: scanConfig.EnableHTTPProbe,
		dnsResolvers: []string{
			"8.8.8.8:53",
			"1.1.1.1:53",
			"114.114.114.114:53",
			"223.5.5.5:53",
		},
	}

	return m
}

// ModuleRun 运行模块
func (m *SubdomainScanModule) ModuleRun() error {
	var allWg sync.WaitGroup
	var resultWg sync.WaitGroup
	var nextModuleRun sync.WaitGroup

	// 报告模块开始
	m.ReportModuleStart(0)
	defer m.ReportModuleComplete()

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

	// 结果处理协程 - 发送到下一个模块
	resultWg.Add(1)
	go func() {
		defer resultWg.Done()
		forwarded := 0
		for result := range m.resultChan {
			forwarded++
			// 报告输出
			m.ReportOutput(1)
			// 发送到下一个模块
			if m.nextModule != nil {
				select {
				case <-m.ctx.Done():
					return
				case m.nextModule.GetInput() <- result:
				}
			}
		}
		// 子域枚举完成：本阶段产出的子域数就是下游端口扫描的分母
		//（子域 1:1 流经域名验证/端口预处理进入端口扫描，端口扫描逐条消费）。
		// 没有这个分母，端口扫描的进度分子会落在 483/0 这种缺失态。
		if m.progressTracker != nil && forwarded > 0 {
			m.progressTracker.UpdateModuleTotal("PortScan", forwarded)
		}
		// 关闭下一个模块的输入
		if m.nextModule != nil {
			m.nextModule.CloseInput()
		}
	}()

	// 处理输入
	var processedCount int
	domainSem := make(chan struct{}, domainScanConcurrency)
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
				// 输入通道关闭
				allWg.Wait()
				close(m.resultChan)
				resultWg.Wait()
				log.Printf("[%s] Input closed, waiting for next module", m.name)
				nextModuleRun.Wait()
				return nil
			}

			processedCount++
			// 报告进度
			m.ReportProgress(1, 0)

			// 处理字符串类型的主域名
			domain, ok := data.(string)
			if !ok {
				// 尝试 SubdomainResult 类型
				if sr, ok := data.(SubdomainResult); ok {
					domain = sr.Domain
				} else {
					log.Printf("[%s] Unexpected data type: %T", m.name, data)
					continue
				}
			}

			allWg.Add(1)
			go func(d string) {
				domainSem <- struct{}{}
				defer func() { <-domainSem; allWg.Done() }()
				m.scanSubdomains(d)
			}(domain)
		}
	}
}

// domainScanConcurrency 同时枚举的域名数。每域名一个独立 ActiveScanner 实例
// （ActiveScanner 每次 Run 会重置内部去重表和回调，共享实例并发 Run 会互相清掉
// 结果），信号量只负责控制外层并发，避免目标多时 goroutine 失控。
const domainScanConcurrency = 2

// scanSubdomains 执行子域名扫描（使用综合扫描器）
func (m *SubdomainScanModule) scanSubdomains(domain string) {
	log.Printf("[%s] Starting comprehensive subdomain scan for %s", m.name, domain)
	log.Printf("[%s] Brute enabled: %v, API enabled: %v, Sources: %v, HTTPProbe: %v",
		m.name, m.config.EnableBrute, m.config.EnableAPI, m.config.APISources, m.enableHTTPProbe)

	// 收集所有子域名，如果启用了 HTTP 探测，需要批量处理
	var collectMu sync.Mutex
	var collectedSubdomains []string
	var collectedResults []SubdomainResult

	flushCollected := func() {
		collectMu.Lock()
		batch := collectedSubdomains
		batchResults := collectedResults
		collectedSubdomains = nil
		collectedResults = nil
		collectMu.Unlock()
		m.enrichAndSend(batch, batchResults)
	}

	// 每域名独立扫描器实例：被动枚举、API 枚举、爆破三个内部 goroutine 会并发
	// 调用回调，模块侧的批处理缓冲必须加锁（见 collectMu）。
	scanner := subdomain.NewActiveScanner(m.config)

	// 使用回调函数实时处理结果
	err := scanner.ScanWithCallback(m.ctx, domain, func(subResult subdomain.SubdomainResult) {
		if !m.allowsHost(subResult.FullDomain) {
			return
		}
		// 去重检查
		if m.dupChecker.IsSubdomainDuplicate(subResult.FullDomain) {
			return
		}

		// 来源用扫描器带回的引擎级标识（passive:crtsh / spacemap:fofa / brute），
		// 不再一律折叠成 active；老扫描器没填时才回落。
		src := subResult.Source
		if src == "" {
			src = "active"
		}
		result := SubdomainResult{
			Host:       subResult.FullDomain, // 子域名完整名称
			Domain:     domain,               // 根域名
			RootDomain: domain,               // 根域名
			Source:     src,
			IPs:        subResult.IPs,
		}

		// 如果没有 IP 且需要解析
		if m.resolveIP && len(result.IPs) == 0 {
			result.IPs = m.resolveIPs(subResult.FullDomain)
		}

		if m.enableHTTPProbe && m.httpxScanner != nil {
			// 小批探测：每攒够一批就探测并立即下发，页面不用等整轮枚举结束。
			// 结果按子域逐条发送，扫描阶段不做去重，去重留给任务结束后的归一步骤。
			collectMu.Lock()
			collectedSubdomains = append(collectedSubdomains, subResult.FullDomain)
			collectedResults = append(collectedResults, result)
			ready := len(collectedSubdomains) >= subdomainProbeBatchSize
			collectMu.Unlock()
			if ready {
				flushCollected()
			}
		} else {
			// 未启用 HTTP 探测时直接发送结果
			select {
			case <-m.ctx.Done():
				return
			case m.resultChan <- result:
			}
		}
	})

	if err != nil {
		log.Printf("[%s] Scan error for %s: %v", m.name, domain, err)
	}

	// 处理最后不足一批的子域
	if m.enableHTTPProbe && m.httpxScanner != nil {
		flushCollected()
	}

	log.Printf("[%s] Subdomain scan completed for %s", m.name, domain)
}

// subdomainProbeBatchSize 是单次 HTTP 探测的子域数量。
// 太大等得久，太小会频繁启动 httpx；20 条约等于几秒的枚举量。
const subdomainProbeBatchSize = 20

// enrichAndSend 对一小批子域做 HTTP 探测，然后逐条发送增强后的结果。
func (m *SubdomainScanModule) enrichAndSend(subdomains []string, results []SubdomainResult) {
	if len(results) == 0 {
		return
	}

	ctx2, cancel2 := context.WithTimeout(m.ctx, 5*time.Minute)
	httpxResults := m.httpxScanner.EnrichSubdomains(ctx2, subdomains)
	cancel2()

	httpxMap := make(map[string]*webscan.HttpxResult, len(httpxResults))
	for _, hr := range httpxResults {
		httpxMap[hr.Host] = hr
	}

	for _, result := range results {
		if hr, ok := httpxMap[result.Host]; ok {
			result.IPs = hr.IPs
			result.Title = hr.Title
			result.StatusCode = hr.StatusCode
			result.WebServer = hr.WebServer
			result.Technologies = hr.Technologies
			result.CDN = hr.CDN
			result.CDNName = hr.CDNName
			result.URL = hr.URL
			// Source 保留发现来源；HTTP 探测是富化不是发现，
			// 探测过与否看 StatusCode/URL 即可。
		}

		select {
		case <-m.ctx.Done():
			return
		case m.resultChan <- result:
		}
	}
}

// resolveIPs 解析域名的 IP 地址
func (m *SubdomainScanModule) resolveIPs(domain string) []string {
	resolvers := m.dnsResolvers
	if len(resolvers) == 0 {
		resolvers = []string{"223.5.5.5:53", "114.114.114.114:53"}
	}

	// 依次尝试所有 resolver。只固定用第一个时，一旦那台 DNS 不可达
	// （被墙、限流、超时），解析结果为空，端口扫描拿不到 IP，下游全断。
	for _, dnsServer := range resolvers {
		server := dnsServer
		resolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 3 * time.Second}
				return d.DialContext(ctx, "udp", server)
			},
		}

		ctx, cancel := context.WithTimeout(m.ctx, 5*time.Second)
		addrs, err := resolver.LookupIPAddr(ctx, domain)
		cancel()
		if err != nil || len(addrs) == 0 {
			continue
		}

		var ips []string
		for _, addr := range addrs {
			ips = append(ips, addr.IP.String())
		}
		if len(ips) > 0 {
			return ips
		}
	}

	return nil
}

// DomainVerifyModule 子域名安全检测模块
// 执行子域名接管检测、DNS解析等
type DomainVerifyModule struct {
	BaseModule
	domainScanner   *subdomain.DomainScanner
	takeoverScanner *subdomain.TakeoverScanner
	resultChan      chan interface{}
	concurrency     int
	targetDelay     time.Duration
}

// SetTargetDelay 设置单目标之间的间隔，用于控制请求节奏、避免被封 IP。
func (m *DomainVerifyModule) SetTargetDelay(d time.Duration) { m.targetDelay = d }

// NewDomainVerifyModule 创建域名验证模块
func NewDomainVerifyModule(ctx context.Context, nextModule ModuleRunner, concurrency int) *DomainVerifyModule {
	if concurrency <= 0 {
		concurrency = 10
	}

	m := &DomainVerifyModule{
		BaseModule: BaseModule{
			name:       "DomainVerify",
			ctx:        ctx,
			nextModule: nextModule,
			dupChecker: NewDuplicateChecker(),
		},
		domainScanner:   subdomain.NewDomainScanner(10),
		takeoverScanner: subdomain.NewTakeoverScanner(10),
		resultChan:      make(chan interface{}, 500),
		concurrency:     concurrency,
	}
	return m
}

// ModuleRun 运行模块
func (m *DomainVerifyModule) ModuleRun() error {
	var allWg sync.WaitGroup
	var resultWg sync.WaitGroup
	var nextModuleRun sync.WaitGroup
	verifySem := make(chan struct{}, 10)

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

			// 处理 SubdomainResult
			subResult, ok := data.(SubdomainResult)
			if !ok {
				log.Printf("[%s] Unexpected data type: %T, value: %+v", m.name, data, data)
				continue
			}

			allWg.Add(1)
			go func(sr SubdomainResult) {
				// 信号量限制同时校验的子域数：每校验各挂 DNS + 接管检测，
				// 无界 goroutine 下 targetDelay 的限速完全失效。
				verifySem <- struct{}{}
				defer func() { <-verifySem; allWg.Done() }()
				if m.targetDelay > 0 {
					select {
					case <-m.ctx.Done():
						return
					case <-time.After(m.targetDelay):
					}
				}
				m.checkSubdomain(sr)
			}(subResult)
		}
	}
}

// checkSubdomain 检查子域名安全
func (m *DomainVerifyModule) checkSubdomain(sr SubdomainResult) {
	// 【重要】先传递原始的 SubdomainResult，确保它被收集到
	select {
	case <-m.ctx.Done():
		return
	case m.resultChan <- sr:
	}

	// 获取子域名（使用 Host 字段）
	subdomain := sr.Host
	if subdomain == "" {
		subdomain = sr.Domain // 兼容旧数据
	}

	// 解析 DNS 获取更多信息
	ctx, cancel := context.WithTimeout(m.ctx, 30*time.Second)
	defer cancel()

	// 使用 DomainScanner 检查子域名。sr.Host 已经是完整域名（如 api.example.com），
	// 直接按完整域查询；此前按（子域,根域）拼接会查出 api.example.com.example.com。
	checkResult := m.domainScanner.CheckFullDomain(ctx, subdomain)

	// 构建 DomainResolve 结果
	result := DomainResolve{
		Domain: subdomain,
		IP:     sr.IPs,
	}

	// 如果有更多的 IP 信息，使用检查结果
	if checkResult != nil {
		if len(checkResult.IPs) > 0 {
			result.IP = checkResult.IPs
		}

		// 记录存活状态和 HTTP 信息
		if checkResult.Alive {
			log.Printf("[%s] %s is alive (HTTP: %d, HTTPS: %d)",
				m.name, subdomain, checkResult.HTTPStatus, checkResult.HTTPSStatus)
		}
	}

	// 子域名接管检测：目标是被发现的子域本身，而不是根域。
	// 传根域会导致真正的子域接管（子域 CNAME 指向失效云服务）漏检，
	// 且每个子域结果都会对同一根域重复检测一次。
	takeoverResult, err := m.takeoverScanner.Scan(ctx, subdomain)
	if err != nil {
		log.Printf("[%s] Takeover scan error for %s: %v", m.name, subdomain, err)
	} else if takeoverResult != nil && takeoverResult.Vulnerable {
		log.Printf("[%s] Potential subdomain takeover detected: %s (Service: %s, CNAME: %s)",
			m.name, subdomain, takeoverResult.Service, takeoverResult.CNAME)
		// 发送接管检测结果
		takeoverRes := TakeoverResult{
			Domain:       takeoverResult.Domain,
			CNAME:        takeoverResult.CNAME,
			Service:      takeoverResult.Service,
			Vulnerable:   takeoverResult.Vulnerable,
			Fingerprints: takeoverResult.Fingerprints,
			Reason:       takeoverResult.Reason,
		}
		select {
		case <-m.ctx.Done():
			return
		case m.resultChan <- takeoverRes:
		}
	}

	select {
	case <-m.ctx.Done():
		return
	case m.resultChan <- result:
	}
}
