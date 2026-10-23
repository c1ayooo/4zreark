package pipeline

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/scanner/scope"
)

// PipelineConfig 流水线配置
type PipelineConfig struct {
	// 子域名扫描
	SubdomainScan          bool `json:"subdomain_scan"`
	SubdomainMaxEnumTime   int  `json:"subdomain_max_enum_time"` // 分钟
	SubdomainResolveIP     bool `json:"subdomain_resolve_ip"`
	SubdomainCheckTakeover bool `json:"subdomain_check_takeover"`
	SubdomainHTTPProbe     bool `json:"subdomain_http_probe"` // 是否对子域名进行 HTTP 探测获取标题、状态码等
	// SubdomainWordlist 任务级子域字典；为空时用内置词表。
	SubdomainWordlist []string `json:"subdomain_wordlist,omitempty"`

	// 子域名枚举的第三方测绘引擎（fofa/hunter/quake/zoomeye/shodan/securitytrails）。
	// SubdomainEnableAPI 仅在存在已配置引擎时置 true；SubdomainEngineKeys 是任务级
	// key，缺失的引擎由 activeScanner 的 KeyResolver 回落到 sources 表/全局配置。
	SubdomainEnableAPI  bool              `json:"subdomain_enable_api,omitempty"`
	SubdomainAPISources []string          `json:"subdomain_api_sources,omitempty"`
	SubdomainEngineKeys map[string]string `json:"subdomain_engine_keys,omitempty"`
	// SubdomainEngineQueryMax 单任务内每引擎查询上限（0=默认）；
	// master 按当日引擎余额收紧后随任务下发。
	SubdomainEngineQueryMax int `json:"subdomain_engine_query_max,omitempty"`

	// 端口扫描
	PortScan     bool   `json:"port_scan"`
	PortScanMode string `json:"port_scan_mode"` // quick, full, top1000, custom
	PortRange    string `json:"port_range"`     // 自定义端口范围
	SkipCDN      bool   `json:"skip_cdn"`       // 是否跳过 CDN

	// 指纹识别
	Fingerprint bool `json:"fingerprint"`

	// 漏洞扫描
	VulnScan bool `json:"vuln_scan"`

	// 爬虫
	WebCrawler bool `json:"web_crawler"`
	// 爬取深度与单目标结果上限；0 = 用模块默认（深度 3、不限页）。
	MaxDepth int `json:"max_depth,omitempty"`
	MaxPages int `json:"max_pages,omitempty"`

	// 目录扫描
	DirScan bool `json:"dir_scan"`
	// DirWordlist 目录字典文件路径（spray -d）；为空时用 spray 默认字典。
	DirWordlist []string `json:"dir_wordlist,omitempty"`

	// 敏感信息检测
	SensitiveScan bool `json:"sensitive_scan"`

	// WIH 接口候选探测：从页面/JS 词法提取接口候选，同源受控探测后落档
	ApiProbe bool `json:"api_probe"`

	// 节奏控制：除漏洞扫描外，所有会主动发请求的模块都受这两个参数约束。
	// 默认值刻意保守，宁可慢，也不要因为高频请求把出口 IP 打进黑名单。
	RatePerSec    int `json:"rate_per_sec"`    // 每秒请求上限；0=用默认 20
	TargetDelayMs int `json:"target_delay_ms"` // 单目标之间的间隔毫秒；0=用默认 200
}

// rate 返回生效的每秒请求上限。
func (c *PipelineConfig) rate() int {
	if c != nil && c.RatePerSec > 0 {
		return c.RatePerSec
	}
	return 20
}

// Rate 是对外暴露的生效速率，用于日志与任务详情展示。
func (c *PipelineConfig) Rate() int { return c.rate() }

// targetDelay 返回生效的单目标间隔。
func (c *PipelineConfig) targetDelay() time.Duration {
	ms := 200
	if c != nil && c.TargetDelayMs > 0 {
		ms = c.TargetDelayMs
	}
	return time.Duration(ms) * time.Millisecond
}

// moduleConcurrency 按速率推导模块并发：每秒 N 个请求，并发不超过 N/divisor，最小 1。
func (c *PipelineConfig) moduleConcurrency(divisor int) int {
	if divisor <= 0 {
		divisor = 4
	}
	n := c.rate() / divisor
	if n < 1 {
		n = 1
	}
	return n
}

// DefaultPipelineConfig 默认流水线配置
func DefaultPipelineConfig() *PipelineConfig {
	return &PipelineConfig{
		SubdomainScan:          true,
		SubdomainMaxEnumTime:   10,
		SubdomainResolveIP:     true,
		SubdomainCheckTakeover: false,
		PortScan:               true,
		PortScanMode:           "quick",
		PortRange:              "1-1000",
		SkipCDN:                true,
		Fingerprint:            true,
		VulnScan:               false,
		WebCrawler:             false,
		DirScan:                false,
		SensitiveScan:          false,
		RatePerSec:             20,
		TargetDelayMs:          200,
	}
}

// StreamingPipeline 流式扫描流水线
type StreamingPipeline struct {
	ctx        context.Context
	cancel     context.CancelFunc
	config     *PipelineConfig
	task       *models.Task
	scope      *scope.Scope
	resultChan chan interface{} // 最终结果通道

	// 模块
	subdomainModule   *SubdomainScanModule
	securityModule    *DomainVerifyModule
	portPrepModule    *PortScanPreparationModule
	portScanModule    *PortScanModule
	fingerprintModule *FingerprintModule
	vulnScanModule    *VulnScanModule
	crawlerModule     *CrawlerModule
	dirScanModule     *DirScanModule
	sensitiveModule   *SensitiveModule
	wihModule         *WihProbeModule

	// 进度追踪
	progressTracker *ProgressTracker

	// 状态
	running bool
	started bool
	mu      sync.Mutex
}

// NewStreamingPipeline 创建新的扫描流水线
func NewStreamingPipeline(ctx context.Context, task *models.Task, config *PipelineConfig) *StreamingPipeline {
	if config == nil {
		config = DefaultPipelineConfig()
	}

	pipeCtx, cancel := context.WithCancel(ctx)

	return &StreamingPipeline{
		ctx:             pipeCtx,
		cancel:          cancel,
		config:          config,
		task:            task,
		scope:           scope.New(task.Targets),
		resultChan:      make(chan interface{}, 1000),
		progressTracker: nil, // 默认无进度追踪，需要通过 SetProgressCallback 设置
	}
}

// NewStreamingPipelineWithProgress 创建带进度追踪的扫描流水线
func NewStreamingPipelineWithProgress(ctx context.Context, task *models.Task, config *PipelineConfig, totalTargets int, callback ProgressCallback) *StreamingPipeline {
	p := NewStreamingPipeline(ctx, task, config)
	p.progressTracker = NewProgressTracker(totalTargets, callback)

	// 根据配置设置启用的模块权重
	enabledModules := p.getEnabledModules()
	p.progressTracker.SetModuleWeights(enabledModules)

	return p
}

// SetProgressCallback 设置进度回调
func (p *StreamingPipeline) SetProgressCallback(totalTargets int, callback ProgressCallback) {
	p.progressTracker = NewProgressTracker(totalTargets, callback)
	enabledModules := p.getEnabledModules()
	p.progressTracker.SetModuleWeights(enabledModules)
}

// getEnabledModules 获取启用的模块列表
func (p *StreamingPipeline) getEnabledModules() []string {
	var modules []string
	if p.config.SubdomainScan {
		modules = append(modules, "SubdomainScan", "DomainVerify")
	}
	if p.config.PortScan {
		if p.config.SkipCDN {
			modules = append(modules, "PortPreparation")
		}
		modules = append(modules, "PortScan")
	}
	if p.config.Fingerprint {
		modules = append(modules, "Fingerprint")
	}
	if p.config.VulnScan {
		modules = append(modules, "VulnScan")
	}
	if p.config.WebCrawler {
		modules = append(modules, "Crawler")
	}
	if p.config.DirScan {
		modules = append(modules, "DirScan")
	}
	if p.config.SensitiveScan {
		modules = append(modules, "Sensitive")
	}
	if p.config.ApiProbe {
		modules = append(modules, "WihProbe")
	}
	return modules
}

// GetProgressTracker 获取进度追踪器
func (p *StreamingPipeline) GetProgressTracker() *ProgressTracker {
	return p.progressTracker
}

// GetProgress 获取当前进度 (0-100)
func (p *StreamingPipeline) GetProgress() int {
	if p.progressTracker == nil {
		return 0
	}
	return p.progressTracker.GetOverallProgress()
}

// GetProgressReport 获取详细进度报告
func (p *StreamingPipeline) GetProgressReport() *ProgressReport {
	if p.progressTracker == nil {
		return nil
	}
	return p.progressTracker.GetReport()
}

// Start 启动流水线
func (p *StreamingPipeline) Start(targets []string) error {
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		return fmt.Errorf("pipeline already running")
	}
	if p.started {
		// resultChan 在首轮结束时已关闭，复用实例会向已关闭通道写入。
		p.mu.Unlock()
		return fmt.Errorf("pipeline 已启动过，请为新任务创建实例")
	}
	p.running = true
	p.mu.Unlock()

	log.Printf("[Pipeline] Starting with %d targets, config: %+v", len(targets), p.config)

	// 构建模块链
	if err := p.buildModuleChain(); err != nil {
		p.mu.Lock()
		p.running = false
		p.mu.Unlock()
		return fmt.Errorf("failed to build module chain: %v", err)
	}

	// 获取入口模块
	entryModule := p.getEntryModule()
	if entryModule == nil {
		p.mu.Lock()
		p.running = false
		p.mu.Unlock()
		return fmt.Errorf("no entry module available")
	}

	// 只有真正要起 goroutine 时才标记为已启动，避免配置错误导致实例被误判不可复用。
	p.mu.Lock()
	p.started = true
	p.mu.Unlock()

	// 启动流水线处理
	go func() {
		defer close(p.resultChan)
		defer func() {
			p.mu.Lock()
			p.running = false
			p.mu.Unlock()
		}()

		// 启动入口模块（模块会自动链式启动下一个模块）
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := entryModule.ModuleRun(); err != nil {
				log.Printf("[Pipeline] Entry module error: %v", err)
			}
		}()

		// 注入目标到入口模块
		for _, target := range targets {
			select {
			case <-p.ctx.Done():
				log.Printf("[Pipeline] Context cancelled, stopping target injection")
				entryModule.CloseInput()
				wg.Wait()
				return
			case entryModule.GetInput() <- target:
				log.Printf("[Pipeline] Injected target: %s", target)
			}
		}

		// 关闭入口模块输入
		entryModule.CloseInput()
		log.Printf("[Pipeline] All targets injected, waiting for completion")

		// 等待所有模块完成
		wg.Wait()
		log.Printf("[Pipeline] All modules completed")
	}()

	return nil
}

// buildModuleChain 构建模块链
// 链式结构: SubdomainScan -> SubdomainSecurity -> PortScanPreparation -> PortScan -> Fingerprint -> VulnScan -> Crawler -> DirScan -> Sensitive -> ResultCollector
func (p *StreamingPipeline) buildModuleChain() error {
	var lastModule ModuleRunner

	// 从后向前构建模块链

	// 结果收集模块（最后一个模块）
	resultCollector := NewResultCollectorModule(p.ctx, p.resultChan)
	resultCollector.SetInput(make(chan interface{}, 500))
	lastModule = resultCollector

	// 敏感信息检测模块
	if p.config.SensitiveScan {
		p.sensitiveModule = NewSensitiveModule(p.ctx, lastModule, p.config.moduleConcurrency(8))
		p.sensitiveModule.SetScope(p.scope)
		p.sensitiveModule.SetInput(make(chan interface{}, 500))
		p.sensitiveModule.SetProgressTracker(p.progressTracker)
		lastModule = p.sensitiveModule
	}

	// 目录扫描模块
	if p.config.DirScan {
		p.dirScanModule = NewDirScanModule(p.ctx, lastModule, p.config.moduleConcurrency(4), p.config.DirWordlist)
		p.dirScanModule.SetRate(p.config.rate(), p.config.moduleConcurrency(4))
		p.dirScanModule.SetScope(p.scope)
		p.dirScanModule.SetInput(make(chan interface{}, 500))
		p.dirScanModule.SetProgressTracker(p.progressTracker)
		lastModule = p.dirScanModule
	}

	// WIH 接口候选探测模块：链位置在目录扫描与爬虫之间——爬虫发现的
	// 页面/JS URL 顺路完成接口面刻画，结论随链流到收集器。
	// out 直接指向下游输入；nextModule 仅用于链式拉起下游 ModuleRun。
	if p.config.ApiProbe {
		wihCfg := DefaultWihConfig()
		p.wihModule = NewWihProbeModule(p.ctx, make(chan interface{}, 500), lastModule.GetInput(), wihCfg)
		p.wihModule.SetProgressTracker(p.progressTracker)
		p.wihModule.nextModule = lastModule
		lastModule = p.wihModule
	}

	// 爬虫模块
	if p.config.WebCrawler {
		p.crawlerModule = NewCrawlerModule(p.ctx, lastModule, p.config.moduleConcurrency(8), true) // 默认使用Katana
		// 流式模式：拿到一个可爬 URL 就开爬，结果边产出边落库
		p.crawlerModule.SetRate(p.config.rate(), p.config.moduleConcurrency(8))
		// 深度/页数上限此前从未接线，任务配置的值一直是摆设
		if p.config.MaxDepth > 0 {
			p.crawlerModule.SetCrawlDepth(p.config.MaxDepth)
		}
		if p.config.MaxPages > 0 {
			p.crawlerModule.SetMaxPages(p.config.MaxPages)
		}
		p.crawlerModule.SetScope(p.scope)
		p.crawlerModule.SetInput(make(chan interface{}, 500))
		p.crawlerModule.SetProgressTracker(p.progressTracker)
		lastModule = p.crawlerModule
	}

	// 漏洞扫描模块
	if p.config.VulnScan {
		p.vulnScanModule = NewVulnScanModule(p.ctx, lastModule, 4)
		p.vulnScanModule.SetInput(make(chan interface{}, 500))
		p.vulnScanModule.SetProgressTracker(p.progressTracker)
		lastModule = p.vulnScanModule
	}

	// 指纹识别模块
	if p.config.Fingerprint {
		p.fingerprintModule = NewFingerprintModule(p.ctx, lastModule, p.config.moduleConcurrency(4))
		p.fingerprintModule.SetTargetDelay(p.config.targetDelay())
		p.fingerprintModule.SetScope(p.scope)
		p.fingerprintModule.SetInput(make(chan interface{}, 500))
		p.fingerprintModule.SetProgressTracker(p.progressTracker)
		lastModule = p.fingerprintModule
	}

	// 端口扫描模块
	if p.config.PortScan {
		p.portScanModule = NewPortScanModule(p.ctx, lastModule, p.config.PortRange, p.config.PortScanMode)
		p.portScanModule.SetRate(p.config.rate(), p.config.moduleConcurrency(2), p.config.targetDelay())
		p.portScanModule.SetInput(make(chan interface{}, 500))
		p.portScanModule.SetProgressTracker(p.progressTracker)
		lastModule = p.portScanModule
	}

	// CDN检测/端口扫描预处理模块
	if p.config.PortScan && p.config.SkipCDN {
		p.portPrepModule = NewPortScanPreparationModule(p.ctx, lastModule)
		p.portPrepModule.SetInput(make(chan interface{}, 500))
		p.portPrepModule.SetProgressTracker(p.progressTracker)
		lastModule = p.portPrepModule
	}

	// 子域名安全检测模块
	if p.config.SubdomainScan {
		p.securityModule = NewDomainVerifyModule(p.ctx, lastModule, p.config.moduleConcurrency(2))
		p.securityModule.SetTargetDelay(p.config.targetDelay())
		p.securityModule.SetInput(make(chan interface{}, 500))
		p.securityModule.SetProgressTracker(p.progressTracker)
		lastModule = p.securityModule
	}

	// 子域名扫描模块（入口模块）
	if p.config.SubdomainScan {
		scanCfg := DefaultSubdomainScanConfig()
		scanCfg.ResolveIP = p.config.SubdomainResolveIP
		scanCfg.EnableHTTPProbe = p.config.SubdomainHTTPProbe
		scanCfg.Wordlist = p.config.SubdomainWordlist
		// 任务配置的第三方测绘引擎：此前 EnableAPI 恒为 false，引擎接线形同虚设。
		scanCfg.EnableAPI = p.config.SubdomainEnableAPI
		scanCfg.APISources = p.config.SubdomainAPISources
		scanCfg.FofaKey = p.config.SubdomainEngineKeys["fofa"]
		scanCfg.HunterKey = p.config.SubdomainEngineKeys["hunter"]
		scanCfg.QuakeKey = p.config.SubdomainEngineKeys["quake"]
		scanCfg.SecurityTrailsKey = p.config.SubdomainEngineKeys["securitytrails"]
		if p.config.SubdomainEngineQueryMax > 0 {
			scanCfg.EngineQueryMaxPerEngine = p.config.SubdomainEngineQueryMax
		}
		// 爆破并发跟随任务级速率，默认 20，避免 500 并发把权威 DNS 和出口 IP 一起打爆。
		scanCfg.BruteConcurrency = p.config.rate()
		p.subdomainModule = NewSubdomainScanModuleWithConfig(p.ctx, lastModule, scanCfg)
		p.subdomainModule.SetScope(p.scope)
		p.subdomainModule.SetInput(make(chan interface{}, 500))
		p.subdomainModule.SetProgressTracker(p.progressTracker)
		lastModule = p.subdomainModule
	}

	return nil
}

// getEntryModule 获取入口模块
func (p *StreamingPipeline) getEntryModule() ModuleRunner {
	if p.config.SubdomainScan && p.subdomainModule != nil {
		return p.subdomainModule
	}
	if p.config.PortScan && p.portPrepModule != nil {
		return p.portPrepModule
	}
	if p.config.PortScan && p.portScanModule != nil {
		return p.portScanModule
	}
	if p.config.Fingerprint && p.fingerprintModule != nil {
		return p.fingerprintModule
	}
	if p.config.WebCrawler && p.crawlerModule != nil {
		return p.crawlerModule
	}
	return nil
}

// Results 获取结果通道
func (p *StreamingPipeline) Results() <-chan interface{} {
	return p.resultChan
}

// Stop 停止流水线
func (p *StreamingPipeline) Stop() {
	p.cancel()
}

// ResultCollectorModule 结果收集模块
// 作为流水线的最后一个模块，收集所有结果
type ResultCollectorModule struct {
	BaseModule
	outputChan chan interface{}
}

// NewResultCollectorModule 创建结果收集模块
func NewResultCollectorModule(ctx context.Context, outputChan chan interface{}) *ResultCollectorModule {
	return &ResultCollectorModule{
		BaseModule: BaseModule{
			name:       "ResultCollector",
			ctx:        ctx,
			dupChecker: NewDuplicateChecker(),
		},
		outputChan: outputChan,
	}
}

// ModuleRun 运行模块
func (m *ResultCollectorModule) ModuleRun() error {
	for {
		select {
		case <-m.ctx.Done():
			return nil
		case data, ok := <-m.input:
			if !ok {
				log.Printf("[%s] Input closed, collection complete", m.name)
				return nil
			}

			// 转发到输出通道
			select {
			case <-m.ctx.Done():
				return nil
			case m.outputChan <- data:
			}
		}
	}
}
