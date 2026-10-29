package pipeline

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	reconportscan "github.com/c1ayooo/4zreark/internal/recon/portscan"
	"github.com/c1ayooo/4zreark/scanner/core"
	"github.com/c1ayooo/4zreark/scanner/portscan"
)

// PortScanModule 端口扫描模块
// 接收预处理后的域名，执行端口扫描，输出存活端口
type PortScanModule struct {
	BaseModule
	gogoScanner *portscan.GoGoScanner
	resultChan  chan interface{}
	portRange   string
	scanMode    string
	// maxThreads 大端口集的线程封顶（0 = 不限制）。gogo 默认 1000 并发，
	// 扫描面一大就会触发目标侧封 IP；用户预期"可以慢"。
	maxThreads  int
	ratePerSec  int
	concurrency int
	targetDelay time.Duration
}

// SetRate 设置端口扫描的速率、并发与单目标间隔。
// 默认值刻意保守：高频 SYN/connect 扫描最容易触发云厂商和目标的封禁策略。
func (m *PortScanModule) SetRate(ratePerSec, concurrency int, delay time.Duration) {
	if ratePerSec > 0 {
		m.ratePerSec = ratePerSec
	}
	if concurrency > 0 {
		m.concurrency = concurrency
		// 外挂 gogo 的 -t 线程数必须一起收紧：它不读上面的 RatePerSec，
		// 默认 1000 并发，不改的话纯 Go fallback 限了速也白限。
		// gogo 是进程级单例，线程数走锁更新，避免与并发任务的扫描竞争。
		if m.gogoScanner != nil {
			m.gogoScanner.SetThreads(concurrency)
			m.applyThreadCap()
		}
	}
	m.targetDelay = delay
}

// applyThreadCap 把 gogo 线程压回当前模式的封顶值（SetRate 抬高后在这里压回；
// gogo 是多任务共享单例，别的任务也可能抬高过线程）。
func (m *PortScanModule) applyThreadCap() {
	if m.maxThreads > 0 && m.gogoScanner != nil {
		m.gogoScanner.ClampThreads(m.maxThreads)
	}
}

// portThreadCap 各扫描模式的线程封顶：扫描面越大越容易被封 IP（可以慢）。
func portThreadCap(scanMode string) int {
	switch scanMode {
	case "top2000":
		return 200
	case "top5000":
		return 100
	case "full":
		return 80
	}
	return 0
}

// NewPortScanModule 创建端口扫描模块
func NewPortScanModule(ctx context.Context, nextModule ModuleRunner, portRange, scanMode string) *PortScanModule {
	if scanMode == "" {
		scanMode = "quick"
	}
	if portRange == "" {
		portRange = "1-1000"
	}

	m := &PortScanModule{
		BaseModule: BaseModule{
			name:       "PortScan",
			ctx:        ctx,
			nextModule: nextModule,
			dupChecker: NewDuplicateChecker(),
		},
		gogoScanner: portscan.NewGoGoScanner(),
		resultChan:  make(chan interface{}, 1000),
		portRange:   portRange,
		scanMode:    scanMode,
		maxThreads:  portThreadCap(scanMode),
	}
	m.applyThreadCap()
	return m
}

// ModuleRun 运行模块
func (m *PortScanModule) ModuleRun() error {
	var allWg sync.WaitGroup
	var resultWg sync.WaitGroup
	var nextModuleRun sync.WaitGroup
	// 同时在扫的主机数：聚合速率 = 并发数 × 单机令牌桶，必须收住。
	hostSem := make(chan struct{}, 4)

	// GoGo 不可用时不再整体透传：改用纯 Go TCP connect 扫描（见 scanPorts）。
	if !m.gogoScanner.IsAvailable() {
		log.Printf("[%s] GoGo not available, fallback to pure-Go TCP connect scan", m.name)
	}

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

	// 结果处理协程 - 去重并发送到下一个模块
	resultWg.Add(1)
	go func() {
		defer resultWg.Done()
		for result := range m.resultChan {
			if portAlive, ok := result.(PortAlive); ok {
				// 去重检查
				if portAlive.Port != "" && m.dupChecker.IsPortDuplicate(portAlive.Host, portAlive.Port) {
					continue
				}
				// 报告输出
				m.ReportOutput(1)
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
		// 关闭下一个模块的输入
		if m.nextModule != nil {
			m.nextModule.CloseInput()
		}
	}()

	// 处理输入
	var processedCount int
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

			// 处理不同类型的输入
			var domainSkip DomainSkip
			switch v := data.(type) {
			case DomainSkip:
				domainSkip = v
			case string:
				// 支持直接传入域名字符串
				domainSkip = DomainSkip{
					Domain: v,
					Skip:   false,
				}
			case DomainResolve:
				// 支持 DomainResolve 类型
				domainSkip = DomainSkip{
					Domain: v.Domain,
					IP:     v.IP,
					Skip:   false,
				}
			default:
				// 非预期类型，直接传递
				m.resultChan <- data
				continue
			}

			// 无论是否扫描，标记该域名已处理
			// 不再发送空端口记录，避免混淆

			// 如果需要跳过（如CDN），不进行端口扫描
			if domainSkip.Skip {
				log.Printf("[%s] Skipping %s (CDN: %s)", m.name, domainSkip.Domain, domainSkip.CDN)
				continue
			}

			allWg.Add(1)
			go func(ds DomainSkip) {
				// 信号量限制同时扫描的主机数：无界 goroutine 下每主机各自持
				// 令牌桶，聚合速率 = N × 单机速率，会乘法放大打挂同网段目标。
				hostSem <- struct{}{}
				defer func() { <-hostSem; allWg.Done() }()
				if m.targetDelay > 0 {
					select {
					case <-m.ctx.Done():
						return
					case <-time.After(m.targetDelay):
					}
				}
				m.scanPorts(ds)
			}(domainSkip)
		}
	}
}

// scanPorts 执行端口扫描
func (m *PortScanModule) scanPorts(ds DomainSkip) {
	log.Printf("[%s] Starting port scan for %s (mode: %s)", m.name, ds.Domain, m.scanMode)

	ctx, cancel := context.WithTimeout(m.ctx, 10*time.Minute)
	defer cancel()

	// gogo 不做 DNS：无子域阶段的流水线入口是裸域名，这里补一次解析，
	// 否则端口结果的 IP 恒为空，端口页签按 ip 聚合会把多主机并成一行。
	ips := ds.IP
	if len(ips) == 0 && ds.Domain != "" && !strings.Contains(ds.Domain, "://") {
		ips = resolveHostIPs(ctx, ds.Domain)
	}

	if !m.gogoScanner.IsAvailable() {
		m.scanPortsFallback(ctx, ds)
		return
	}

	var scanResult *core.ScanResult
	var err error
	m.applyThreadCap()

	// 根据扫描模式选择扫描方式
	switch m.scanMode {
	case "full":
		scanResult, err = m.gogoScanner.FullScan(ctx, ds.Domain)
	case "top1000":
		scanResult, err = m.gogoScanner.Top1000Scan(ctx, ds.Domain)
	case "top2000", "top5000":
		// nmap 频率序真 Top-N 列表（config/dicts/ports/，go:embed 内置）
		ports := topNPorts(m.scanMode)
		if ports == "" {
			log.Printf("[%s] 端口表 %s 缺失，回退 top1000", m.name, m.scanMode)
			scanResult, err = m.gogoScanner.Top1000Scan(ctx, ds.Domain)
		} else {
			scanResult, err = m.gogoScanner.ScanPorts(ctx, ds.Domain, ports)
		}
	case "custom":
		scanResult, err = m.gogoScanner.ScanPorts(ctx, ds.Domain, m.portRange)
	default: // quick
		scanResult, err = m.gogoScanner.QuickScan(ctx, ds.Domain)
	}

	if err != nil {
		log.Printf("[%s] GoGo error for %s: %v", m.name, ds.Domain, err)
		return
	}

	if scanResult == nil {
		return
	}

	// 发送扫描结果
	for _, port := range scanResult.Ports {
		if port.State != "open" {
			continue
		}

		ip := ""
		if len(ips) > 0 {
			ip = ips[0]
		}

		result := PortAlive{
			Host:    ds.Domain,
			IP:      ip,
			Port:    intToString(port.Port),
			Service: port.Service,
		}

		log.Printf("[%s] Found open port: %s:%d (%s)", m.name, ds.Domain, port.Port, port.Service)

		select {
		case <-m.ctx.Done():
			return
		case m.resultChan <- result:
		}
	}

	// gogo 内置 poc 命中：走统一漏洞结果通道（Source=gogo），severity 按
	// fingers 口径映射。gogo 的 poc 集是粗筛，进漏洞清单后仍走人工复核。
	for _, v := range scanResult.Vulns {
		target := v.Target
		if target == "" {
			target = net.JoinHostPort(ds.Domain, "0")
		}
		select {
		case <-m.ctx.Done():
			return
		case m.resultChan <- VulnResult{
			Target:    target,
			Name:      v.Name,
			Severity:  gogoSeverity(v.SeverityLevel),
			Source:    "gogo",
			MatchedAt: target,
			Timestamp: time.Now(),
		}:
		}
	}

	log.Printf("[%s] Port scan completed for %s, found %d ports", m.name, ds.Domain, len(scanResult.Ports))
}

// gogoSeverity 把 gogo/fingers 的数字严重度映射为平台口径。
func gogoSeverity(level int) string {
	switch level {
	case 1:
		return "info"
	case 2:
		return "medium"
	case 3:
		return "high"
	case 4:
		return "critical"
	default:
		return "info"
	}
}

// intToString 整数转字符串
func intToString(n int) string {
	return fmt.Sprintf("%d", n)
}

// scanPortsFallback 在 gogo 不可用时用纯 Go TCP connect 扫描。
// 端口集按 scanMode 选：quick/top1000 → Top100，custom → 解析 portRange，full → 1-65535。
func (m *PortScanModule) scanPortsFallback(ctx context.Context, ds DomainSkip) {
	ips := ds.IP
	if len(ips) == 0 && ds.Domain != "" {
		resolved, err := net.LookupHost(ds.Domain)
		if err != nil || len(resolved) == 0 {
			log.Printf("[%s] Fallback resolve failed for %s: %v", m.name, ds.Domain, err)
			return
		}
		ips = resolved
	}
	if len(ips) == 0 {
		return
	}

	ports := m.fallbackPorts()
	if len(ports) == 0 {
		return
	}

	concurrency := m.concurrency
	if concurrency <= 0 {
		concurrency = 8
	}
	ratePerSec := m.ratePerSec
	if ratePerSec <= 0 {
		ratePerSec = 20
	}
	results := reconportscan.Scan(ctx, ips, reconportscan.Options{
		Ports:       ports,
		Concurrency: concurrency,
		Timeout:     2 * time.Second,
		RatePerSec:  ratePerSec,
	})
	log.Printf("[%s] Fallback scan completed for %s: %d open ports", m.name, ds.Domain, len(results))

	for _, r := range results {
		service := r.Service
		if service == "" {
			service = reconportscan.GuessService(r.Port)
		}
		log.Printf("[%s] Found open port: %s:%d (%s)", m.name, ds.Domain, r.Port, service)
		select {
		case <-m.ctx.Done():
			return
		case m.resultChan <- PortAlive{
			Host:    ds.Domain,
			IP:      r.IP,
			Port:    intToString(r.Port),
			Service: service,
		}:
		}
	}
}

func (m *PortScanModule) fallbackPorts() []int {
	switch m.scanMode {
	case "full":
		ports := make([]int, 0, 65535)
		for p := 1; p <= 65535; p++ {
			ports = append(ports, p)
		}
		return ports
	case "custom":
		return reconportscan.ResolvePorts("", m.portRange)
	default: // quick / top1000
		return reconportscan.Top100
	}
}
