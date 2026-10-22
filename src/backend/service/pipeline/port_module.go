package pipeline

import (
	"context"
	"fmt"
	"log"
	"net"
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
		}
	}
	m.targetDelay = delay
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
	}
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

	if !m.gogoScanner.IsAvailable() {
		m.scanPortsFallback(ctx, ds)
		return
	}

	var scanResult *core.ScanResult
	var err error

	// 根据扫描模式选择扫描方式
	switch m.scanMode {
	case "full":
		scanResult, err = m.gogoScanner.FullScan(ctx, ds.Domain)
	case "top1000":
		scanResult, err = m.gogoScanner.Top1000Scan(ctx, ds.Domain)
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
		if len(ds.IP) > 0 {
			ip = ds.IP[0]
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

	log.Printf("[%s] Port scan completed for %s, found %d ports", m.name, ds.Domain, len(scanResult.Ports))
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
