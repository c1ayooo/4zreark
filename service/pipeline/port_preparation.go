package pipeline

import (
	"context"
	"log"
	"net"
	neturl "net/url"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/scanner/subdomain"
)

// PortScanPreparationModule 端口扫描预处理模块
// 负责在端口扫描前进行CDN检测，决定是否跳过某些目标
type PortScanPreparationModule struct {
	BaseModule
	cdnDetector *subdomain.CDNDetector
	resultChan  chan interface{}
	seenMu      sync.Mutex
	// seen 记录已放行过 DomainSkip 的目标：同一域名会以多种形态到达
	// （DomainVerify 对每个子域先发 SubdomainResult 再发 DomainResolve），
	// 端口扫描一次即终态，重复放行等于对外双倍扫描流量。
	seen map[string]bool
}

// NewPortScanPreparationModule 创建端口扫描预处理模块
func NewPortScanPreparationModule(ctx context.Context, nextModule ModuleRunner) *PortScanPreparationModule {
	m := &PortScanPreparationModule{
		BaseModule: BaseModule{
			name:       "PortScanPreparation",
			ctx:        ctx,
			nextModule: nextModule,
		},
		cdnDetector: subdomain.NewCDNDetector(),
		resultChan:  make(chan interface{}, 1000),
		seen:        map[string]bool{},
	}
	return m
}

// emitSkipOnce 每个目标只放行第一份 DomainSkip，后续形态一律丢弃。
func (m *PortScanPreparationModule) emitSkipOnce(ds DomainSkip) {
	m.seenMu.Lock()
	if m.seen[ds.Domain] {
		m.seenMu.Unlock()
		return
	}
	m.seen[ds.Domain] = true
	m.seenMu.Unlock()

	if ds.Skip {
		log.Printf("[%s] Skip port scan for %s (%s)", m.name, ds.Domain, ds.CDN)
	}
	select {
	case <-m.ctx.Done():
	case m.resultChan <- ds:
	}
}

// ModuleRun 运行模块
func (m *PortScanPreparationModule) ModuleRun() error {
	var allWg sync.WaitGroup
	var resultWg sync.WaitGroup
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
		// 关闭下一个模块的输入
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
				// 输入通道关闭
				allWg.Wait()
				close(m.resultChan)
				resultWg.Wait()
				log.Printf("[%s] Input closed, waiting for next module", m.name)
				nextModuleRun.Wait()
				return nil
			}

			// 子域记录只原样下沉（结果收集器要子域明细），不再就地转端口
			// 扫描输入：DomainVerify 对同一子域随后必发 DomainResolve，那是
			// 带新鲜 DNS/CDN 结论的规范端口触发形态。此前两路各转一份
			// DomainSkip，同一域名被扫两次，且两路 CDN 结论可能相反
			//（httpx 判「Unknown CDN」时该域名甚至整段漏扫）。
			if sr, ok := data.(SubdomainResult); ok {
				select {
				case <-m.ctx.Done():
					return nil
				case m.resultChan <- sr:
				}
				continue
			}

			// 入口目标：本模块作为入口时（无子域阶段）进来的是裸 string 或
			// 缺 IP 的 DomainSkip——此前原样透传，CDN 检测形同虚设、
			// 端口结果也没有 IP。这里补一次解析 + CDN 判定。
			switch v := data.(type) {
			case string:
				allWg.Add(1)
				go func(target string) {
					defer allWg.Done()
					m.emitResolvedSkip(target, nil)
				}(v)
				continue
			case DomainSkip:
				if len(v.IP) > 0 || v.Skip || v.CIDR || v.Domain == "" {
					// 上游已带 IP / 已判定跳过 / CIDR 交给端口模块自理
					m.emitSkipOnce(v)
					continue
				}
				allWg.Add(1)
				go func(ds DomainSkip) {
					defer allWg.Done()
					m.emitResolvedSkip(ds.Domain, nil)
				}(v)
				continue
			}

			// 处理 DomainResolve 类型的数据
			domainResolve, ok := data.(DomainResolve)
			if !ok {
				// 非预期类型，直接传递给下一个模块
				log.Printf("[%s] Unexpected data type: %T, passing through, value: %+v", m.name, data, data)
				m.resultChan <- data
				continue
			}

			allWg.Add(1)
			go func(dr DomainResolve) {
				defer allWg.Done()

				domainSkip := DomainSkip{Domain: dr.Domain, IP: dr.IP}
				cdnResult := m.cdnDetector.DetectCDN(m.ctx, dr.Domain)
				if cdnResult != nil && cdnResult.IsCDN {
					domainSkip.IsCDN = true
					domainSkip.CDN = cdnResult.CDNProvider
					domainSkip.Skip = true
					log.Printf("[%s] Detected CDN for %s: %s", m.name, dr.Domain, cdnResult.CDNProvider)
				}

				select {
				case <-m.ctx.Done():
					return
				default:
					m.emitSkipOnce(domainSkip)
				}
			}(domainResolve)
		}
	}
}

// emitResolvedSkip 解析目标并做 CDN 判定，产出带 IP 的 DomainSkip。
// Domain 保留原文（gogo 兼容 host:port / URL 形态）；解析用剥掉
// scheme/端口/路径后的 host。
func (m *PortScanPreparationModule) emitResolvedSkip(target string, ips []string) {
	host := target
	if u, err := neturl.Parse(target); err == nil && u.Host != "" {
		host = u.Hostname()
	} else if h, _, err := net.SplitHostPort(target); err == nil {
		host = h
	}
	if ips == nil {
		ips = resolveHostIPs(m.ctx, host)
	}

	domainSkip := DomainSkip{Domain: target, IP: ips}
	if host != "" {
		if cdnResult := m.cdnDetector.DetectCDN(m.ctx, host); cdnResult != nil && cdnResult.IsCDN {
			domainSkip.IsCDN = true
			domainSkip.CDN = cdnResult.CDNProvider
			domainSkip.Skip = true
			log.Printf("[%s] Detected CDN for %s: %s", m.name, target, cdnResult.CDNProvider)
		}
	}

	m.emitSkipOnce(domainSkip)
}

// resolveHostIPs 解析 host；失败返回 nil，端口扫描照常进行（与旧行为一致）。
func resolveHostIPs(ctx context.Context, host string) []string {
	if host == "" {
		return nil
	}
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupHost(rctx, host)
	if err != nil || len(ips) == 0 {
		return nil
	}
	return ips
}
