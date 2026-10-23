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
	}
	return m
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

			// 子域扫描结果：原样下沉（结果收集器要子域记录），同时转成端口扫描输入。
			// HTTP 探测阶段已经判过 CDN，这里直接用，不再重复探测。
			if sr, ok := data.(SubdomainResult); ok {
				m.resultChan <- sr

				domainSkip := DomainSkip{
					Domain: sr.Host,
					IP:     sr.IPs,
					Skip:   sr.CDN,
					IsCDN:  sr.CDN,
					CDN:    sr.CDNName,
				}
				if domainSkip.Skip {
					log.Printf("[%s] CDN target, skip port scan: %s (%s)", m.name, sr.Host, sr.CDNName)
				}
				select {
				case <-m.ctx.Done():
					return nil
				case m.resultChan <- domainSkip:
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
					select {
					case <-m.ctx.Done():
						return nil
					case m.resultChan <- v:
					}
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
				case m.resultChan <- domainSkip:
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

	select {
	case <-m.ctx.Done():
	case m.resultChan <- domainSkip:
	}
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
