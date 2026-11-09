package pipeline

import (
	"context"
	"fmt"
	"log"
	neturl "net/url"
	"sync"

	"github.com/c1ayooo/4zreark/internal/useragent"
	"github.com/c1ayooo/4zreark/scanner/webscan"
)

// HttpProbeModule 是信息收集 S2 的独立探活模块。
//
// 输入：子域结果 / 端口结果 / 上一阶段落库的 URL；
// 输出：AssetHttp（存活 URL + 标题/状态码/Server/技术栈），供爬虫/目录/敏感等下游消费。
// 后端优先 httpx（统一工具目录），缺失时回退纯 Go HttpxScanner。
type HttpProbeModule struct {
	BaseModule
	resultChan  chan interface{}
	concurrency int
	seed        string
	cliScanner  *webscan.HTTPXScanner
	goScanner   *webscan.HttpxScanner
	out         chan interface{}
}

// NewHttpProbeModule 创建探活模块。
func NewHttpProbeModule(ctx context.Context, nextModule ModuleRunner, concurrency int, seed string) *HttpProbeModule {
	if concurrency <= 0 {
		concurrency = 4
	}
	return &HttpProbeModule{
		BaseModule: BaseModule{
			name:       "HttpProbe",
			ctx:        ctx,
			nextModule: nextModule,
			dupChecker: NewDuplicateChecker(),
		},
		resultChan:  make(chan interface{}, 500),
		concurrency: concurrency,
		seed:        seed,
		cliScanner:  webscan.NewHTTPXScanner(),
		goScanner:   webscan.NewHttpxScanner(concurrency),
		out:         nextModule.GetInput(),
	}
}

// ModuleRun 运行模块：读目标 → 探活 → 输出 AssetHttp。
func (m *HttpProbeModule) ModuleRun() error {
	m.ReportModuleStart(0)
	defer m.ReportModuleComplete()

	var nextWg sync.WaitGroup
	if m.nextModule != nil {
		nextWg.Add(1)
		go func() {
			defer nextWg.Done()
			if err := m.nextModule.ModuleRun(); err != nil {
				log.Printf("[%s] Next module error: %v", m.name, err)
			}
		}()
	}

	sem := make(chan struct{}, m.concurrency)
	var wg sync.WaitGroup
	var fwdWg sync.WaitGroup
	fwdWg.Add(1)
	go func() {
		defer fwdWg.Done()
		for result := range m.resultChan {
			if m.nextModule == nil {
				continue
			}
			select {
			case <-m.ctx.Done():
				return
			case m.nextModule.GetInput() <- result:
			}
		}
	}()

	for {
		select {
		case <-m.ctx.Done():
			wg.Wait()
			close(m.resultChan)
			fwdWg.Wait()
			if m.nextModule != nil {
				m.nextModule.CloseInput()
			}
			nextWg.Wait()
			return nil
		case data, ok := <-m.input:
			if !ok {
				wg.Wait()
				close(m.resultChan)
				fwdWg.Wait()
				if m.nextModule != nil {
					m.nextModule.CloseInput()
				}
				nextWg.Wait()
				return nil
			}
			target := probeTarget(data)
			if target == "" {
				continue
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(t string) {
				defer func() { <-sem; wg.Done() }()
				m.probe(t)
			}(target)
		}
	}
}

func (m *HttpProbeModule) probe(target string) {
	ctx, cancel := context.WithCancel(m.ctx)
	defer cancel()

	host := probeHost(target)
	var asset *AssetHttp

	if m.cliScanner != nil && m.cliScanner.IsAvailable() {
		// 同站一致：httpx 进程按目标 host 派生 UA；单目标执行避免批量跨站复用。
		m.cliScanner.UserAgent = useragent.ForSite(m.seed, host).UserAgent
		results, err := m.cliScanner.Probe(ctx, []string{target})
		if err != nil && len(results) == 0 {
			m.Logf("warn", "%s httpx 探活失败：%v", target, err)
			return
		}
		if len(results) > 0 {
			r := results[0]
			if r.Failed || r.StatusCode == 0 {
				return
			}
			asset = &AssetHttp{
				Host:         firstNonEmpty(r.Host, host),
				IP:           r.IP,
				Port:         r.Port,
				URL:          firstNonEmpty(r.URL, target),
				Title:        r.Title,
				StatusCode:   r.StatusCode,
				Server:       r.WebServer,
				Technologies: r.Tech,
			}
		}
	} else {
		r := m.goScanner.Probe(ctx, target)
		if r == nil || r.StatusCode == 0 {
			return
		}
		asset = &AssetHttp{
			Host:         firstNonEmpty(r.Host, host),
			IP:           r.IP,
			Port:         r.Port,
			URL:          firstNonEmpty(r.URL, target),
			Title:        r.Title,
			StatusCode:   r.StatusCode,
			Server:       r.WebServer,
			Technologies: r.Technologies,
			ContentType:  r.ContentType,
		}
	}
	if asset == nil || asset.URL == "" {
		return
	}
	if m.dupChecker.IsURLDuplicate(asset.URL) {
		return
	}
	select {
	case <-m.ctx.Done():
	case m.resultChan <- *asset:
	}
}

// probeTarget 从各类上游结果中提取可探活的目标。
func probeTarget(data interface{}) string {
	switch v := data.(type) {
	case AssetHttp:
		if v.URL != "" {
			return v.URL
		}
		if v.Host != "" {
			return hostPortURL(v.Host, v.Port, false)
		}
	case SubdomainResult:
		return hostPortURL(v.Host, "", false)
	case DomainResolve:
		return hostPortURL(v.Domain, "", false)
	case DomainSkip:
		return hostPortURL(v.Domain, "", false)
	case PortAlive:
		return hostPortURL(firstNonEmpty(v.Host, v.IP), v.Port, true)
	case string:
		return v
	}
	return ""
}

func probeHost(target string) string {
	if u, err := neturl.Parse(target); err == nil && u.Host != "" {
		return u.Host
	}
	return target
}

func hostPortURL(host, port string, knownPort bool) string {
	if host == "" {
		return ""
	}
	if u, err := neturl.Parse(host); err == nil && u.Scheme != "" {
		return host
	}
	_ = knownPort
	if port != "" {
		switch port {
		case "80":
			return "http://" + host
		case "443":
			return "https://" + host
		default:
			return fmt.Sprintf("http://%s:%s", host, port)
		}
	}
	return "http://" + host
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
