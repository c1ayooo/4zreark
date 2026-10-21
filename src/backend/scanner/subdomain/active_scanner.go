package subdomain

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/internal/recon/brute"
	"github.com/c1ayooo/4zreark/internal/recon/spacemap"
	reconsub "github.com/c1ayooo/4zreark/internal/recon/subdomain"
)

// DNS 服务器列表
var dnsServers = []string{
	"8.8.8.8:53",         // Google
	"1.1.1.1:53",         // Cloudflare
	"223.5.5.5:53",       // 阿里DNS
	"114.114.114.114:53", // 114 DNS
	"8.8.4.4:53",         // Google Secondary
	"1.0.0.1:53",         // Cloudflare Secondary
}

// ActiveScannerConfig 主动扫描配置
type ActiveScannerConfig struct {
	BruteConcurrency  int      // 爆破并发数
	EnableBrute       bool     // 是否启用爆破
	EnableRecursive   bool     // 是否启用递归
	RecursiveDepth    int      // 递归深度
	WildcardDetection bool     // 泛解析检测
	ResolveTimeout    int      // 解析超时(秒)
	EnableAPI         bool     // 是否启用API
	APISources        []string // API源列表
	APIMaxResults     int      // API最大结果数
	VerifySubdomains  bool     // 是否验证存活
	EnableHTTPProbe   bool     // 是否进行HTTP探测
	// Wordlist 任务级字典；为空时回落到全局 config.GetSubdomains()。
	Wordlist []string
	// EngineKeys 任务级引擎 key（fofa/hunter/quake/zoomeye/shodan/securitytrails）。
	// 为空时回落到全局配置；数据源表由 service 层解析后注入。
	EngineKeys map[string]string
}

// ActiveScanner 综合子域名扫描器
type ActiveScanner struct {
	config   *ActiveScannerConfig
	results  sync.Map              // 存储去重后的结果 map[string]*SubdomainResult
	callback func(SubdomainResult) // 结果回调函数
}

// NewActiveScanner 创建新的扫描器
func NewActiveScanner(cfg *ActiveScannerConfig) *ActiveScanner {
	return &ActiveScanner{config: cfg}
}

// Run 执行扫描
func (s *ActiveScanner) Run(ctx context.Context, domain string) ([]SubdomainResult, error) {
	log.Printf("[ActiveScanner] Starting scan for domain: %s", domain)

	// 重置结果存储，确保每次扫描都是干净的
	s.results = sync.Map{}

	var wg sync.WaitGroup

	// 1. Subfinder 被动枚举（推荐，使用多个免费数据源）
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.runSubfinder(ctx, domain)
	}()

	// 2. API 枚举（可选，付费API）
	if s.config.EnableAPI {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.runAPIEnum(ctx, domain)
		}()
	}

	// 3. 字典爆破（可选）
	if s.config.EnableBrute {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.runBruteForce(ctx, domain)
		}()
	}

	wg.Wait()

	// 收集结果
	var results []SubdomainResult
	s.results.Range(func(key, value interface{}) bool {
		if result, ok := value.(*SubdomainResult); ok {
			results = append(results, *result)
		}
		return true
	})

	log.Printf("[ActiveScanner] Scan completed for %s, found %d subdomains", domain, len(results))
	return results, nil
}

// runSubfinder 被动枚举（T11：reconkit 纯 Go 实现，不再调 subfinder 子进程）。
// 证书透明 + 公开被动 DNS + 国内被动源 + 目标自身工件（robots/sitemap/CSP/SAN）。
func (s *ActiveScanner) runSubfinder(ctx context.Context, domain string) {
	opts := reconsub.Options{
		EnableCT:           config.CrtShEnabled(),
		EnablePassiveDNS:   true,
		EnableCNPassiveDNS: true,
		Timeout:            45 * time.Second,
		Limit:              500,
	}
	res, err := reconsub.Enumerate(ctx, domain, opts)
	if err != nil {
		log.Printf("[ActiveScanner] Passive enumeration error: %v", err)
	} else if res != nil {
		for _, hit := range res.Hits {
			s.addResult(hit.Name, nil, "passive:"+hit.Source)
		}
		log.Printf("[ActiveScanner] Passive enumeration found %d subdomains (per_source=%v, errors=%v)",
			len(res.Hits), res.PerSrc, res.Errors)
	}

	art := reconsub.CollectFromArtifacts(ctx, domain, nil, 500)
	if art != nil {
		for _, hit := range art.Hits {
			s.addResult(hit.Name, nil, "artifact:"+hit.Source)
		}
		log.Printf("[ActiveScanner] Artifacts found %d subdomains (per_source=%v)", len(art.Hits), art.PerSrc)
	}
}

// runAPIEnum 空间测绘枚举（T11：reconkit spacemap，5 引擎）。
// 单源未配置直接跳过；单源报错只记日志，不影响其他源。
func (s *ActiveScanner) runAPIEnum(ctx context.Context, domain string) {
	log.Printf("[ActiveScanner] Starting API enumeration for %s", domain)
	client := spacemap.NewClient()
	client.KeyResolver = s.engineKey

	for _, source := range s.config.APISources {
		provider := strings.ToLower(strings.TrimSpace(source))
		if !spacemap.ValidProvider(provider) {
			log.Printf("[ActiveScanner] Unsupported engine %q, skipped", source)
			continue
		}
		if !client.SourceConfigured(provider) {
			log.Printf("[ActiveScanner] Engine %s not configured, skipped", provider)
			continue
		}
		if ctx.Err() != nil {
			return
		}

		query := spacemap.DomainQuery(provider, domain)
		results, _, _, err := client.SearchEngineAssets(ctx, provider, query, s.config.APIMaxResults, 1)
		if err != nil {
			// 401/429/网络错误都只影响当前源
			log.Printf("[ActiveScanner] Engine %s error: %v", provider, err)
			continue
		}
		for _, r := range results {
			host := r.Domain
			if host == "" {
				host = r.Host
			}
			if host == "" {
				continue
			}
			var ips []string
			if r.IP != "" {
				ips = []string{r.IP}
			}
			s.addResult(host, ips, "spacemap:"+provider)
		}
		log.Printf("[ActiveScanner] Engine %s found %d assets", provider, len(results))
	}
}

// engineKey 解析引擎 key：任务级配置优先，其次全局配置。
func (s *ActiveScanner) engineKey(provider string) string {
	if s.config != nil {
		if v := strings.TrimSpace(s.config.EngineKeys[provider]); v != "" {
			return v
		}
	}
	if c := config.Loaded(); c != nil {
		switch provider {
		case "fofa":
			return c.ThirdParty.Fofa.Key
		case "hunter":
			return c.ThirdParty.Hunter.Key
		case "quake":
			return c.ThirdParty.Quake.Key
		case "zoomeye":
			return c.ThirdParty.ZoomEye.Key
		case "shodan":
			return c.ThirdParty.Shodan.Key
		}
	}
	return ""
}

// runBruteForce 执行字典爆破
func (s *ActiveScanner) runBruteForce(ctx context.Context, domain string) {
	log.Printf("[ActiveScanner] Starting brute force for %s (reconkit dnsres + brute)", domain)

	subdomains := s.config.Wordlist
	if len(subdomains) == 0 {
		subdomains = config.GetSubdomains()
	}
	if len(subdomains) == 0 {
		log.Printf("[ActiveScanner] No dictionary loaded, skipping brute force")
		return
	}
	log.Printf("[ActiveScanner] Loaded %d subdomains from dictionary for %s", len(subdomains), domain)

	// T11：直接走纯 Go 爆破。泛解析基线过滤由 brute 内部完成，
	// 不再调用 ksubdomain 库/子进程，也不再做第二遍 wildcard 过滤。
	hits, stats, err := brute.Brute(ctx, domain, brute.Options{
		Words:     subdomains,
		Resolvers: dnsServers,
		QPS:       300,
	})
	if err != nil {
		log.Printf("[ActiveScanner] brute error: %v", err)
		return
	}
	log.Printf("[ActiveScanner] brute: probed=%d hits=%d wildcard=%v filtered=%d",
		stats.Probed, stats.Hits, stats.Wildcard, stats.WildcardFiltered)

	var added int64
	for _, h := range hits {
		s.addResult(h.Name, h.IPs, "brute")
		added++
	}
	log.Printf("[ActiveScanner] Brute force completed, added %d subdomains", added)
}

// resolveDomain 解析域名（使用多个DNS服务器并带重试机制）
func (s *ActiveScanner) resolveDomain(domain string) ([]string, error) {
	timeout := s.config.ResolveTimeout
	if timeout <= 0 {
		timeout = 5
	}

	// 随机选择一个DNS服务器开始
	startIdx := rand.Intn(len(dnsServers))

	// 尝试所有DNS服务器
	for i := 0; i < len(dnsServers); i++ {
		serverIdx := (startIdx + i) % len(dnsServers)
		dnsServer := dnsServers[serverIdx]

		// 创建自定义resolver
		resolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: time.Duration(timeout) * time.Second,
				}
				return d.DialContext(ctx, "udp", dnsServer)
			},
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
		ips, err := resolver.LookupHost(ctx, domain)
		cancel()

		if err == nil && len(ips) > 0 {
			return ips, nil
		}
	}

	// 所有DNS服务器都失败了，返回NXDOMAIN
	return nil, fmt.Errorf("no DNS record found")
}

// detectWildcard 检测泛解析，返回泛解析的IP
func (s *ActiveScanner) detectWildcard(domain string) []string {
	// 生成多个随机子域名进行测试
	testDomains := []string{
		fmt.Sprintf("wildcard-test-%d.%s", time.Now().UnixNano(), domain),
		fmt.Sprintf("random-check-%d.%s", time.Now().UnixNano()+1, domain),
		fmt.Sprintf("notexist-%d.%s", time.Now().UnixNano()+2, domain),
	}

	ipCounts := make(map[string]int)

	for _, testDomain := range testDomains {
		if ips, err := s.resolveDomain(testDomain); err == nil {
			for _, ip := range ips {
				ipCounts[ip]++
			}
		}
	}

	// 如果多个随机域名解析到相同IP，则认为是泛解析
	var wildcardIPs []string
	for ip, count := range ipCounts {
		if count >= 2 {
			wildcardIPs = append(wildcardIPs, ip)
		}
	}

	return wildcardIPs
}

// addResult 添加结果
func (s *ActiveScanner) addResult(subdomain string, ips []string, source string) {
	// 提取域名部分
	result := &SubdomainResult{
		Subdomain:  subdomain,
		FullDomain: subdomain,
		IPs:        ips,
		Alive:      true,
	}

	// 去重存储
	if _, loaded := s.results.LoadOrStore(subdomain, result); !loaded {

		// 调用回调函数（如果设置了）
		if s.callback != nil {
			s.callback(*result)
		}
	}
}

// ScanWithCallback 使用回调函数进行扫描
func (s *ActiveScanner) ScanWithCallback(ctx context.Context, domain string, callback func(SubdomainResult)) error {
	s.callback = callback
	_, err := s.Run(ctx, domain)
	return err
}
