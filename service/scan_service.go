package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/scanner/fingerprint"
	"github.com/c1ayooo/4zreark/scanner/portscan"
	"github.com/c1ayooo/4zreark/scanner/subdomain"
	"github.com/c1ayooo/4zreark/scanner/vulnscan"
	"github.com/c1ayooo/4zreark/scanner/webscan"
)

// ScanService 是同步扫描能力的服务层封装。
// HTTP 的 /api/scan/* 与 MCP 的 scan_* 工具共用同一批 scanner 实现；
// 不同点是 MCP 会额外做 project 目标归属校验（见 TargetAllowedForProject）。
type ScanService struct {
	gogo        *portscan.GoGoScanner
	domain      *subdomain.DomainScanner
	fingerprint *fingerprint.FingerprintScanner
	vuln        *vulnscan.VulnScanner
	content     *webscan.ContentScanner
	spray       *webscan.SprayScanner
	weak        *vulnscan.WeakPasswordScanner
	takeover    *subdomain.TakeoverScanner
	nuclei      *NucleiService
}

func NewScanService() *ScanService {
	return &ScanService{
		gogo:        portscan.NewGoGoScanner(),
		domain:      subdomain.NewDomainScanner(100),
		fingerprint: fingerprint.NewFingerprintScanner(50),
		vuln:        vulnscan.NewVulnScanner(20),
		content:     webscan.NewContentScanner(30),
		spray:       webscan.NewSprayScanner(),
		weak:        vulnscan.NewWeakPasswordScanner(5),
		takeover:    subdomain.NewTakeoverScanner(30),
		nuclei:      NewNucleiService(),
	}
}

func withTimeout(ctx context.Context, seconds int, fallback time.Duration) (context.Context, context.CancelFunc) {
	timeout := fallback
	if seconds > 0 {
		timeout = time.Duration(seconds) * time.Second
	}
	return context.WithTimeout(ctx, timeout)
}

// PortScan 支持 quick / custom / single 三种模式。
func (s *ScanService) PortScan(ctx context.Context, mode, target, ports string, port int, timeout int) (any, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, errors.New("target 必填")
	}
	if !s.gogo.IsAvailable() {
		return nil, errors.New("GoGo 端口扫描器不可用")
	}
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "quick", "":
		c, cancel := withTimeout(ctx, timeout, 60*time.Second)
		defer cancel()
		return s.gogo.QuickScan(c, target)
	case "custom":
		if strings.TrimSpace(ports) == "" {
			return nil, errors.New("ports 必填（如 80,443 或 1-1000）")
		}
		c, cancel := withTimeout(ctx, timeout, 120*time.Second)
		defer cancel()
		return s.gogo.ScanPorts(c, target, ports)
	case "single":
		if port < 1 || port > 65535 {
			return nil, errors.New("port 需在 1..65535")
		}
		if !s.gogo.IsAvailable() {
			return nil, errors.New("GoGo 端口扫描器不可用")
		}
		return s.gogo.ScanOne(target, strconv.Itoa(port)), nil
	default:
		return nil, errors.New("mode 只支持 quick / custom / single")
	}
}

func (s *ScanService) SubdomainScan(ctx context.Context, mode, domain string, wordlist []string, timeout int) (any, error) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return nil, errors.New("domain 必填")
	}
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "quick", "":
		c, cancel := withTimeout(ctx, timeout, 3*time.Minute)
		defer cancel()
		return s.domain.QuickSubdomainScan(c, domain), nil
	case "full":
		c, cancel := withTimeout(ctx, timeout, 10*time.Minute)
		defer cancel()
		return s.domain.FullSubdomainScan(c, domain), nil
	case "custom":
		if len(wordlist) == 0 {
			return nil, errors.New("custom 模式需要非空 wordlist")
		}
		c, cancel := withTimeout(ctx, timeout, 10*time.Minute)
		defer cancel()
		return s.domain.CustomSubdomainScan(c, domain, wordlist), nil
	default:
		return nil, errors.New("mode 只支持 quick / full / custom")
	}
}

func (s *ScanService) DomainInfo(ctx context.Context, domain string, timeout int) (any, error) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return nil, errors.New("domain 必填")
	}
	c, cancel := withTimeout(ctx, timeout, 30*time.Second)
	defer cancel()
	return s.domain.GetDomainInfo(c, domain), nil
}

func (s *ScanService) FingerprintScan(ctx context.Context, targets []string, timeout int) (any, error) {
	targets = cleanTargets(targets)
	if len(targets) == 0 {
		return nil, errors.New("targets 不能为空")
	}
	if len(targets) == 1 {
		c, cancel := withTimeout(ctx, timeout, 30*time.Second)
		defer cancel()
		return s.fingerprint.ScanFingerprint(c, targets[0]), nil
	}
	c, cancel := withTimeout(ctx, timeout, 10*time.Minute)
	defer cancel()
	return map[string]any{"total": len(targets), "results": s.fingerprint.BatchScanFingerprint(c, targets)}, nil
}

func (s *ScanService) VulnScan(ctx context.Context, target string, quick bool, severities []string, templateIDs []string, timeout int) (any, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, errors.New("target 必填")
	}

	var templates []*vulnscan.POCTemplate
	switch {
	case quick && len(severities) == 0 && len(templateIDs) == 0:
		templates = append(s.vuln.FilterTemplatesBySeverity("high"), s.vuln.FilterTemplatesBySeverity("critical")...)
	case len(severities) > 0:
		for _, sev := range severities {
			templates = append(templates, s.vuln.FilterTemplatesBySeverity(strings.TrimSpace(sev))...)
		}
	case len(templateIDs) > 0:
		ids := make(map[string]bool, len(templateIDs))
		for _, id := range templateIDs {
			ids[strings.TrimSpace(id)] = true
		}
		for _, t := range s.vuln.Templates {
			if ids[t.ID] {
				templates = append(templates, t)
			}
		}
	default:
		templates = s.vuln.Templates
	}
	if len(templates) == 0 {
		return nil, errors.New("没有匹配的 POC 模板，请检查 severity/template_ids")
	}
	c, cancel := withTimeout(ctx, timeout, 10*time.Minute)
	defer cancel()
	return s.vuln.ScanVuln(c, target, templates), nil
}

func (s *ScanService) DirScan(ctx context.Context, target string, wordlist []string, quick bool, timeout int) (any, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, errors.New("target 必填")
	}
	if s.spray == nil || !s.spray.IsAvailable() {
		return nil, errors.New("Spray 目录扫描器不可用")
	}
	if quick || len(wordlist) == 0 {
		c, cancel := withTimeout(ctx, timeout, 3*time.Minute)
		defer cancel()
		return s.spray.Scan(c, target)
	}
	c, cancel := withTimeout(ctx, timeout, 10*time.Minute)
	defer cancel()
	return s.spray.ScanWithWordlist(c, target, wordlist)
}

func (s *ScanService) SensitiveScan(ctx context.Context, targets []string, timeout int) (any, error) {
	targets = cleanTargets(targets)
	if len(targets) == 0 {
		return nil, errors.New("targets 不能为空")
	}
	if len(targets) == 1 {
		c, cancel := withTimeout(ctx, timeout, 30*time.Second)
		defer cancel()
		return s.content.ScanSensitiveInfo(c, targets[0]), nil
	}
	c, cancel := withTimeout(ctx, timeout, 10*time.Minute)
	defer cancel()
	return map[string]any{"total": len(targets), "results": s.content.BatchScanSensitive(c, targets)}, nil
}

func (s *ScanService) Crawl(ctx context.Context, target string, maxDepth, maxURLs, timeout int) (any, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, errors.New("target 必填")
	}
	if maxDepth <= 0 {
		maxDepth = 3
	}
	if maxURLs <= 0 {
		maxURLs = 100
	}
	c, cancel := withTimeout(ctx, timeout, 10*time.Minute)
	defer cancel()
	return webscan.NewWebCrawler(maxDepth, maxURLs, 10).Crawl(c, target), nil
}

func (s *ScanService) WeakPasswordScan(ctx context.Context, target string, port int, serviceType string, timeout int) (any, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, errors.New("target 必填")
	}
	if port < 1 || port > 65535 {
		return nil, errors.New("port 需在 1..65535")
	}
	c, cancel := withTimeout(ctx, timeout, 10*time.Minute)
	defer cancel()

	switch strings.ToLower(strings.TrimSpace(serviceType)) {
	case "ssh":
		return s.weak.BruteForceSSH(c, target, port), nil
	case "ftp":
		return s.weak.BruteForceFTP(c, target, port), nil
	case "mysql":
		return s.weak.BruteForceMySQL(c, target, port), nil
	case "redis":
		return s.weak.BruteForceRedis(c, target, port), nil
	default:
		return nil, errors.New("service 只支持 ssh / ftp / mysql / redis")
	}
}

func (s *ScanService) TakeoverScan(ctx context.Context, domains []string, timeout int) (any, error) {
	domains = cleanTargets(domains)
	if len(domains) == 0 {
		return nil, errors.New("domains 不能为空")
	}
	if len(domains) > 1000 {
		return nil, errors.New("一次最多 1000 个域名")
	}
	if len(domains) == 1 {
		c, cancel := withTimeout(ctx, timeout, 30*time.Second)
		defer cancel()
		res, err := s.takeover.Scan(c, domains[0])
		if err != nil {
			return nil, err
		}
		return res, nil
	}
	c, cancel := withTimeout(ctx, timeout, 5*time.Minute)
	defer cancel()
	results, err := s.takeover.ScanBatch(c, domains)
	if err != nil {
		return nil, err
	}
	vulnerable := 0
	for _, r := range results {
		if r.Vulnerable {
			vulnerable++
		}
	}
	return map[string]any{"total": len(results), "vulnerable": vulnerable, "results": results}, nil
}

func (s *ScanService) NucleiScan(ctx context.Context, targets []string, severity string, templateIDs, tags []string, timeout int) (any, error) {
	targets = cleanTargets(targets)
	if len(targets) == 0 {
		return nil, errors.New("targets 不能为空")
	}
	var severities []string
	for _, s := range strings.Split(severity, ",") {
		if s = strings.TrimSpace(s); s != "" {
			severities = append(severities, s)
		}
	}
	dir, err := os.MkdirTemp("", "zre-nuclei-*")
	if err != nil {
		return nil, fmt.Errorf("创建模板目录失败: %w", err)
	}
	defer os.RemoveAll(dir)

	count, err := s.nuclei.MaterializeTemplates(dir, severities, templateIDs, tags)
	if err != nil {
		return nil, fmt.Errorf("加载模板失败: %w", err)
	}
	if count == 0 {
		return nil, errors.New("没有可用模板：库为空、全部未验证，或筛选条件过窄")
	}
	scanner := vulnscan.NewNucleiCLIScanner(dir)
	if !scanner.IsAvailable() {
		return nil, errors.New("nuclei CLI 不可用")
	}
	c, cancel := withTimeout(ctx, timeout, 10*time.Minute)
	defer cancel()
	results, err := scanner.Scan(c, targets, &vulnscan.NucleiScanConfig{
		Concurrency: 25,
		RateLimit:   50, // 与自动链路 nucleiruntime 的 50 硬顶对齐：150rps 对小目标是 DoS 级
		Timeout:     10 * time.Minute,
	})
	if err != nil {
		return nil, fmt.Errorf("扫描失败: %w", err)
	}
	return map[string]any{
		"targets": targets, "templates": count, "matched": len(results), "results": results,
	}, nil
}

// TargetAllowedForProject 判断扫描目标是否落在项目的站点或种子范围内。
// 只用于绑定项目的 API key；全项目 key 不做此限制。
func (s *ScanService) TargetAllowedForProject(ctx context.Context, projectID int64, target string) (bool, error) {
	host := NormalizeScanTarget(target)
	if host == "" {
		return false, errors.New("无法解析目标主机")
	}
	return repo.NewAssetRepo().TargetAllowedForProject(ctx, projectID, host)
}

// NormalizeScanTarget 把 URL / host:port / 域名 / IP 归一成主机名。
func NormalizeScanTarget(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	// CIDR 不能被后面的路径/端口处理截断。
	if _, _, err := net.ParseCIDR(s); err == nil {
		return strings.ToLower(s)
	}
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil && u.Host != "" {
			s = u.Host
		}
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	s = strings.Trim(s, "[]")
	return strings.ToLower(strings.TrimSpace(s))
}

func cleanTargets(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, raw := range in {
		t := strings.TrimSpace(raw)
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	return out
}
