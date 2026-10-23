package api

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/scanner/core"
	"github.com/c1ayooo/4zreark/scanner/fingerprint"
	"github.com/c1ayooo/4zreark/scanner/portscan"
	"github.com/c1ayooo/4zreark/scanner/subdomain"
	"github.com/c1ayooo/4zreark/scanner/vulnscan"
	"github.com/c1ayooo/4zreark/scanner/webscan"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

type ScanHandler struct {
	gogoScanner        *portscan.GoGoScanner
	csegmentScanner    *portscan.CSegmentScanner
	domainScanner      *subdomain.DomainScanner
	cdnDetector        *subdomain.CDNDetector
	fingerprintScanner *fingerprint.FingerprintScanner
	vulnScanner        *vulnscan.VulnScanner
	contentScanner     *webscan.ContentScanner
	sprayScanner       *webscan.SprayScanner
	weakPwdScanner     *vulnscan.WeakPasswordScanner
	webCrawler         *webscan.WebCrawler
	takeoverScanner    *subdomain.TakeoverScanner
}

func NewScanHandler() *ScanHandler {
	return &ScanHandler{
		gogoScanner:        portscan.NewGoGoScanner(),
		csegmentScanner:    portscan.NewCSegmentScanner(100),
		domainScanner:      subdomain.NewDomainScanner(100),
		cdnDetector:        subdomain.NewCDNDetector(),
		fingerprintScanner: fingerprint.NewFingerprintScanner(50),
		vulnScanner:        vulnscan.NewVulnScanner(20),
		contentScanner:     webscan.NewContentScanner(30),
		sprayScanner:       webscan.NewSprayScanner(),
		weakPwdScanner:     vulnscan.NewWeakPasswordScanner(5),
		webCrawler:         webscan.NewWebCrawler(3, 100, 10),
		takeoverScanner:    subdomain.NewTakeoverScanner(30),
	}
}

// maxScanTimeoutSeconds 是实时扫描入口允许的单次超时上限（24h）。
// 入口参数不可信：10^9 秒的 timeout 会把 goroutine 占到进程退出。
const maxScanTimeoutSeconds = 24 * 60 * 60

// clampScanTimeout 收敛调用方传来的超时秒数。
func clampScanTimeout(seconds int) time.Duration {
	if seconds > maxScanTimeoutSeconds {
		return time.Duration(maxScanTimeoutSeconds) * time.Second
	}
	return time.Duration(seconds) * time.Second
}

// maxDirWordlist 是目录扫描自定义字典的条数上限。
const maxDirWordlist = 20000

// maxBatchTargets 是批量扫描接口的单次目标数上限（与接管批量对齐）。
const maxBatchTargets = 1000

// QuickPortScan performs a quick port scan on common ports
// POST /api/scan/port/quick
func (h *ScanHandler) QuickPortScan(c *gin.Context) {
	var req struct {
		Target  string `json:"target" binding:"required"`
		Timeout int    `json:"timeout"` // seconds
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}

	// Check if GoGo is available
	if !h.gogoScanner.IsAvailable() {
		utils.InternalError(c, "GoGo 端口扫描器不可用")
		return
	}

	// Set timeout
	timeout := 60 * time.Second
	if req.Timeout > 0 {
		timeout = clampScanTimeout(req.Timeout)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	result, err := h.gogoScanner.QuickScan(ctx, req.Target)
	if err != nil {
		utils.InternalError(c, "端口扫描失败: "+err.Error())
		return
	}
	utils.Success(c, result)
}

// CustomPortScan performs a custom port scan
// POST /api/scan/port/custom
func (h *ScanHandler) CustomPortScan(c *gin.Context) {
	var req struct {
		Target    string `json:"target" binding:"required"`
		Ports     string `json:"ports"`      // comma-separated: "80,443,8080" or range: "1-1000"
		StartPort int    `json:"start_port"` // for range scan
		EndPort   int    `json:"end_port"`   // for range scan
		Timeout   int    `json:"timeout"`    // seconds
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}

	// Check if GoGo is available
	if !h.gogoScanner.IsAvailable() {
		utils.InternalError(c, "GoGo 端口扫描器不可用")
		return
	}

	// Set timeout
	timeout := 120 * time.Second
	if req.Timeout > 0 {
		timeout = clampScanTimeout(req.Timeout)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var result *core.ScanResult
	var err error

	// Parse ports
	if req.Ports != "" {
		result, err = h.gogoScanner.ScanPorts(ctx, req.Target, req.Ports)
	} else if req.StartPort > 0 && req.EndPort > 0 {
		if req.EndPort < req.StartPort {
			utils.BadRequest(c, "结束端口必须大于起始端口")
			return
		}
		if req.EndPort-req.StartPort > 10000 {
			utils.BadRequest(c, "端口范围不能超过10000")
			return
		}
		portRange := strconv.Itoa(req.StartPort) + "-" + strconv.Itoa(req.EndPort)
		result, err = h.gogoScanner.ScanPorts(ctx, req.Target, portRange)
	} else {
		// Default to quick scan
		result, err = h.gogoScanner.QuickScan(ctx, req.Target)
	}

	if err != nil {
		utils.InternalError(c, "端口扫描失败: "+err.Error())
		return
	}
	utils.Success(c, result)
}

// SinglePortScan scans a single port
// GET /api/scan/port/single
func (h *ScanHandler) SinglePortScan(c *gin.Context) {
	target := c.Query("target")
	portStr := c.Query("port")

	if target == "" || portStr == "" {
		utils.BadRequest(c, "target 和 port 参数必填")
		return
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		utils.BadRequest(c, "无效的端口号")
		return
	}

	// Check if GoGo is available
	if !h.gogoScanner.IsAvailable() {
		utils.InternalError(c, "GoGo 端口扫描器不可用")
		return
	}

	// Use ScanOne for single port (faster)
	result := h.gogoScanner.ScanOne(target, portStr)
	utils.Success(c, gin.H{
		"target": target,
		"port":   port,
		"result": result,
	})
}

// parsePortString parses a port string like "80,443,8080" or "1-1000" or mixed "80,443,8000-9000"
func parsePortString(portStr string) []int {
	ports := make([]int, 0)
	portMap := make(map[int]bool) // deduplicate

	parts := strings.Split(portStr, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Check if it's a range
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				continue
			}
			start, err1 := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err1 != nil || err2 != nil || start < 1 || end > 65535 || start > end {
				continue
			}
			for p := start; p <= end && p <= 65535; p++ {
				if !portMap[p] {
					portMap[p] = true
					ports = append(ports, p)
				}
			}
		} else {
			port, err := strconv.Atoi(part)
			if err != nil || port < 1 || port > 65535 {
				continue
			}
			if !portMap[port] {
				portMap[port] = true
				ports = append(ports, port)
			}
		}
	}

	return ports
}

// CSegmentScan performs a C segment scan
// POST /api/scan/csegment
func (h *ScanHandler) CSegmentScan(c *gin.Context) {
	var req struct {
		Target    string `json:"target" binding:"required"` // 192.168.1.0/24, 192.168.1.*, 192.168.1.1-254
		Ports     string `json:"ports"`                     // optional: comma-separated ports
		AliveOnly bool   `json:"alive_only"`                // only return alive hosts
		Timeout   int    `json:"timeout"`                   // seconds
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}

	// Set timeout (default 5 minutes for C segment)
	timeout := 5 * time.Minute
	if req.Timeout > 0 {
		timeout = clampScanTimeout(req.Timeout)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Parse ports
	var ports []int
	if req.Ports != "" {
		ports = parsePortString(req.Ports)
	}

	var result *portscan.CSegmentResult
	if len(ports) > 0 {
		result = h.csegmentScanner.ScanCSegment(ctx, req.Target, ports, req.AliveOnly)
	} else {
		result = h.csegmentScanner.QuickCSegmentScan(ctx, req.Target)
	}

	utils.Success(c, result)
}

// QuickCSegmentScan performs a quick C segment alive detection
// POST /api/scan/csegment/quick
func (h *ScanHandler) QuickCSegmentScan(c *gin.Context) {
	var req struct {
		Target  string `json:"target" binding:"required"`
		Timeout int    `json:"timeout"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}

	timeout := 3 * time.Minute
	if req.Timeout > 0 {
		timeout = clampScanTimeout(req.Timeout)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	result := h.csegmentScanner.QuickCSegmentScan(ctx, req.Target)
	utils.Success(c, result)
}

// FullCSegmentScan performs a full C segment scan with port detection
// POST /api/scan/csegment/full
func (h *ScanHandler) FullCSegmentScan(c *gin.Context) {
	var req struct {
		Target  string `json:"target" binding:"required"`
		Ports   string `json:"ports"` // optional, defaults to top ports
		Timeout int    `json:"timeout"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}

	timeout := 10 * time.Minute
	if req.Timeout > 0 {
		timeout = clampScanTimeout(req.Timeout)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var ports []int
	if req.Ports != "" {
		ports = parsePortString(req.Ports)
	}

	result := h.csegmentScanner.FullCSegmentScan(ctx, req.Target, ports)
	utils.Success(c, result)
}

// ===================== Domain Scanning =====================

// DomainInfo retrieves DNS information for a domain
// GET /api/scan/domain/info
func (h *ScanHandler) DomainInfo(c *gin.Context) {
	domain := c.Query("domain")
	if domain == "" {
		utils.BadRequest(c, "domain 参数必填")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result := h.domainScanner.GetDomainInfo(ctx, domain)
	utils.Success(c, result)
}

// QuickSubdomainScan performs a quick subdomain enumeration
// POST /api/scan/subdomain/quick
func (h *ScanHandler) QuickSubdomainScan(c *gin.Context) {
	var req struct {
		Domain  string `json:"domain" binding:"required"`
		Timeout int    `json:"timeout"` // seconds
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}

	timeout := 3 * time.Minute
	if req.Timeout > 0 {
		timeout = clampScanTimeout(req.Timeout)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	result := h.domainScanner.QuickSubdomainScan(ctx, req.Domain)
	utils.Success(c, result)
}

// FullSubdomainScan performs a full subdomain enumeration
// POST /api/scan/subdomain/full
func (h *ScanHandler) FullSubdomainScan(c *gin.Context) {
	var req struct {
		Domain  string `json:"domain" binding:"required"`
		Timeout int    `json:"timeout"` // seconds
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}

	timeout := 10 * time.Minute
	if req.Timeout > 0 {
		timeout = clampScanTimeout(req.Timeout)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	result := h.domainScanner.FullSubdomainScan(ctx, req.Domain)
	utils.Success(c, result)
}

// CustomSubdomainScan performs subdomain enumeration with custom wordlist
// POST /api/scan/subdomain/custom
func (h *ScanHandler) CustomSubdomainScan(c *gin.Context) {
	var req struct {
		Domain   string `json:"domain" binding:"required"`
		Wordlist string `json:"wordlist" binding:"required"` // comma or newline separated
		Timeout  int    `json:"timeout"`                     // seconds
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}

	wordlist := subdomain.ParseWordlist(req.Wordlist)
	if len(wordlist) == 0 {
		utils.BadRequest(c, "字典不能为空")
		return
	}

	timeout := 10 * time.Minute
	if req.Timeout > 0 {
		timeout = clampScanTimeout(req.Timeout)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	result := h.domainScanner.CustomSubdomainScan(ctx, req.Domain, wordlist)
	utils.Success(c, result)
}

// ===================== CDN Detection =====================

// CDNDetect detects if a domain is behind CDN
// POST /api/scan/cdn/detect
func (h *ScanHandler) CDNDetect(c *gin.Context) {
	var req struct {
		Domain  string `json:"domain" binding:"required"`
		Timeout int    `json:"timeout"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}

	timeout := 30 * time.Second
	if req.Timeout > 0 {
		timeout = clampScanTimeout(req.Timeout)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	result := h.cdnDetector.DetectCDN(ctx, req.Domain)

	// Try to find real IP if CDN detected
	if result.IsCDN {
		result.RealIPs = h.cdnDetector.TryFindRealIP(ctx, req.Domain)
	}

	utils.Success(c, result)
}

// CDNBatchDetect detects CDN for multiple domains
// POST /api/scan/cdn/batch
func (h *ScanHandler) CDNBatchDetect(c *gin.Context) {
	var req struct {
		Domains []string `json:"domains" binding:"required"`
		Timeout int      `json:"timeout"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}

	if len(req.Domains) == 0 {
		utils.BadRequest(c, "域名列表不能为空")
		return
	}
	if len(req.Domains) > maxBatchTargets {
		utils.BadRequest(c, fmt.Sprintf("域名列表过多（%d），单次最多 %d 个", len(req.Domains), maxBatchTargets))
		return
	}

	timeout := 5 * time.Minute
	if req.Timeout > 0 {
		timeout = clampScanTimeout(req.Timeout)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	results := h.cdnDetector.BatchDetectCDN(ctx, req.Domains, 20)
	utils.Success(c, results)
}

// ===================== Fingerprint Detection =====================

// FingerprintScan performs fingerprint detection on a target
// POST /api/scan/fingerprint
func (h *ScanHandler) FingerprintScan(c *gin.Context) {
	var req struct {
		Target  string `json:"target" binding:"required"`
		Timeout int    `json:"timeout"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}

	timeout := 30 * time.Second
	if req.Timeout > 0 {
		timeout = clampScanTimeout(req.Timeout)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	result := h.fingerprintScanner.ScanFingerprint(ctx, req.Target)
	utils.Success(c, result)
}

// FingerprintBatchScan performs fingerprint detection on multiple targets
// POST /api/scan/fingerprint/batch
func (h *ScanHandler) FingerprintBatchScan(c *gin.Context) {
	var req struct {
		Targets []string `json:"targets" binding:"required"`
		Timeout int      `json:"timeout"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}

	if len(req.Targets) == 0 {
		utils.BadRequest(c, "目标列表不能为空")
		return
	}
	if len(req.Targets) > maxBatchTargets {
		utils.BadRequest(c, fmt.Sprintf("目标列表过多（%d），单次最多 %d 个", len(req.Targets), maxBatchTargets))
		return
	}

	timeout := 10 * time.Minute
	if req.Timeout > 0 {
		timeout = clampScanTimeout(req.Timeout)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	results := h.fingerprintScanner.BatchScanFingerprint(ctx, req.Targets)
	utils.Success(c, results)
}

// ===================== Vulnerability Scanning =====================

// VulnScan performs vulnerability scan on a target
// POST /api/scan/vuln
func (h *ScanHandler) VulnScan(c *gin.Context) {
	var req struct {
		Target   string `json:"target" binding:"required"`
		Severity string `json:"severity"` // filter by severity: critical, high, medium, low, info
		Timeout  int    `json:"timeout"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}

	timeout := 10 * time.Minute
	if req.Timeout > 0 {
		timeout = clampScanTimeout(req.Timeout)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var templates []*vulnscan.POCTemplate
	if req.Severity != "" {
		templates = h.vulnScanner.FilterTemplatesBySeverity(req.Severity)
	}

	result := h.vulnScanner.ScanVuln(ctx, req.Target, templates)
	utils.Success(c, result)
}

// VulnQuickScan performs a quick vulnerability scan (high/critical only)
// POST /api/scan/vuln/quick
func (h *ScanHandler) VulnQuickScan(c *gin.Context) {
	var req struct {
		Target  string `json:"target" binding:"required"`
		Timeout int    `json:"timeout"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}

	timeout := 5 * time.Minute
	if req.Timeout > 0 {
		timeout = clampScanTimeout(req.Timeout)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Get only high and critical severity templates
	highTemplates := h.vulnScanner.FilterTemplatesBySeverity("high")
	criticalTemplates := h.vulnScanner.FilterTemplatesBySeverity("critical")
	templates := append(highTemplates, criticalTemplates...)

	result := h.vulnScanner.ScanVuln(ctx, req.Target, templates)
	utils.Success(c, result)
}

// GetPOCList returns list of available POC templates
// GET /api/scan/vuln/pocs
func (h *ScanHandler) GetPOCList(c *gin.Context) {
	severity := c.Query("severity")

	var templates []*vulnscan.POCTemplate
	if severity != "" {
		templates = h.vulnScanner.FilterTemplatesBySeverity(severity)
	} else {
		templates = h.vulnScanner.Templates
	}

	// Return simplified list
	type POCInfo struct {
		ID          string   `json:"id"`
		Name        string   `json:"name"`
		Severity    string   `json:"severity"`
		Description string   `json:"description"`
		Tags        []string `json:"tags"`
	}

	pocs := make([]POCInfo, len(templates))
	for i, t := range templates {
		pocs[i] = POCInfo{
			ID:          t.ID,
			Name:        t.Info.Name,
			Severity:    t.Info.Severity,
			Description: t.Info.Description,
			Tags:        t.Info.Tags,
		}
	}

	utils.Success(c, gin.H{
		"total": len(pocs),
		"pocs":  pocs,
	})
}

// ===================== Content Scanning =====================

// DirScan performs directory brute force scan using Spray
// POST /api/scan/dir
func (h *ScanHandler) DirScan(c *gin.Context) {
	var req struct {
		Target   string   `json:"target" binding:"required"`
		Wordlist []string `json:"wordlist"`
		Timeout  int      `json:"timeout"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}

	if h.sprayScanner == nil || !h.sprayScanner.IsAvailable() {
		utils.Error(c, 500, "Spray 扫描器不可用")
		return
	}

	timeout := 10 * time.Minute
	if req.Timeout > 0 {
		timeout = clampScanTimeout(req.Timeout)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var result *webscan.SprayResult
	var err error

	if len(req.Wordlist) > maxDirWordlist {
		utils.BadRequest(c, fmt.Sprintf("字典过大（%d 条），最多 %d 条", len(req.Wordlist), maxDirWordlist))
		return
	}
	if len(req.Wordlist) > 0 {
		result, err = h.sprayScanner.ScanWithWordlist(ctx, req.Target, req.Wordlist)
	} else {
		result, err = h.sprayScanner.Scan(ctx, req.Target)
	}

	if err != nil {
		utils.Error(c, 500, "扫描失败: "+err.Error())
		return
	}
	utils.Success(c, result)
}

// QuickDirScan performs a quick directory scan using Spray
// POST /api/scan/dir/quick
func (h *ScanHandler) QuickDirScan(c *gin.Context) {
	var req struct {
		Target  string `json:"target" binding:"required"`
		Timeout int    `json:"timeout"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}

	if h.sprayScanner == nil || !h.sprayScanner.IsAvailable() {
		utils.Error(c, 500, "Spray 扫描器不可用")
		return
	}

	timeout := 3 * time.Minute
	if req.Timeout > 0 {
		timeout = clampScanTimeout(req.Timeout)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	result, err := h.sprayScanner.Scan(ctx, req.Target)
	if err != nil {
		utils.Error(c, 500, "扫描失败: "+err.Error())
		return
	}
	utils.Success(c, result)
}

// SensitiveScan scans for sensitive information
// POST /api/scan/sensitive
func (h *ScanHandler) SensitiveScan(c *gin.Context) {
	var req struct {
		Target  string `json:"target" binding:"required"`
		Timeout int    `json:"timeout"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}

	timeout := 30 * time.Second
	if req.Timeout > 0 {
		timeout = clampScanTimeout(req.Timeout)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	result := h.contentScanner.ScanSensitiveInfo(ctx, req.Target)
	utils.Success(c, result)
}

// SensitiveBatchScan scans multiple targets for sensitive information
// POST /api/scan/sensitive/batch
func (h *ScanHandler) SensitiveBatchScan(c *gin.Context) {
	var req struct {
		Targets []string `json:"targets" binding:"required"`
		Timeout int      `json:"timeout"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}

	if len(req.Targets) == 0 {
		utils.BadRequest(c, "目标列表不能为空")
		return
	}
	if len(req.Targets) > maxBatchTargets {
		utils.BadRequest(c, fmt.Sprintf("目标列表过多（%d），单次最多 %d 个", len(req.Targets), maxBatchTargets))
		return
	}

	timeout := 10 * time.Minute
	if req.Timeout > 0 {
		timeout = clampScanTimeout(req.Timeout)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	results := h.contentScanner.BatchScanSensitive(ctx, req.Targets)
	utils.Success(c, results)
}

// CrawlerScan performs web crawling
// POST /api/scan/crawler
func (h *ScanHandler) CrawlerScan(c *gin.Context) {
	var req struct {
		Target   string `json:"target" binding:"required"`
		MaxDepth int    `json:"max_depth"`
		MaxURLs  int    `json:"max_urls"`
		Timeout  int    `json:"timeout"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}

	// Set defaults
	if req.MaxDepth <= 0 {
		req.MaxDepth = 3
	}
	if req.MaxURLs <= 0 {
		req.MaxURLs = 100
	}

	timeout := 10 * time.Minute
	if req.Timeout > 0 {
		timeout = clampScanTimeout(req.Timeout)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	crawler := webscan.NewWebCrawler(req.MaxDepth, req.MaxURLs, 10)
	result := crawler.Crawl(ctx, req.Target)
	utils.Success(c, result)
}

// ===================== Weak Password Scanning =====================

// WeakPwdScan performs weak password brute force
// POST /api/scan/weakpwd
func (h *ScanHandler) WeakPwdScan(c *gin.Context) {
	var req struct {
		Target  string `json:"target" binding:"required"`
		Port    int    `json:"port" binding:"required"`
		Service string `json:"service" binding:"required"` // ssh, ftp, mysql, redis
		Timeout int    `json:"timeout"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}

	timeout := 10 * time.Minute
	if req.Timeout > 0 {
		timeout = clampScanTimeout(req.Timeout)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var result *vulnscan.BruteForceResult
	switch strings.ToLower(req.Service) {
	case "ssh":
		result = h.weakPwdScanner.BruteForceSSH(ctx, req.Target, req.Port)
	case "ftp":
		result = h.weakPwdScanner.BruteForceFTP(ctx, req.Target, req.Port)
	case "mysql":
		result = h.weakPwdScanner.BruteForceMySQL(ctx, req.Target, req.Port)
	case "redis":
		result = h.weakPwdScanner.BruteForceRedis(ctx, req.Target, req.Port)
	default:
		utils.BadRequest(c, "不支持的服务类型，支持: ssh, ftp, mysql, redis")
		return
	}

	utils.Success(c, result)
}

// ===================== Subdomain Takeover Detection =====================

// TakeoverScan checks for subdomain takeover vulnerabilities
// POST /api/scan/takeover
func (h *ScanHandler) TakeoverScan(c *gin.Context) {
	var req struct {
		Domain  string `json:"domain" binding:"required"`
		Timeout int    `json:"timeout"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}

	timeout := 30 * time.Second
	if req.Timeout > 0 {
		timeout = clampScanTimeout(req.Timeout)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	result, err := h.takeoverScanner.Scan(ctx, req.Domain)
	if err != nil {
		utils.InternalError(c, "扫描失败: "+err.Error())
		return
	}

	utils.Success(c, result)
}

// TakeoverBatchScan batch checks for subdomain takeover
// POST /api/scan/takeover/batch
func (h *ScanHandler) TakeoverBatchScan(c *gin.Context) {
	var req struct {
		Domains []string `json:"domains" binding:"required"`
		Timeout int      `json:"timeout"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}

	if len(req.Domains) > 1000 {
		utils.BadRequest(c, "一次最多支持1000个域名")
		return
	}

	timeout := 5 * time.Minute
	if req.Timeout > 0 {
		timeout = clampScanTimeout(req.Timeout)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	results, err := h.takeoverScanner.ScanBatch(ctx, req.Domains)
	if err != nil {
		utils.InternalError(c, "扫描失败: "+err.Error())
		return
	}

	// 统计结果
	vulnerable := 0
	for _, r := range results {
		if r.Vulnerable {
			vulnerable++
		}
	}

	utils.Success(c, map[string]interface{}{
		"total":      len(results),
		"vulnerable": vulnerable,
		"results":    results,
	})
}

// GetTakeoverFingerprints returns available takeover fingerprints
// GET /api/scan/takeover/fingerprints
func (h *ScanHandler) GetTakeoverFingerprints(c *gin.Context) {
	fps := h.takeoverScanner.GetFingerprints()

	// 简化输出
	simplified := make([]map[string]interface{}, len(fps))
	for i, fp := range fps {
		simplified[i] = map[string]interface{}{
			"service":    fp.Service,
			"cnames":     fp.CNames,
			"vulnerable": fp.Vulnerable,
			"nxdomain":   fp.NXDomain,
			"http_check": fp.HTTPCheck,
		}
	}

	utils.Success(c, simplified)
}
