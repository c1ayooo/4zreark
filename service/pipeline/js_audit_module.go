package pipeline

import (
	"github.com/c1ayooo/4zreark/internal/safehttp"
	"github.com/c1ayooo/4zreark/internal/sourcemap"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/internal/useragent"
	"github.com/c1ayooo/4zreark/scanner/scope"
	"github.com/c1ayooo/4zreark/scanner/vulnscan"
)

// 单个 JS 产物的体积上限。前端 bundle 常见 1-5MB，再大的基本是打包进
// 来的第三方库，密钥密度极低，下载只白占带宽；总量同样封顶，防止大站
// 把磁盘写满。
const (
	jsAuditMaxFileBytes = 5 << 20
	jsAuditMaxFiles     = 300
	jsAuditFetchTimeout = 20 * time.Second
	jsAuditScanTimeout  = 8 * time.Minute
)

// JSAuditModule 把爬虫发现的 JS 产物落盘，再用 nuclei 的 file 模板
// （keys 目录：AK/SK、token 泄露规则）做内容审计。
// 这一层补的是纯 URL 扫描的盲区：密钥写在 JS 里，不需要发请求就能看。
type JSAuditModule struct {
	BaseModule
	scanner      *vulnscan.NucleiCLIScanner
	templatesDir string
	concurrency  int
	client       *http.Client
	scope        *scope.Scope

	mu       sync.Mutex
	files    map[string]string // 本地文件名 -> 源 URL（还原源文件带 [source: 路径] 后缀）
	failures int
	// restoredTotal 全局还原源文件计数（跨任务内所有 map），配合
	// sourcemapMaxRestoredTotal 防大站把磁盘与审计时间拖爆。
	restoredTotal int
}

// NewJSAuditModule 创建 JS 产物审计模块。
func NewJSAuditModule(ctx context.Context, nextModule ModuleRunner, concurrency int, templatesDir string) *JSAuditModule {
	if concurrency <= 0 {
		concurrency = 4
	}
	scanner := vulnscan.NewNucleiCLIScanner(templatesDir)
	return &JSAuditModule{
		BaseModule: BaseModule{
			name:       "JSAudit",
			ctx:        ctx,
			nextModule: nextModule,
			dupChecker: NewDuplicateChecker(),
		},
		scanner:      scanner,
		templatesDir: templatesDir,
		concurrency:  concurrency,
		// 审计 M3：抓取扫描目标的 JS，连接级校验（scan 档）
		client: &http.Client{
			Timeout: jsAuditFetchTimeout,
			Transport: &http.Transport{
				MaxIdleConns:        32,
				MaxIdleConnsPerHost: 8,
				IdleConnTimeout:     60 * time.Second,
				DialContext:         safehttp.NewDialer(safehttp.ModeScan, 10*time.Second).DialContext,
			},
		},
		files: make(map[string]string),
	}
}

// SetScope 设置任务授权边界；越界 URL 一律不下载。
func (m *JSAuditModule) SetScope(s *scope.Scope) { m.scope = s }

// SetTemplatesDir 覆盖模板目录（默认由流水线在装配时注入）。
func (m *JSAuditModule) SetTemplatesDir(dir string) { m.templatesDir = dir }

// SetNucleiBinary 覆盖 nuclei 二进制路径。
func (m *JSAuditModule) SetNucleiBinary(path string) {
	if m.scanner != nil {
		m.scanner.SetNucleiBinary(path)
	}
}

func (m *JSAuditModule) allowsURL(raw string) bool {
	return m.scope == nil || m.scope.AllowsURL(raw)
}

// ModuleRun 消费上游 URL，下载 JS 产物，收完后一次性交给 nuclei -file。
func (m *JSAuditModule) ModuleRun() error {
	if m.scanner == nil || m.templatesDir == "" {
		log.Printf("[%s] 未配置 nuclei 或模板目录，透传", m.name)
		return m.RunPassThrough()
	}

	workDir, err := os.MkdirTemp("", "js-audit-*")
	if err != nil {
		log.Printf("[%s] 创建临时目录失败: %v，透传", m.name, err)
		return m.RunPassThrough()
	}
	defer os.RemoveAll(workDir)

	m.ReportModuleStart(0)
	defer m.ReportModuleComplete()

	// 先拉起下游，保证结果通道有人消费
	var nextWg sync.WaitGroup
	if m.nextModule != nil {
		nextWg.Add(1)
		go func() {
			defer nextWg.Done()
			if err := m.nextModule.ModuleRun(); err != nil {
				log.Printf("[%s] 下游模块错误: %v", m.name, err)
			}
		}()
	}

	sem := make(chan struct{}, m.concurrency)
	var wg sync.WaitGroup
	queued := 0

	for {
		select {
		case <-m.ctx.Done():
			wg.Wait()
			m.runScan(workDir)
			if m.nextModule != nil {
				m.nextModule.CloseInput()
			}
			nextWg.Wait()
			return m.ctx.Err()

		case data, ok := <-m.input:
			if !ok {
				wg.Wait()
				m.runScan(workDir)
				if m.nextModule != nil {
					m.nextModule.CloseInput()
				}
				nextWg.Wait()
				return nil
			}

			rawURL, contentType := extractJSURL(data)
			if rawURL == "" {
				continue
			}
			if !looksLikeJS(rawURL, contentType) {
				// 非 JS 直接透传，别让上游的资产信息断流
				m.forward(data)
				continue
			}
			if !m.allowsURL(rawURL) {
				continue
			}

			m.mu.Lock()
			tooMany := len(m.files) >= jsAuditMaxFiles
			m.mu.Unlock()
			if tooMany {
				continue
			}

			queued++
			wg.Add(1)
			go func(u string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				name, err := m.fetch(workDir, u)
				if err != nil {
					m.mu.Lock()
					m.failures++
					m.mu.Unlock()
					return
				}
				m.mu.Lock()
				m.files[name] = u
				m.mu.Unlock()
				// restoreSourceMap 内部自己持 m.mu——绝不能在持锁状态下调用
				//（Mutex 不可重入，否则 fetch goroutine 死锁、任务永久卡 running）。
				restored := m.restoreSourceMap(workDir, u, filepath.Join(workDir, name))
				if restored > 0 {
					m.Logf("info", "%s source map 还原 %d 个源文件进审计", u, restored)
				}
			}(rawURL)
		}
	}
}

// runScan 对已落盘的 JS 产物跑一次 file 模板扫描，并把命中转成 VulnResult。
func (m *JSAuditModule) runScan(workDir string) {
	m.mu.Lock()
	count := len(m.files)
	failures := m.failures
	m.mu.Unlock()

	if count == 0 {
		log.Printf("[%s] 无 JS 产物可审计（下载失败 %d 个）", m.name, failures)
		return
	}

	log.Printf("[%s] 开始审计 %d 个 JS 产物（下载失败 %d 个）", m.name, count, failures)
	results, err := m.scanner.Scan(m.ctx, []string{workDir}, &vulnscan.NucleiScanConfig{
		Templates: []string{m.templatesDir},
		Timeout:   jsAuditScanTimeout,
	})
	if err != nil {
		log.Printf("[%s] nuclei 审计失败: %v", m.name, err)
		return
	}

	for _, r := range results {
		vr := m.toVulnResult(r)
		if vr == nil {
			continue
		}
		m.forward(*vr)
	}
	log.Printf("[%s] 审计完成，命中 %d 条", m.name, len(results))
}

// toVulnResult 把 nuclei 命中的本地路径换成源 URL。
// matched-at 指向临时文件，直接入库会丢失「这个密钥来自哪个站点」的线索。
func (m *JSAuditModule) toVulnResult(r *vulnscan.NucleiResult) *VulnResult {
	if r == nil {
		return nil
	}
	srcURL := ""
	if r.URL != "" {
		base := filepath.Base(r.URL)
		m.mu.Lock()
		srcURL = m.files[base]
		m.mu.Unlock()
	}

	evidence := r.Matched
	if len(r.ExtractedResults) > 0 {
		evidence = strings.Join(r.ExtractedResults, ",")
	}

	return &VulnResult{
		Target:      srcURL,
		VulnID:      r.TemplateID,
		Name:        r.TemplateName,
		Severity:    r.Severity,
		Type:        "js_secret",
		Description: r.Description,
		Evidence:    evidence,
		MatchedAt:   srcURL,
		Source:      "nuclei-js",
		Timestamp:   time.Now(),
	}
}

func (m *JSAuditModule) forward(v interface{}) {
	if m.nextModule == nil {
		return
	}
	select {
	case <-m.ctx.Done():
	case m.nextModule.GetInput() <- v:
	}
}

// sourcemap 还原的限额：单个 map 的还原源文件数、全局还原文件总数。
// map 里可能有上百个 source（node_modules 全量），全部落盘会把 nuclei
// 审计拖慢且磁盘翻倍；源码密钥集中在业务代码，优先级按 map 顺序即可。
const (
	sourcemapMaxRestoredPerMap  = 50
	sourcemapMaxRestoredTotal   = 1000
	sourcemapMaxSourcePathLogs  = 10
)

// restoreSourceMap 尝试还原 JS 产物对应的 source map 原始源码并落盘进
// workDir，与 JS 一起被 nuclei 审计。返回还原的源文件数。
// 两条发现路径：JS 尾部 sourceMappingURL 注释（含 data URI 内联）；
// 注释缺席时探测同路径 .map（部分构建产物不写注释但 map 一起部署了）。
func (m *JSAuditModule) restoreSourceMap(workDir, jsURL, localPath string) int {
	data, err := os.ReadFile(localPath)
	if err != nil || len(data) == 0 {
		return 0
	}

	ref := sourcemap.ExtractSourceMappingURL(string(data))
	mapData := m.fetchInlineOrRemoteMap(jsURL, ref)
	if mapData == nil {
		mapData = m.probeAdjacentMap(jsURL)
	}
	if mapData == nil {
		return 0
	}

	sm, err := sourcemap.Parse(mapData)
	if err != nil {
		log.Printf("[%s] %s source map 解析失败: %v", m.name, jsURL, err)
		return 0
	}

	restored := sm.Restore()
	if len(restored) == 0 {
		// 无 sourcesContent：sources 路径清单本身是目录结构泄露。
		paths := sm.SourcePaths()
		if len(paths) > 0 {
			preview := paths
			if len(preview) > sourcemapMaxSourcePathLogs {
				preview = preview[:sourcemapMaxSourcePathLogs]
			}
			log.Printf("[%s] %s source map 无源码内容，但泄露 %d 个源路径: %s...",
				m.name, jsURL, len(paths), strings.Join(preview, ", "))
		}
		return 0
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.restoredTotal >= sourcemapMaxRestoredTotal {
		return 0
	}

	h := sha1.Sum([]byte(jsURL))
	prefix := hex.EncodeToString(h[:8])
	count := 0
	for _, r := range restored {
		if count >= sourcemapMaxRestoredPerMap || m.restoredTotal >= sourcemapMaxRestoredTotal {
			break
		}
		if len(r.Content) > jsAuditMaxFileBytes {
			continue
		}
		name := prefix + "-map-" + r.Name
		if _, dup := m.files[name]; dup {
			continue
		}
		if err := os.WriteFile(filepath.Join(workDir, name), []byte(r.Content), 0o600); err != nil {
			continue
		}
		// 命中线索带源路径：JS URL + 还原文件在源码树里的位置。
		m.files[name] = jsURL + " [source: " + r.Path + "]"
		count++
		m.restoredTotal++
	}
	return count
}

// fetchInlineOrRemoteMap 处理 sourceMappingURL 引用：data URI 直接解码，
// 远程引用按相对 URL 解析、scope 校验后下载。ref 为空返回 nil。
func (m *JSAuditModule) fetchInlineOrRemoteMap(jsURL, ref string) []byte {
	if ref == "" {
		return nil
	}
	if sourcemap.IsDataURI(ref) {
		idx := strings.Index(ref, "base64,")
		if idx < 0 {
			// URL-encoded 形态
			if payload := strings.TrimPrefix(ref, "data:application/json,"); payload != ref {
				if dec, err := neturl.QueryUnescape(payload); err == nil {
					return []byte(dec)
				}
			}
			return nil
		}
		dec, err := base64.StdEncoding.DecodeString(ref[idx+len("base64,"):])
		if err != nil {
			return nil
		}
		return dec
	}
	base, err := neturl.Parse(jsURL)
	if err != nil {
		return nil
	}
	refURL, err := base.Parse(ref)
	if err != nil {
		return nil
	}
	if !m.allowsURL(refURL.String()) {
		return nil
	}
	return m.fetchBytes(refURL.String())
}

// probeAdjacentMap 探测与 JS 同路径的 .map 文件（app.js → app.js.map）。
// 404/403 等一切失败静默：探测本就是尽力而为。
func (m *JSAuditModule) probeAdjacentMap(jsURL string) []byte {
	if !strings.HasSuffix(strings.ToLower(neturl.PathEscape(jsURL)), ".js") &&
		!strings.HasSuffix(strings.ToLower(jsURL), ".js") {
		return nil
	}
	candidate := jsURL + ".map"
	if !m.allowsURL(candidate) {
		return nil
	}
	return m.fetchBytes(candidate)
}

// fetchBytes 下载 URL 内容，受单文件体积上限约束；非 2xx/HTML 一律 nil。
func (m *JSAuditModule) fetchBytes(rawURL string) []byte {
	req, err := http.NewRequestWithContext(m.ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", useragent.Pick())
	req.Header.Set("Accept", "*/*")
	resp, err := m.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, jsAuditMaxFileBytes+1))
	if err != nil || len(data) > jsAuditMaxFileBytes || len(data) == 0 || looksLikeHTML(data) {
		return nil
	}
	return data
}

// fetch 下载单个 JS 产物并落盘，返回本地文件名。
func (m *JSAuditModule) fetch(workDir, rawURL string) (string, error) {
	req, err := http.NewRequestWithContext(m.ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", useragent.Pick())
	req.Header.Set("Accept", "*/*")

	resp, err := m.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, jsAuditMaxFileBytes+1))
	if err != nil {
		return "", err
	}
	if len(data) > jsAuditMaxFileBytes {
		return "", fmt.Errorf("超过 %d 字节上限", jsAuditMaxFileBytes)
	}
	if len(data) == 0 || looksLikeHTML(data) {
		return "", fmt.Errorf("内容为空或实为 HTML")
	}

	h := sha1.Sum([]byte(rawURL))
	name := hex.EncodeToString(h[:8]) + ".js"
	if err := os.WriteFile(filepath.Join(workDir, name), data, 0o600); err != nil {
		return "", err
	}
	return name, nil
}

// extractJSURL 从上游数据里取出 URL 与 ContentType。
func extractJSURL(data interface{}) (string, string) {
	switch v := data.(type) {
	case UrlResult:
		return v.Output, v.ContentType
	case *UrlResult:
		if v != nil {
			return v.Output, v.ContentType
		}
	case AssetHttp:
		return v.URL, v.ContentType
	case *AssetHttp:
		if v != nil {
			return v.URL, v.ContentType
		}
	case string:
		return v, ""
	}
	return "", ""
}

// looksLikeJS 按扩展名与响应类型判断是否 JS 产物。
func looksLikeJS(rawURL, contentType string) bool {
	if strings.Contains(strings.ToLower(contentType), "javascript") {
		return true
	}
	u, err := neturl.Parse(rawURL)
	if err != nil {
		return false
	}
	p := strings.ToLower(u.Path)
	return strings.HasSuffix(p, ".js") || strings.HasSuffix(p, ".mjs") || strings.HasSuffix(p, ".cjs")
}

// looksLikeHTML 用来挡掉「.js 路径返回首页」这类错误页，
// 否则一堆 HTML 会被当成 JS 送进正则引擎。
func looksLikeHTML(data []byte) bool {
	head := data
	if len(head) > 512 {
		head = head[:512]
	}
	s := strings.ToLower(strings.TrimSpace(string(head)))
	return strings.HasPrefix(s, "<!doctype") || strings.HasPrefix(s, "<html")
}
