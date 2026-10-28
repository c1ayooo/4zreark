package pipeline

import (
	"github.com/c1ayooo/4zreark/internal/safehttp"
	"context"
	"crypto/sha1"
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
	files    map[string]string // 本地文件名 -> 源 URL
	failures int
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
