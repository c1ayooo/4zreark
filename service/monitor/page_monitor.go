package monitor

import (
	"github.com/c1ayooo/4zreark/internal/safehttp"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/c1ayooo/4zreark/internal/useragent"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
)

// PageMonitor 页面变化监控器
type PageMonitor struct {
	client         *http.Client
	pages          map[string]*MonitoredPage
	mu             sync.RWMutex
	stopCh         chan struct{}
	stopOnce       sync.Once
	changeCallback func(*PageChange)
}

// MonitoredPage 被监控的页面
type MonitoredPage struct {
	ID          string            `json:"id"`
	URL         string            `json:"url"`
	Name        string            `json:"name"`
	Interval    time.Duration     `json:"interval"`
	MonitorType MonitorType       `json:"monitor_type"`
	Selector    string            `json:"selector,omitempty"` // CSS 选择器
	Keywords    []string          `json:"keywords,omitempty"` // 关键词监控
	Headers     map[string]string `json:"headers,omitempty"`  // 自定义请求头
	Enabled     bool              `json:"enabled"`

	// 状态
	LastCheck   time.Time `json:"last_check"`
	LastHash    string    `json:"last_hash"`
	LastContent string    `json:"last_content,omitempty"`
	LastStatus  int       `json:"last_status"`
	ChangeCount int       `json:"change_count"`
	ErrorCount  int       `json:"error_count"`
	LastError   string    `json:"last_error,omitempty"`

	// 内部控制：stopCh 与 stopped 由 PageMonitor.mu 保护，stopped 保证只 close 一次。
	// ticker 由 monitorPage 在协程内自建，不挂到结构体上（避免跨 goroutine 读写）。
	stopCh  chan struct{} `json:"-"`
	stopped bool          `json:"-"`
}

// MonitorType 监控类型
type MonitorType string

const (
	MonitorTypeFullPage MonitorType = "full_page" // 完整页面内容
	MonitorTypeSelector MonitorType = "selector"  // CSS 选择器内容
	MonitorTypeKeyword  MonitorType = "keyword"   // 关键词出现/消失
	MonitorTypeStatus   MonitorType = "status"    // HTTP 状态码
	MonitorTypeHash     MonitorType = "hash"      // 内容哈希
	MonitorTypeTitle    MonitorType = "title"     // 页面标题
)

// PageChange 页面变化记录
type PageChange struct {
	PageID     string     `json:"page_id"`
	URL        string     `json:"url"`
	ChangeType string     `json:"change_type"`
	OldContent string     `json:"old_content,omitempty"`
	NewContent string     `json:"new_content,omitempty"`
	OldHash    string     `json:"old_hash,omitempty"`
	NewHash    string     `json:"new_hash,omitempty"`
	OldStatus  int        `json:"old_status,omitempty"`
	NewStatus  int        `json:"new_status,omitempty"`
	Diff       []DiffLine `json:"diff,omitempty"`
	Timestamp  time.Time  `json:"timestamp"`
}

// DiffLine 差异行
type DiffLine struct {
	Type    string `json:"type"` // add, remove, same
	Content string `json:"content"`
	Line    int    `json:"line"`
}

// MonitorConfig 监控配置
type MonitorConfig struct {
	URL         string            `json:"url"`
	Name        string            `json:"name"`
	Interval    int               `json:"interval"` // 秒
	MonitorType MonitorType       `json:"monitor_type"`
	Selector    string            `json:"selector,omitempty"`
	Keywords    []string          `json:"keywords,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
}

// NewPageMonitor 创建页面监控器
func NewPageMonitor() *PageMonitor {
	return &PageMonitor{
		client: safehttp.Client(safehttp.ModeScan, 30*time.Second), // 审计 M3：连接级校验,
		pages:  make(map[string]*MonitoredPage),
		stopCh: make(chan struct{}),
	}
}

// SetChangeCallback 设置变化回调
func (m *PageMonitor) SetChangeCallback(callback func(*PageChange)) {
	m.mu.Lock()
	m.changeCallback = callback
	m.mu.Unlock()
}

// stopPageLocked 停止单个页面的监控协程，幂等。调用方必须持 m.mu 写锁。
func (m *PageMonitor) stopPageLocked(page *MonitoredPage) {
	if page.stopped {
		return
	}
	page.stopped = true
	close(page.stopCh)
}

// AddPage 添加监控页面
func (m *PageMonitor) AddPage(config MonitorConfig) (*MonitoredPage, error) {
	if config.URL == "" {
		return nil, fmt.Errorf("URL is required")
	}

	if config.Interval < 10 {
		config.Interval = 60 // 默认 60 秒
	}

	if config.MonitorType == "" {
		config.MonitorType = MonitorTypeFullPage
	}

	id := generatePageID(config.URL)

	// 同一 URL 重复添加时先停掉旧监控：否则旧协程仍按自己的 ticker 探测，
	// 既重复请求又永远无人回收（goroutine + ticker 泄漏）。
	m.mu.Lock()
	if old, ok := m.pages[id]; ok {
		m.stopPageLocked(old)
		delete(m.pages, id)
	}
	m.mu.Unlock()

	page := &MonitoredPage{
		ID:          id,
		URL:         config.URL,
		Name:        config.Name,
		Interval:    time.Duration(config.Interval) * time.Second,
		MonitorType: config.MonitorType,
		Selector:    config.Selector,
		Keywords:    config.Keywords,
		Headers:     config.Headers,
		Enabled:     true,
		stopCh:      make(chan struct{}),
	}

	// 首次获取内容（网络 IO，不持锁）
	if err := m.fetchAndStore(page); err != nil {
		m.mu.Lock()
		page.LastError = err.Error()
		page.ErrorCount++
		m.mu.Unlock()
	}

	m.mu.Lock()
	// 并发重复添加的兜底：后发布者覆盖前一个，并停掉它的协程。
	if old, ok := m.pages[id]; ok {
		m.stopPageLocked(old)
	}
	m.pages[id] = page
	m.mu.Unlock()

	// 启动监控
	go m.monitorPage(page)

	// 返回副本，避免调用方与监控协程共享可变字段。
	return copyPage(page), nil
}

// RemovePage 移除监控页面
func (m *PageMonitor) RemovePage(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	page, ok := m.pages[id]
	if !ok {
		return fmt.Errorf("page not found")
	}

	// 停止监控
	m.stopPageLocked(page)

	delete(m.pages, id)
	return nil
}

// copyPage 返回页面状态的浅拷贝（含 Headers/Keywords 的独立切片与 map），
// 调用方读写副本不会与监控协程竞争。
func copyPage(page *MonitoredPage) *MonitoredPage {
	if page == nil {
		return nil
	}
	cp := *page
	cp.stopCh = nil
	if page.Headers != nil {
		cp.Headers = make(map[string]string, len(page.Headers))
		for k, v := range page.Headers {
			cp.Headers[k] = v
		}
	}
	if page.Keywords != nil {
		cp.Keywords = append([]string(nil), page.Keywords...)
	}
	return &cp
}

// GetPage 获取页面信息（返回副本）
func (m *PageMonitor) GetPage(id string) (*MonitoredPage, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	page, ok := m.pages[id]
	if !ok {
		return nil, false
	}
	return copyPage(page), true
}

// GetAllPages 获取所有页面（返回副本）
func (m *PageMonitor) GetAllPages() []*MonitoredPage {
	m.mu.RLock()
	defer m.mu.RUnlock()

	pages := make([]*MonitoredPage, 0, len(m.pages))
	for _, p := range m.pages {
		pages = append(pages, copyPage(p))
	}
	return pages
}

// EnablePage 启用页面监控
func (m *PageMonitor) EnablePage(id string, enabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	page, ok := m.pages[id]
	if !ok {
		return fmt.Errorf("page not found")
	}

	page.Enabled = enabled
	return nil
}

// CheckNow 立即检查页面
func (m *PageMonitor) CheckNow(id string) (*PageChange, error) {
	m.mu.RLock()
	page, ok := m.pages[id]
	m.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("page not found")
	}

	return m.checkPage(page)
}

// monitorPage 监控页面循环
func (m *PageMonitor) monitorPage(page *MonitoredPage) {
	// ticker 只在本协程内可见：挂到 page 上会被 RemovePage/Stop 并发读写。
	ticker := time.NewTicker(page.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-page.stopCh:
			return
		case <-m.stopCh:
			return
		case <-ticker.C:
		}

		m.mu.RLock()
		enabled := page.Enabled
		callback := m.changeCallback
		m.mu.RUnlock()
		if !enabled {
			continue
		}

		change, err := m.checkPage(page)
		if err != nil {
			m.mu.Lock()
			page.LastError = err.Error()
			page.ErrorCount++
			m.mu.Unlock()
			continue
		}

		if change != nil && callback != nil {
			callback(change)
		}
	}
}

// checkPage 检查页面变化
func (m *PageMonitor) checkPage(page *MonitoredPage) (*PageChange, error) {
	// 先取配置快照再发请求：HTTP 往返期间持有读锁会阻塞 EnablePage/RemovePage。
	m.mu.RLock()
	targetURL := page.URL
	monitorType := page.MonitorType
	selector := page.Selector
	keywords := append([]string(nil), page.Keywords...)
	headers := make(map[string]string, len(page.Headers))
	for k, v := range page.Headers {
		headers[k] = v
	}
	m.mu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return nil, err
	}

	// 设置默认 User-Agent
	req.Header.Set("User-Agent", useragent.Pick())

	// 设置自定义请求头
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var change *PageChange

	switch monitorType {
	case MonitorTypeFullPage:
		change = m.checkFullPage(page, body, resp.StatusCode)
	case MonitorTypeSelector:
		change = m.checkSelector(page, selector, body, resp.StatusCode)
	case MonitorTypeKeyword:
		change = m.checkKeywords(page, keywords, body, resp.StatusCode)
	case MonitorTypeStatus:
		change = m.checkStatus(page, resp.StatusCode)
	case MonitorTypeHash:
		change = m.checkHash(page, body, resp.StatusCode)
	case MonitorTypeTitle:
		change = m.checkTitle(page, body, resp.StatusCode)
	}

	// 更新状态
	m.mu.Lock()
	page.LastCheck = time.Now()
	page.LastStatus = resp.StatusCode
	page.LastError = ""
	m.mu.Unlock()

	return change, nil
}

// checkFullPage 检查完整页面内容
func (m *PageMonitor) checkFullPage(page *MonitoredPage, body []byte, status int) *PageChange {
	// 清理 HTML 获取纯文本
	content := extractText(string(body))
	hash := hashContent(content)

	m.mu.Lock()
	defer m.mu.Unlock()

	if page.LastHash == "" {
		page.LastHash = hash
		page.LastContent = truncate(content, 10000)
		return nil
	}

	if page.LastHash != hash {
		change := &PageChange{
			PageID:     page.ID,
			URL:        page.URL,
			ChangeType: "content",
			OldHash:    page.LastHash,
			NewHash:    hash,
			OldContent: truncate(page.LastContent, 1000),
			NewContent: truncate(content, 1000),
			Diff:       generateDiff(page.LastContent, content),
			Timestamp:  time.Now(),
		}

		page.LastHash = hash
		page.LastContent = truncate(content, 10000)
		page.ChangeCount++

		return change
	}

	return nil
}

// checkSelector 检查选择器内容
func (m *PageMonitor) checkSelector(page *MonitoredPage, selector string, body []byte, status int) *PageChange {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(string(body)))
	if err != nil {
		return nil
	}

	var content strings.Builder
	doc.Find(selector).Each(func(i int, s *goquery.Selection) {
		content.WriteString(s.Text())
		content.WriteString("\n")
	})

	text := strings.TrimSpace(content.String())
	hash := hashContent(text)

	m.mu.Lock()
	defer m.mu.Unlock()

	if page.LastHash == "" {
		page.LastHash = hash
		page.LastContent = text
		return nil
	}

	if page.LastHash != hash {
		change := &PageChange{
			PageID:     page.ID,
			URL:        page.URL,
			ChangeType: "selector",
			OldHash:    page.LastHash,
			NewHash:    hash,
			OldContent: page.LastContent,
			NewContent: text,
			Timestamp:  time.Now(),
		}

		page.LastHash = hash
		page.LastContent = text
		page.ChangeCount++

		return change
	}

	return nil
}

// checkKeywords 检查关键词
func (m *PageMonitor) checkKeywords(page *MonitoredPage, keywords []string, body []byte, status int) *PageChange {
	content := string(body)

	var foundKeywords []string
	for _, kw := range keywords {
		if strings.Contains(strings.ToLower(content), strings.ToLower(kw)) {
			foundKeywords = append(foundKeywords, kw)
		}
	}

	keywordsHash := hashContent(strings.Join(foundKeywords, ","))

	m.mu.Lock()
	defer m.mu.Unlock()

	if page.LastHash == "" {
		page.LastHash = keywordsHash
		page.LastContent = strings.Join(foundKeywords, ",")
		return nil
	}

	if page.LastHash != keywordsHash {
		change := &PageChange{
			PageID:     page.ID,
			URL:        page.URL,
			ChangeType: "keyword",
			OldContent: page.LastContent,
			NewContent: strings.Join(foundKeywords, ","),
			Timestamp:  time.Now(),
		}

		page.LastHash = keywordsHash
		page.LastContent = strings.Join(foundKeywords, ",")
		page.ChangeCount++

		return change
	}

	return nil
}

// checkStatus 检查状态码
func (m *PageMonitor) checkStatus(page *MonitoredPage, status int) *PageChange {
	m.mu.Lock()
	defer m.mu.Unlock()

	if page.LastStatus == 0 {
		page.LastStatus = status
		return nil
	}

	if page.LastStatus != status {
		change := &PageChange{
			PageID:     page.ID,
			URL:        page.URL,
			ChangeType: "status",
			OldStatus:  page.LastStatus,
			NewStatus:  status,
			Timestamp:  time.Now(),
		}

		page.LastStatus = status
		page.ChangeCount++

		return change
	}

	return nil
}

// checkHash 检查内容哈希
func (m *PageMonitor) checkHash(page *MonitoredPage, body []byte, status int) *PageChange {
	hash := hashContent(string(body))

	m.mu.Lock()
	defer m.mu.Unlock()

	if page.LastHash == "" {
		page.LastHash = hash
		return nil
	}

	if page.LastHash != hash {
		change := &PageChange{
			PageID:     page.ID,
			URL:        page.URL,
			ChangeType: "hash",
			OldHash:    page.LastHash,
			NewHash:    hash,
			Timestamp:  time.Now(),
		}

		page.LastHash = hash
		page.ChangeCount++

		return change
	}

	return nil
}

// checkTitle 检查页面标题
func (m *PageMonitor) checkTitle(page *MonitoredPage, body []byte, status int) *PageChange {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(string(body)))
	if err != nil {
		return nil
	}

	title := doc.Find("title").Text()

	m.mu.Lock()
	defer m.mu.Unlock()

	if page.LastContent == "" {
		page.LastContent = title
		return nil
	}

	if page.LastContent != title {
		change := &PageChange{
			PageID:     page.ID,
			URL:        page.URL,
			ChangeType: "title",
			OldContent: page.LastContent,
			NewContent: title,
			Timestamp:  time.Now(),
		}

		page.LastContent = title
		page.ChangeCount++

		return change
	}

	return nil
}

// fetchAndStore 获取并存储初始内容
func (m *PageMonitor) fetchAndStore(page *MonitoredPage) error {
	// 配置取快照，写回统一在锁内完成：该函数既被 AddPage 调用，也可能被
	// 后续的「立即检查」路径复用，不能假设没有并发读者。
	m.mu.RLock()
	targetURL := page.URL
	monitorType := page.MonitorType
	selector := page.Selector
	keywords := append([]string(nil), page.Keywords...)
	headers := make(map[string]string, len(page.Headers))
	for k, v := range page.Headers {
		headers[k] = v
	}
	m.mu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return err
	}

	req.Header.Set("User-Agent", useragent.Pick())
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// 解析先在局部变量完成，再一次性写回，缩短持锁时间。
	var lastHash, lastContent string
	switch monitorType {
	case MonitorTypeFullPage, MonitorTypeHash:
		content := extractText(string(body))
		lastHash = hashContent(content)
		lastContent = truncate(content, 10000)
	case MonitorTypeSelector:
		doc, _ := goquery.NewDocumentFromReader(strings.NewReader(string(body)))
		var content strings.Builder
		doc.Find(selector).Each(func(i int, s *goquery.Selection) {
			content.WriteString(s.Text())
		})
		lastContent = content.String()
		lastHash = hashContent(lastContent)
	case MonitorTypeTitle:
		doc, _ := goquery.NewDocumentFromReader(strings.NewReader(string(body)))
		lastContent = doc.Find("title").Text()
	case MonitorTypeKeyword:
		var found []string
		for _, kw := range keywords {
			if strings.Contains(strings.ToLower(string(body)), strings.ToLower(kw)) {
				found = append(found, kw)
			}
		}
		lastContent = strings.Join(found, ",")
		lastHash = hashContent(lastContent)
	}

	m.mu.Lock()
	page.LastStatus = resp.StatusCode
	page.LastCheck = time.Now()
	page.LastHash = lastHash
	page.LastContent = lastContent
	m.mu.Unlock()

	return nil
}

// Stop 停止所有监控（可重复调用）
func (m *PageMonitor) Stop() {
	m.stopOnce.Do(func() { close(m.stopCh) })

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, page := range m.pages {
		m.stopPageLocked(page)
	}
}

// 工具函数

func generatePageID(url string) string {
	hash := md5.Sum([]byte(url))
	return hex.EncodeToString(hash[:8])
}

func hashContent(content string) string {
	hash := sha256.Sum256([]byte(content))
	return hex.EncodeToString(hash[:])
}

func extractText(html string) string {
	// 移除 script 和 style
	scriptRe := regexp.MustCompile(`<script[^>]*>[\s\S]*?</script>`)
	html = scriptRe.ReplaceAllString(html, "")

	styleRe := regexp.MustCompile(`<style[^>]*>[\s\S]*?</style>`)
	html = styleRe.ReplaceAllString(html, "")

	// 移除所有 HTML 标签
	tagRe := regexp.MustCompile(`<[^>]+>`)
	text := tagRe.ReplaceAllString(html, " ")

	// 清理多余空白
	spaceRe := regexp.MustCompile(`\s+`)
	text = spaceRe.ReplaceAllString(text, " ")

	return strings.TrimSpace(text)
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func generateDiff(old, new string) []DiffLine {
	oldLines := strings.Split(old, "\n")
	newLines := strings.Split(new, "\n")

	diff := make([]DiffLine, 0)

	// 简单 diff 实现
	maxLen := len(oldLines)
	if len(newLines) > maxLen {
		maxLen = len(newLines)
	}

	for i := 0; i < maxLen; i++ {
		var oldLine, newLine string
		if i < len(oldLines) {
			oldLine = oldLines[i]
		}
		if i < len(newLines) {
			newLine = newLines[i]
		}

		if oldLine != newLine {
			if oldLine != "" {
				diff = append(diff, DiffLine{
					Type:    "remove",
					Content: oldLine,
					Line:    i + 1,
				})
			}
			if newLine != "" {
				diff = append(diff, DiffLine{
					Type:    "add",
					Content: newLine,
					Line:    i + 1,
				})
			}
		}
	}

	// 限制 diff 数量
	if len(diff) > 100 {
		diff = diff[:100]
	}

	return diff
}
