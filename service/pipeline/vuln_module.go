package pipeline

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/scanner/vulnscan"
	"github.com/c1ayooo/4zreark/service/notify"
)

// POCLoader 允许远程 worker 从平台 API 拉取 POC，而不是直连数据库。
type POCLoader func(ctx context.Context) ([]*models.POC, error)

var (
	pocLoaderMu sync.RWMutex
	pocLoader   POCLoader
)

// SetPOCLoader 设置 POC 来源；传 nil 恢复默认的 repo 读取。
func SetPOCLoader(l POCLoader) {
	pocLoaderMu.Lock()
	pocLoader = l
	pocLoaderMu.Unlock()
}

func loadPOCsFromDB(ctx context.Context) ([]*models.POC, error) {
	r := repo.Default()
	if r == nil {
		return nil, fmt.Errorf("数据库未就绪")
	}
	enabled := true
	f := repo.POCFilter{Type: "nuclei", Enabled: &enabled}
	items := make([]*models.POC, 0, 1024)
	for page := 1; ; page++ {
		f.Page, f.PageSize = page, 500
		batch, total, err := r.Pocs().List(ctx, f)
		if err != nil {
			return nil, err
		}
		items = append(items, batch...)
		if len(batch) < 500 || int64(len(items)) >= total {
			break
		}
	}
	return items, nil
}

func loadPOCs(ctx context.Context) ([]*models.POC, error) {
	pocLoaderMu.RLock()
	l := pocLoader
	pocLoaderMu.RUnlock()
	if l != nil {
		return l(ctx)
	}
	return loadPOCsFromDB(ctx)
}

// VulnScanModule 漏洞扫描模块
// 接收HTTP资产或URL，执行漏洞扫描，输出漏洞结果
type VulnScanModule struct {
	BaseModule
	resultChan  chan interface{}
	concurrency int
	templates   []string // 指定模板 ID
	severity    []string // 过滤严重级别
	tags        []string // 过滤标签

	invOnce sync.Once
	inv     []templateEntry
	invErr  error

	// 高危发现（critical/high）在模块收尾时聚成一条通知，避免逐条轰炸渠道。
	foundMu    sync.Mutex
	foundVulns []VulnResult
}

// templateEntry 是模板库的内存索引（内容 + 匹配所需的元数据）。
type templateEntry struct {
	ID       string
	Name     string
	Tags     []string
	Severity string
	Verified bool
	Content  string
}

// NewVulnScanModule 创建漏洞扫描模块
func NewVulnScanModule(ctx context.Context, nextModule ModuleRunner, concurrency int) *VulnScanModule {
	if concurrency <= 0 {
		concurrency = 10
	}

	m := &VulnScanModule{
		BaseModule: BaseModule{
			name:       "VulnScan",
			ctx:        ctx,
			nextModule: nextModule,
			dupChecker: NewDuplicateChecker(),
		},
		resultChan:  make(chan interface{}, 500),
		concurrency: concurrency,
		severity:    []string{"critical", "high", "medium"}, // 默认只扫描中高危
	}
	return m
}

// SetTemplates 设置要使用的模板
func (m *VulnScanModule) SetTemplates(templates []string) {
	m.templates = templates
}

// SetSeverity 设置要扫描的严重级别
func (m *VulnScanModule) SetSeverity(severity []string) {
	m.severity = severity
}

// SetTags 设置过滤标签
func (m *VulnScanModule) SetTags(tags []string) {
	m.tags = tags
}

// ModuleRun 运行模块
func (m *VulnScanModule) ModuleRun() error {
	var allWg sync.WaitGroup
	var resultWg sync.WaitGroup
	var nextModuleRun sync.WaitGroup

	// 并发控制
	sem := make(chan struct{}, m.concurrency)

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
					if vulnResult, ok := result.(VulnResult); ok {
						log.Printf("[%s] Found vulnerability: %s on %s (%s)",
							m.name, vulnResult.Name, vulnResult.Target, vulnResult.Severity)
					}
				}
			}
		}
		if m.nextModule != nil {
			m.nextModule.CloseInput()
		}
	}()

	// 处理输入
	// 进度追踪：模块启动 + 逐条处理计数（软进度，完成态由 ReportModuleComplete 置 100）
	m.ReportModuleStart(0)
	defer m.ReportModuleComplete()
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
				allWg.Wait()
				close(m.resultChan)
				resultWg.Wait()
				m.notifyHighRiskFindings()
				log.Printf("[%s] Input closed, waiting for next module", m.name)
				nextModuleRun.Wait()
				return nil
			}
			m.ReportProgress(1, 0)

			// 获取扫描目标 + 指纹技术栈
			target, techs := m.extractTarget(data)
			if target == "" {
				// 非HTTP资产，直接传递
				m.resultChan <- data
				continue
			}

			// 去重检查
			if m.dupChecker.IsURLDuplicate(target) {
				continue
			}

			allWg.Add(1)
			go func(t string, techs []string, originalData interface{}) {
				defer allWg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				// 先转发原始数据
				select {
				case <-m.ctx.Done():
					return
				case m.resultChan <- originalData:
				}

				// 执行漏洞扫描（带指纹）
				m.scanVulnerabilities(t, techs)
			}(target, techs, data)
		}
	}
}

// extractTarget 从输入数据中提取目标URL
func (m *VulnScanModule) extractTarget(data interface{}) (string, []string) {
	switch v := data.(type) {
	case AssetHttp:
		return v.URL, v.Technologies
	case SubdomainResult:
		// 子域模块的 HTTP 探测已经拿到更丰富的技术栈（Jenkins、明源云等），
		// 指纹模块的 808 条规则不一定认得出，这里一并利用。
		return v.URL, v.Technologies
	case UrlResult:
		return v.Output, nil
	case string:
		return v, nil
	default:
		return "", nil
	}
}

// verifiedRe 匹配模板 metadata 里的 verified: true。
var verifiedRe = regexp.MustCompile(`(?m)^\s*verified:\s*true\s*$`)

// techNoise 是「识别到了但不能用来选漏洞模板」的技术名：前端库、CDN、
// 页面特征词。把它们当产品去匹配会把整个模板库都选进来。
var techNoise = map[string]bool{
	"jquery": true, "bootstrap": true, "layui": true, "layer": true,
	"clipboard": true, "linkfinder": true, "cdn": true, "baidu": true,
	"webmaster": true, "website": true, "platform": true, "official": true,
	"manager": true, "operations": true, "server": true, "default": true,
	"test": true, "page": true, "welcome": true, "phone": true,
	"电话号": true, "管理后台登录": true, "腾讯问卷泄漏": true,
	"exposure-secretkey": true, "phpsessid": true, "nginx-default-test-page": true,
	// 语言 / 通用服务器不是「产品」：按它们选模板等于回到全量扫描
	"php": true, "nginx": true, "apache": true, "tengine": true, "iis": true,
	"java": true, "python": true, "node": true, "nodejs": true, "ruby": true,
	"perl": true, "asp": true, "aspnet": true, "jsp": true, "html": true,
	"css": true, "javascript": true, "js": true, "react": true, "vue": true,
	"angular": true, "webpack": true, "http": true, "https": true,
}

var techTokenRe = regexp.MustCompile(`[a-z0-9\p{Han}]+`)

// techTokens 把指纹技术名拆成可匹配的 token。
func techTokens(techs []string) []string {
	set := map[string]bool{}
	for _, tech := range techs {
		lower := strings.ToLower(strings.TrimSpace(tech))
		if lower == "" {
			continue
		}
		if !techNoise[lower] {
			set[lower] = true
		}
		for _, tok := range techTokenRe.FindAllString(lower, -1) {
			if len([]rune(tok)) >= 2 && !techNoise[tok] {
				set[tok] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	return out
}

// inventory 从 POC 库加载一次模板索引（只取启用中的 nuclei 模板）。
// 本地执行走 repo；远程 worker 通过注入的 POCLoader 走平台 API。
func (m *VulnScanModule) inventory() ([]templateEntry, error) {
	m.invOnce.Do(func() {
		items, err := loadPOCs(m.ctx)
		if err != nil {
			m.invErr = err
			return
		}
		inv := make([]templateEntry, 0, len(items))
		for _, p := range items {
			if strings.TrimSpace(p.Content) == "" {
				continue
			}
			inv = append(inv, templateEntry{
				ID:       p.TemplateID,
				Name:     p.Name,
				Tags:     p.Tags,
				Severity: strings.ToLower(string(p.Severity)),
				Verified: verifiedRe.MatchString(p.Content),
				Content:  p.Content,
			})
		}
		m.inv = inv
	})
	return m.inv, m.invErr
}

func (m *VulnScanModule) severityOK(t templateEntry) bool {
	if len(m.severity) == 0 {
		return true
	}
	for _, s := range m.severity {
		if t.Severity == strings.ToLower(s) {
			return true
		}
	}
	return false
}

func (m *VulnScanModule) tagOK(t templateEntry) bool {
	if len(m.tags) == 0 {
		return true
	}
	for _, want := range m.tags {
		for _, have := range t.Tags {
			if strings.EqualFold(have, want) {
				return true
			}
		}
	}
	return false
}

func matchesTech(t templateEntry, tokens []string) bool {
	hay := strings.ToLower(t.ID + " " + t.Name)
	for _, tok := range tokens {
		for _, tag := range t.Tags {
			if strings.EqualFold(tag, tok) {
				return true
			}
		}
		if strings.Contains(hay, tok) {
			return true
		}
	}
	return false
}

// selectTemplates 指纹驱动的模板选择：
//   - 显式指定 template_ids：只跑这些；
//   - 有指纹：选 tag/ID/名称命中该产品的模板（产品命中时允许未验证模板，
//     因为产品匹配本身已经把范围收窄了）；
//   - 指纹没命中任何模板：回退到已验证集合，避免漏扫；
//   - 没有指纹：只跑已验证集合。
func (m *VulnScanModule) selectTemplates(techs []string) []templateEntry {
	inv, err := m.inventory()
	if err != nil || len(inv) == 0 {
		return nil
	}

	if len(m.templates) > 0 {
		out := make([]templateEntry, 0, len(m.templates))
		ids := map[string]bool{}
		for _, id := range m.templates {
			ids[id] = true
		}
		for _, t := range inv {
			if ids[t.ID] {
				out = append(out, t)
			}
		}
		return out
	}

	tokens := techTokens(techs)
	if len(tokens) > 0 {
		matched := make([]templateEntry, 0, 64)
		for _, t := range inv {
			if m.severityOK(t) && m.tagOK(t) && matchesTech(t, tokens) {
				matched = append(matched, t)
			}
		}
		if len(matched) > 0 {
			log.Printf("[%s] 指纹命中: %v -> %d 个模板", m.name, tokens, len(matched))
			return matched
		}
	}

	// 回退：只跑已验证模板
	out := make([]templateEntry, 0, 128)
	for _, t := range inv {
		if t.Verified && m.severityOK(t) && m.tagOK(t) {
			out = append(out, t)
		}
	}
	return out
}

func (m *VulnScanModule) materialize(selected []templateEntry) (string, error) {
	dir, err := os.MkdirTemp("", "zre-nuclei-*")
	if err != nil {
		return "", err
	}
	for _, t := range selected {
		name := strings.Map(func(r rune) rune {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
				(r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
				return r
			}
			return '_'
		}, t.ID)
		if name == "" {
			name = "tpl"
		}
		if err := os.WriteFile(filepath.Join(dir, name+".yaml"), []byte(t.Content), 0o600); err != nil {
			continue
		}
	}
	return dir, nil
}

// scanVulnerabilities 执行漏洞扫描：指纹 → 选模板 → nuclei CLI。
func (m *VulnScanModule) scanVulnerabilities(target string, techs []string) {
	selected := m.selectTemplates(techs)
	if len(selected) == 0 {
		log.Printf("[%s] 无匹配模板，跳过 %s", m.name, target)
		return
	}

	dir, err := m.materialize(selected)
	if err != nil {
		log.Printf("[%s] 物化模板失败: %v", m.name, err)
		return
	}
	defer os.RemoveAll(dir)

	log.Printf("[%s] Scanning vulnerabilities for %s（%d 模板，指纹: %v）", m.name, target, len(selected), techs)

	scanner := vulnscan.NewNucleiCLIScanner(dir)
	if !scanner.IsAvailable() {
		log.Printf("[%s] nuclei CLI 不可用，跳过 %s", m.name, target)
		return
	}

	ctx, cancel := context.WithTimeout(m.ctx, 30*time.Minute)
	defer cancel()

	results, err := scanner.Scan(ctx, []string{target}, &vulnscan.NucleiScanConfig{
		Concurrency: 25,
		RateLimit:   50, // 与自动链路 nucleiruntime 的 50 硬顶对齐：150rps 对小目标是 DoS 级
		Timeout:     30 * time.Minute,
	})
	if err != nil {
		log.Printf("[%s] nuclei scan error for %s: %v", m.name, target, err)
		return
	}

	for _, r := range results {
		if r == nil {
			continue
		}
		vr := VulnResult{
			Target:      target,
			VulnID:      r.TemplateID,
			Name:        r.TemplateName,
			Severity:    strings.ToLower(r.Severity),
			Description: r.Description,
			Evidence:    r.URL,
			Reference:   r.Reference,
			MatchedAt:   r.URL,
			POC:         r.TemplateID,
			Source:      "nuclei",
			Timestamp:   time.Now(),
		}
		if vr.Severity == "critical" || vr.Severity == "high" {
			m.foundMu.Lock()
			m.foundVulns = append(m.foundVulns, vr)
			m.foundMu.Unlock()
		}
		select {
		case <-m.ctx.Done():
			return
		case m.resultChan <- vr:
		}
	}
	log.Printf("[%s] Scanned %d templates for %s, matched %d", m.name, len(selected), target, len(results))
}

// vulnNotifyTopN 高危通知里最多展示的明细条数。
const vulnNotifyTopN = 10

// notifyHighRiskFindings 模块收尾时把本轮 critical/high 发现聚合成一条通知。
// 逐条发会在大目标量下轰炸所有渠道；每条流水线一轮只发一条。
func (m *VulnScanModule) notifyHighRiskFindings() {
	m.foundMu.Lock()
	found := m.foundVulns
	m.foundVulns = nil
	m.foundMu.Unlock()

	msg := vulnFindingsMessage(found)
	if msg == nil {
		return
	}
	notify.GetGlobalManager().SendAsync(msg)
}

var vulnNotifyRanks = map[string]int{"critical": 0, "high": 1}

func vulnNotifyLabel(sev string) string {
	if sev == "critical" {
		return "严重"
	}
	return "高危"
}

// vulnFindingsMessage 高危发现聚合通知（纯函数，便于测试）。
// found 里只应传 critical/high；其他级别会被忽略，全被忽略时返回 nil。
func vulnFindingsMessage(found []VulnResult) *notify.NotifyMessage {
	filtered := make([]VulnResult, 0, len(found))
	critical, high := 0, 0
	for _, v := range found {
		switch v.Severity {
		case "critical":
			critical++
			filtered = append(filtered, v)
		case "high":
			high++
			filtered = append(filtered, v)
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	sort.SliceStable(filtered, func(i, j int) bool {
		return vulnNotifyRanks[filtered[i].Severity] < vulnNotifyRanks[filtered[j].Severity]
	})

	targets := make(map[string]struct{}, len(filtered))
	for _, v := range filtered {
		targets[v.Target] = struct{}{}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "**严重**: %d\n**高危**: %d\n**涉及目标**: %d\n**明细**:", critical, high, len(targets))
	shown := filtered
	if len(shown) > vulnNotifyTopN {
		shown = shown[:vulnNotifyTopN]
	}
	for _, v := range shown {
		fmt.Fprintf(&b, "\n- [%s] %s — %s", vulnNotifyLabel(v.Severity), v.Name, v.Target)
	}
	if len(filtered) > len(shown) {
		fmt.Fprintf(&b, "\n- ……等共 %d 条", len(filtered))
	}

	level := notify.NotifyLevelWarning
	if critical > 0 {
		level = notify.NotifyLevelCritical
	}
	return &notify.NotifyMessage{
		Level:   level,
		Title:   fmt.Sprintf("🚨 扫描发现 %d 个高危漏洞（%d 个目标）", len(filtered), len(targets)),
		Content: b.String(),
		Source:  "vuln_scanner",
	}
}
