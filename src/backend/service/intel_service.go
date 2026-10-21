package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/internal/recon/githubpoc"
	"github.com/c1ayooo/4zreark/internal/recon/triage"
	"github.com/c1ayooo/4zreark/internal/recon/vulnmonitor"
	"github.com/c1ayooo/4zreark/internal/recon/vulnmonitor/grab"
	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service/notify"
)

// 情报域服务：把 reconkit 的 vulnmonitor（9 个公开源轮询）接进本仓。
//
// 两个契约差异在这里消化，不往上漏：
//   - vulnmonitor 输出的 severity 是中文（低危/中危/高危/严重），而本仓
//     vulnerabilities 的 CHECK 约束与前端只认 critical/high/medium/low/info；
//   - vulnmonitor 的 Store 接口只有一个方法，其余查询走 repo.IntelRepo。

// severityRank 是中文档位在本仓内的排序权重。
var chineseSeverityRank = map[grab.SeverityLevel]int{
	grab.Low:      1,
	grab.Medium:   2,
	grab.High:     3,
	grab.Critical: 4,
}

// mapSeverity 把上游中文档位映射成本仓的英文档位。
// 认不出的档位落 info，不猜成 high——宁可漏报优先级，不要凭空拔高。
func mapSeverity(s grab.SeverityLevel) string {
	switch s {
	case grab.Critical:
		return "critical"
	case grab.High:
		return "high"
	case grab.Medium:
		return "medium"
	case grab.Low:
		return "low"
	}
	// 兜底：上游偶尔混入英文或带修饰的词，按关键字匹配一次。
	lower := strings.ToLower(string(s))
	switch {
	case strings.Contains(lower, "critical") || strings.Contains(lower, "严重"):
		return "critical"
	case strings.Contains(lower, "high") || strings.Contains(lower, "高危"):
		return "high"
	case strings.Contains(lower, "medium") || strings.Contains(lower, "中危"):
		return "medium"
	case strings.Contains(lower, "low") || strings.Contains(lower, "低危"):
		return "low"
	}
	return "info"
}

// intelStore 实现 vulnmonitor.Store，把归一化情报写进 vuln_intel。
type intelStore struct {
	repo  repo.IntelRepo
	stats *pollCounter
}

// NewIntelStore 返回 vulnmonitor.Store 的入库实现。这是情报落库的唯一接缝，
// 导出是为了让测试能直接打它（正常装配走 IntelService）。
func NewIntelStore(ri repo.IntelRepo) vulnmonitor.Store {
	return &intelStore{repo: ri}
}

// pollCounter 累计一轮轮询的写入结果，供日志与接口返回。
type pollCounter struct {
	mu      sync.Mutex
	created int
	updated int
	failed  int
}

func (c *pollCounter) add(created bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if created {
		c.created++
	} else {
		c.updated++
	}
}

func (c *pollCounter) addFail() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failed++
}

func (c *pollCounter) snapshot() (created, updated, failed int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.created, c.updated, c.failed
}

func (c *pollCounter) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.created, c.updated, c.failed = 0, 0, 0
}

func (s *intelStore) UpsertIntel(ctx context.Context, in vulnmonitor.Intel) (bool, error) {
	sev := mapSeverity(grab.SeverityLevel(in.Severity))
	if sev == "" {
		sev = "info"
	}
	created, err := s.repo.UpsertIntel(ctx, repo.IntelUpsert{
		UniqueKey:  in.UniqueKey,
		Title:      in.Title,
		Desc:       in.Description,
		Severity:   sev,
		CVE:        in.CVE,
		Disclosure: in.Disclosure,
		Solutions:  in.Solutions,
		Source:     in.Source,
		SourceName: in.SourceName,
		SourceURL:  in.SourceURL,
		From:       in.From,
		Tags:       in.Tags,
		References: in.References,
	})
	if err != nil {
		if s.stats != nil {
			s.stats.addFail()
		}
		return false, err
	}
	if s.stats != nil {
		s.stats.add(created)
	}
	return created, nil
}

// intelPollTimeout 是单轮轮询的上下文上限。9 个源里有 5 个是网页抓取，
// 慢的时候一轮能跑到几分钟；设太短会把正常轮询掐断，太长则让「立即刷新」
// 的请求挂住。5 分钟是踩过的折中值。
const intelPollTimeout = 5 * time.Minute

// dbCtxPoll 轮询专用上下文：比 dbCtx 的 10s 长得多。
func dbCtxPoll() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), intelPollTimeout)
}

// IntelService 管理轮询器的生命周期与设置。
type IntelService struct {
	mu      sync.Mutex
	monitor *vulnmonitor.Monitor
	counter *pollCounter
	running bool
	cancel  context.CancelFunc
	// tokenFn 解析 GitHub 凭据；默认环境变量优先、其次 sources 表。
	tokenFn func(context.Context) string
}

// intelSettings 是 vuln_intel_settings 里本服务关心的键。
type intelSettings struct {
	Enabled         bool
	IntervalMinutes int
	NotifyEnabled   bool
	Polling         bool
	LastPoll        time.Time
	LastResult      vulnmonitor.PollResult
	Sources         int
}

func NewIntelService() *IntelService {
	return &IntelService{tokenFn: func(ctx context.Context) string {
		return NewSourceService().GitHubToken(ctx)
	}}
}

// NewIntelServiceWithToken 供测试注入 token 解析，避免依赖进程环境与库内凭据。
func NewIntelServiceWithToken(fn func(context.Context) string) *IntelService {
	return &IntelService{tokenFn: fn}
}

func (s *IntelService) githubToken(ctx context.Context) string {
	if s.tokenFn != nil {
		return strings.TrimSpace(s.tokenFn(ctx))
	}
	return NewSourceService().GitHubToken(ctx)
}

func (s *IntelService) store() (repo.IntelRepo, error) {
	r := repo.Default()
	if r == nil {
		return nil, errors.New("数据库未就绪")
	}
	return r.Intels(), nil
}

// loadSettings 读设置表，缺键时用 DDL 里写入的默认值兜底。
func (s *IntelService) loadSettings(ctx context.Context) (intelSettings, error) {
	st, err := s.store()
	if err != nil {
		return intelSettings{}, err
	}
	kv, err := st.GetSettings(ctx)
	if err != nil {
		return intelSettings{}, err
	}
	out := intelSettings{
		Enabled:         kv["vulnintel.enabled"] == "true",
		IntervalMinutes: 60,
		NotifyEnabled:   true,
	}
	if v, err := strconv.Atoi(kv["vulnintel.interval_minutes"]); err == nil && v > 0 {
		out.IntervalMinutes = v
	}
	if v, ok := kv["vulnintel.notify_enabled"]; ok {
		out.NotifyEnabled = v == "true"
	}
	return out, nil
}

// build 按设置构造轮询器。Caller 必须持有 s.mu。
func (s *IntelService) build(cfg intelSettings) error {
	st, err := s.store()
	if err != nil {
		return err
	}
	s.counter = &pollCounter{}
	opts := []vulnmonitor.Option{
		vulnmonitor.WithInterval(time.Duration(cfg.IntervalMinutes) * time.Minute),
		// 硬编码 Medium 是刻意的：低危情报量大、信噪比低，默认不进库。
		// 要放宽就改这里，不暴露成用户设置——避免出现「库里突然多出几万条低危」。
		vulnmonitor.WithMinSeverity(grab.Medium),
	}
	if cfg.NotifyEnabled {
		opts = append(opts, vulnmonitor.WithNotifyHook(func(newHigh []string) {
			if len(newHigh) == 0 {
				return
			}
			log.Printf("[intel] 本轮新增高危/严重情报 %d 条，首条: %s", len(newHigh), newHigh[0])
			notifyIntelHigh(newHigh)
		}))
	}
	s.monitor = vulnmonitor.New(&intelStore{repo: st, stats: s.counter}, opts...)
	return nil
}

// notifyIntelHigh 走全局通知管理器。没配通知渠道时 SendAsync 只是静默丢弃，
// 不会报错，所以这里不用判断「有没有配」。
func notifyIntelHigh(titles []string) {
	m := notify.GetGlobalManager()
	if m == nil || len(titles) == 0 {
		return
	}
	body := "本轮新增高危/严重情报 " + strconv.Itoa(len(titles)) + " 条：\n"
	for i, t := range titles {
		if i >= 10 {
			body += "...\n"
			break
		}
		body += "· " + t + "\n"
	}
	m.SendAsync(&notify.NotifyMessage{
		Level:   notify.NotifyLevelWarning,
		Title:   "漏洞情报提醒",
		Content: body,
		Source:  "vuln-intel",
	})
}

// Start 启动轮询循环。设置里 enabled=false 时不轮询，但仍保留手动触发能力。
func (s *IntelService) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return nil
	}

	ctx, cancel := dbCtxPoll()
	cfg, err := s.loadSettings(ctx)
	if err != nil {
		cancel()
		return err
	}
	if err := s.build(cfg); err != nil {
		cancel()
		return err
	}

	if !cfg.Enabled {
		log.Println("[intel] 设置 vulnintel.enabled=false，跳过定时轮询（可手动触发）")
		cancel()
		return nil
	}

	s.cancel = cancel
	s.running = true
	s.monitor.Start(ctx)
	log.Printf("[intel] 已启动 %d 个情报源，间隔 %d 分钟", len(s.monitor.Providers()), cfg.IntervalMinutes)
	return nil
}

// Stop 停掉轮询。
func (s *IntelService) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		s.cancel()
	}
	s.running = false
}

// PollNow 手动触发一轮，同步返回结果。
func (s *IntelService) PollNow() (vulnmonitor.PollResult, error) {
	s.mu.Lock()
	if s.monitor == nil {
		cfg, err := s.loadSettings(context.Background())
		if err != nil {
			s.mu.Unlock()
			return vulnmonitor.PollResult{}, err
		}
		if err := s.build(cfg); err != nil {
			s.mu.Unlock()
			return vulnmonitor.PollResult{}, err
		}
	}
	m, counter := s.monitor, s.counter
	s.mu.Unlock()

	counter.reset()
	ctx, cancel := dbCtxPoll()
	defer cancel()
	res := m.Poll(ctx)
	return res, nil
}

// Refresh 插队一次异步轮询（用于从页面点「立即刷新」后不阻塞请求）。
func (s *IntelService) Refresh() {
	s.mu.Lock()
	m := s.monitor
	s.mu.Unlock()
	if m != nil {
		m.Refresh()
	}
}

// Status 返回轮询器状态与设置。
func (s *IntelService) Status() map[string]any {
	s.mu.Lock()
	m, running := s.monitor, s.running
	s.mu.Unlock()

	out := map[string]any{"running": running}
	if m == nil {
		return out
	}
	st := m.Status()
	out["polling"] = st.Polling
	out["sources"] = st.Sources
	out["last_poll"] = timeToNullable(st.LastPoll)
	out["last_result"] = map[string]any{
		"new":     st.LastResult.New,
		"updated": st.LastResult.Updated,
		"failed":  st.LastResult.Failed,
		"sources": st.LastResult.Sources,
		"errors":  st.LastResult.Errors,
	}

	providers := m.Providers()
	list := make([]map[string]string, 0, len(providers))
	for _, p := range providers {
		list = append(list, map[string]string{
			"name": p.Name, "display_name": p.DisplayName, "link": p.Link,
		})
	}
	out["providers"] = list
	return out
}

// GetSettings 读设置（含轮询状态）。
func (s *IntelService) GetSettings() (map[string]any, error) {
	ctx, cancel := dbCtx()
	defer cancel()
	cfg, err := s.loadSettings(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]any{
		"enabled":          cfg.Enabled,
		"interval_minutes": cfg.IntervalMinutes,
		"notify_enabled":   cfg.NotifyEnabled,
	}
	for k, v := range s.Status() {
		out[k] = v
	}
	return out, nil
}

// UpdateSettings 改设置。运行中改变间隔需要重建轮询器。
func (s *IntelService) UpdateSettings(in map[string]any) error {
	ctx, cancel := dbCtx()
	defer cancel()
	st, err := s.store()
	if err != nil {
		return err
	}

	writable := []string{"vulnintel.enabled", "vulnintel.interval_minutes", "vulnintel.notify_enabled"}
	for _, key := range writable {
		raw, ok := in[key]
		if !ok {
			continue
		}
		val, err := settingValue(raw)
		if err != nil {
			return errors.New("设置项 " + key + " 取值非法")
		}
		if key == "vulnintel.interval_minutes" {
			n, err := strconv.Atoi(val)
			if err != nil || n < 5 || n > 1440 {
				return errors.New("轮询间隔需在 5 到 1440 分钟之间")
			}
			val = strconv.Itoa(n)
		}
		if err := st.SetSetting(ctx, key, val); err != nil {
			return err
		}
	}

	// 设置变更后重建轮询器，让新间隔/新开关立即生效。
	s.Stop()
	if err := s.Start(); err != nil {
		log.Printf("[intel] 设置已保存，但重启轮询器失败: %v", err)
	}
	return nil
}

func settingValue(v any) (string, error) {
	switch x := v.(type) {
	case bool:
		if x {
			return "true", nil
		}
		return "false", nil
	case string:
		return strings.TrimSpace(x), nil
	case float64:
		return strconv.Itoa(int(x)), nil
	}
	return "", errors.New("不支持的类型")
}

func timeToNullable(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}

// ListIntel / GetIntel / IntelStats 是查询入口，供 api 层使用。
func (s *IntelService) ListIntel(f repo.IntelFilter) ([]*repo.IntelRow, int64, error) {
	ctx, cancel := dbCtx()
	defer cancel()
	st, err := s.store()
	if err != nil {
		return nil, 0, err
	}
	return st.List(ctx, f)
}

func (s *IntelService) GetIntel(uniqueKey string) (*repo.IntelRow, error) {
	ctx, cancel := dbCtx()
	defer cancel()
	st, err := s.store()
	if err != nil {
		return nil, err
	}
	return st.GetByUniqueKey(ctx, uniqueKey)
}

func (s *IntelService) IntelStats() (map[string]any, error) {
	ctx, cancel := dbCtx()
	defer cancel()
	st, err := s.store()
	if err != nil {
		return nil, err
	}
	bySource, err := st.SourceStats(ctx)
	if err != nil {
		return nil, err
	}
	bySeverity, err := st.SeverityStats(ctx)
	if err != nil {
		return nil, err
	}

	var total int64
	srcList := make([]map[string]any, 0, len(bySource))
	for _, s := range bySource {
		total += s.Count
		srcList = append(srcList, map[string]any{"source_name": s.SourceName, "count": s.Count})
	}
	sevList := make([]map[string]any, 0, len(bySeverity))
	for _, s := range bySeverity {
		sevList = append(sevList, map[string]any{"severity": s.Severity, "count": s.Count})
	}
	return map[string]any{
		"total":       total,
		"by_source":   srcList,
		"by_severity": sevList,
	}, nil
}

// ---------------------------------------------------------------- T3 富化

// EnrichIntel 对一条情报做 GitHub PoC 检索 + 仓库分诊，写回富化列。
//
// token 未配置时直接报错：vendored 的 SearchRepos 在无 token 时会返回空结果，
// 若不在这里拦住，调用方会看到一个「成功但 0 条」的假象。
func (s *IntelService) EnrichIntel(uniqueKey string) (*githubpoc.Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	st, err := s.store()
	if err != nil {
		return nil, err
	}
	row, err := st.GetByUniqueKey(ctx, uniqueKey)
	if err != nil {
		return nil, errors.New("情报不存在")
	}
	cve := strings.TrimSpace(row.CVE)
	if cve == "" {
		return nil, errors.New("该情报没有 CVE 编号，无法检索 PoC")
	}

	token := s.githubToken(ctx)
	if token == "" {
		return nil, errors.New("未配置 GitHub Token（环境变量 GITHUB_TOKEN 或数据源 github 凭据），GitHub 检索能力不可用")
	}
	client := githubpoc.NewClient(func() string { return token })

	meta := triage.CVEMeta{
		CVEID:       cve,
		CVSSScore:   row.CVSSScore,
		CVSSVector:  row.CVSSVector,
		CWE:         row.CWEs,
		Description: row.Description,
	}

	res, err := client.Enrich(ctx, meta)
	if err != nil {
		return nil, err
	}

	pocs := make([]repo.POCRef, 0, len(res.POCs))
	for _, p := range res.POCs {
		pocs = append(pocs, repo.POCRef{
			FullName:    p.FullName,
			URL:         p.URL,
			Stars:       p.Stars,
			Verdict:     p.Verdict,
			TriageScore: p.TriageScore,
		})
	}

	cwes := make([]int, 0, len(res.CWEs))
	for _, c := range res.CWEs {
		var n int
		if _, err := fmt.Sscanf(c, "CWE-%d", &n); err == nil && n > 0 {
			cwes = append(cwes, n)
		}
	}

	if err := st.MarkEnriched(ctx, repo.IntelEnrich{
		UniqueKey:  uniqueKey,
		GithubPoc:  pocs,
		CVSSScore:  res.CVSSScore,
		CVSSVector: res.CVSSVector,
		CWEs:       cwes,
		Affected:   res.Affected,
		// 已有 lab_only 标记不回退：说明该漏洞本身不适合实战。
		LabOnly: res.LabOnly || row.LabOnly,
	}); err != nil {
		return nil, err
	}
	return res, nil
}

// EnrichStatus 返回某条情报的富化状态，供接口回显。
func (s *IntelService) EnrichStatus(uniqueKey string) (map[string]any, error) {
	ctx, cancel := dbCtx()
	defer cancel()
	st, err := s.store()
	if err != nil {
		return nil, err
	}
	row, err := st.GetByUniqueKey(ctx, uniqueKey)
	if err != nil {
		return nil, errors.New("情报不存在")
	}
	out := map[string]any{
		"unique_key": row.UniqueKey,
		"cve":        row.CVE,
		"enriched":   !row.EnrichedAt.IsZero(),
		"lab_only":   row.LabOnly,
		"poc_count":  len(row.GithubPoc),
		"pocs":       row.GithubPoc,
	}
	if !row.EnrichedAt.IsZero() {
		out["enriched_at"] = row.EnrichedAt
		out["cvss_score"] = row.CVSSScore
		out["cvss_vector"] = row.CVSSVector
		out["cwes"] = row.CWEs
		out["affected"] = row.Affected
	}
	return out, nil
}
