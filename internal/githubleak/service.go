package githubleak

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/internal/lz"

	"github.com/c1ayooo/4zreark/internal/githubtokens"
	)

type persistence interface {
	AcquireRunLock(context.Context) (func(), bool, error)
	UpsertCandidates(context.Context, []Candidate, time.Time) ([]Candidate, int, error)
	List(context.Context, ListFilter) (ListResult, error)
	ListMissingSecret(context.Context, int) ([]Finding, error)
	UpdateSecretValue(context.Context, string, string, string) error
	Get(context.Context, string) (Finding, error)
	UpdateStatus(context.Context, string, string) (Finding, error)
	RecordVerifyResult(context.Context, string, string, string) error
	Stats(context.Context, *time.Time) (Stats, error)
	KeywordState(context.Context, string) (KeywordState, error)
	SaveKeywordState(context.Context, KeywordState) error
	BeginRun(context.Context, time.Time) (RunRecord, error)
	FinishRun(context.Context, RunRecord) error
	LatestRun(context.Context) (RunRecord, error)
}

type searchProvider interface {
	SearchKeywords(context.Context, []string, string, int, int) (SearchResult, error)
	// LatestPathCommitAt 路径提交时间（core API）：本地回溯窗口的时效校验依据。
	LatestPathCommitAt(context.Context, SearchItem) (time.Time, error)
}

// blobFetcher 由 *Client 实现：明文回填按 blob_sha 拉取原始文件内容。
type blobFetcher interface {
	FetchBlob(ctx context.Context, repository, blobSHA string) ([]byte, error)
}

type secretDetector interface {
	Detect(string, SearchItem) []Candidate
}

// searchQuotaProber 可选能力：实时查询 search 桶配额（*Client 实现；
// 测试桩可不实现，RuntimeStatus 里类型断言探测，缺省回退最近一轮 run 的头值）。
type searchQuotaProber interface {
	SearchQuota(context.Context) (SearchQuota, error)
}

// searchQuotaCacheTTL 配额探测进程内缓存：/rate_limit 虽不计配额，前端高频轮询
// Runtime 时不放大对 GitHub 的请求频率。
const searchQuotaCacheTTL = time.Minute

type runtimeConfig struct {
	settings Settings
	client   searchProvider
	detector secretDetector
}

// tokenPicker 从 GitHub Token 池选号（池未配置时为 nil → 用配置 token）。
type tokenPicker interface {
	Pick(ctx context.Context) string
}

type Service struct {
	store         persistence
	logger        *lz.Logger
	picker        tokenPicker
	searchLimiter *githubtokens.SearchLimiter
	// notify 新命中 IM 通知出口（notifier.Publish；未注入=不通知）。
	notify func(Event)
	// 池启用后固定指纹键：换号不使已存 findings 指纹失效
	fingerprintKeyFixed bool
	fixedFingerprintKey string

	mu        sync.Mutex
	settings  Settings
	client    searchProvider
	detector  secretDetector
	lastPurge time.Time
	// search 配额实时探测缓存（searchQuotaCacheTTL 内复用，见 RuntimeStatus）。
	quotaMu      sync.Mutex
	quotaCache   SearchQuota
	quotaChecked time.Time
	ctx          context.Context
	cancel       context.CancelFunc
	queue        chan struct{}
	wake         chan struct{}
	wg           sync.WaitGroup
	started      bool
	closed       bool
	running      bool
	queued       bool
	nextRun      *time.Time
	pending      *runtimeConfig
}

func NewService(store *Store, settings Settings, logger *lz.Logger) (*Service, error) {
	if store == nil {
		return nil, errors.New("github leak store is required")
	}
	return newService(store, settings, nil, nil, logger)
}

// SetSearchLimiter 注入进程级共享 search 桶限速器（轮换 provider 时保留）。
func (s *Service) SetSearchLimiter(l *githubtokens.SearchLimiter) {
	s.mu.Lock()
	s.searchLimiter = l
	if client, ok := s.client.(*Client); ok {
		client.SetSearchLimiter(l)
	}
	s.mu.Unlock()
}

// SetTokenPool 注入 Token 池轮换器（每次执行轮开始前取号）。
// SetNotify 注入 IM 通知出口（app 层传 notifier.Publish；未注入=不通知）。
func (s *Service) SetNotify(publish func(Event)) {
	s.mu.Lock()
	s.notify = publish
	s.mu.Unlock()
}

func (s *Service) SetTokenPool(picker tokenPicker) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.picker = picker
}

func newService(store persistence, settings Settings, provider searchProvider, detector secretDetector, logger *lz.Logger) (*Service, error) {
	if store == nil {
		return nil, errors.New("github leak persistence is required")
	}
	if logger == nil {
		logger = lz.NewNop()
	}
	normalized, err := settings.Normalize()
	if err != nil {
		return nil, err
	}
	if provider == nil {
		provider, err = NewClient(normalized)
		if err != nil {
			return nil, err
		}
	}
	if detector == nil && normalized.Configured() {
		detector, err = NewDetector(normalized)
		if err != nil {
			return nil, err
		}
	}
	logDetectorRules(logger, detector)
	return &Service{
		store: store, settings: normalized, client: provider, detector: detector, logger: logger,
		queue: make(chan struct{}, 1), wake: make(chan struct{}, 1),
	}, nil
}

// logDetectorRules 启动/热更时暴露检测规则构成。动态规则（extra_rules_path）
// 加载失败是静默的，dynamic=0 即提示接线/产物缺失（文档 R3 注意点 2）。
func logDetectorRules(logger *lz.Logger, detector secretDetector) {
	if logger == nil {
		return
	}
	if d, ok := detector.(*Detector); ok {
		logger.Info("GitHub leak monitor 检测规则就绪",
			lz.Int("builtin", len(strongSecretPatterns)), lz.Int("dynamic", d.DynamicRuleCount()))
	}
}

func (s *Service) Start(parent context.Context) {
	if parent == nil {
		parent = context.Background()
	}
	s.mu.Lock()
	if s.started || s.closed {
		s.mu.Unlock()
		return
	}
	s.ctx, s.cancel = context.WithCancel(parent)
	s.started = true
	if s.settings.Enabled && s.settings.Configured() && s.detector != nil {
		now := time.Now().UTC()
		s.nextRun = &now
	}
	s.wg.Add(1)
	s.mu.Unlock()
	go s.loop()
}

func (s *Service) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		s.wg.Wait()
		return
	}
	s.closed = true
	if s.cancel != nil {
		s.cancel()
	}
	s.mu.Unlock()
	s.wg.Wait()
}

func (s *Service) Trigger(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.started || s.closed || s.ctx == nil || s.ctx.Err() != nil {
		return ErrUnavailable
	}
	if !s.settings.Configured() || s.detector == nil {
		return ErrUnconfigured
	}
	if s.running || s.queued {
		return ErrBusy
	}
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	s.queued = true
	select {
	case s.queue <- struct{}{}:
		return nil
	default:
		s.queued = false
		return ErrBusy
	}
}

// UpdateSettings applies a validated snapshot. During an active run the latest
// snapshot is queued and atomically applied after that run, preserving the
// client's hard inter-request spacing boundary.
func (s *Service) UpdateSettings(settings Settings) error {
	normalized, err := settings.Normalize()
	if err != nil {
		return err
	}
	client, err := NewClient(normalized)
	if err != nil {
		return err
	}
	var detector secretDetector
	if normalized.Configured() {
		detector, err = NewDetector(normalized)
		if err != nil {
			return err
		}
	}
	logDetectorRules(s.logger, detector)
	next := &runtimeConfig{settings: normalized, client: client, detector: detector}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrUnavailable
	}
	if s.running {
		s.pending = next
		s.mu.Unlock()
		return nil
	}
	s.applyRuntimeLocked(next, s.client)
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
	return nil
}

func (s *Service) applyRuntimeLocked(next *runtimeConfig, previous searchProvider) {
	if next == nil {
		return
	}
	inheritRequestBoundary(previous, next.client)
	s.settings = next.settings
	s.client = next.client
	s.detector = next.detector
	s.pending = nil
	if s.settings.Enabled && s.settings.Configured() && s.detector != nil {
		now := time.Now().UTC()
		s.nextRun = &now
	} else {
		s.nextRun = nil
	}
}

func inheritRequestBoundary(previous, next searchProvider) {
	oldClient, oldOK := previous.(*Client)
	newClient, newOK := next.(*Client)
	if !oldOK || !newOK || oldClient == newClient {
		return
	}
	oldClient.requestMu.Lock()
	lastRequest := oldClient.lastRequest
	oldClient.requestMu.Unlock()
	newClient.lastRequest = lastRequest
}

// List 列表（按当前回溯窗口过滤：窗口外的历史行留在库中供审计，不再展示）。
func (s *Service) List(ctx context.Context, filter ListFilter) (ListResult, error) {
	cutoff := s.currentLookbackCutoff()
	filter.SourceUpdatedAfter = &cutoff
	return s.store.List(ctx, filter)
}

// Get 详情（窗口外的历史命中视为不存在，避免从深链访问已过期数据）。
// RecordVerifyResult 回写一条 finding 的验证结论（「验证」入口/Agent 落库）。
func (s *Service) RecordVerifyResult(ctx context.Context, id, verifyStatus, verifyEvidence string) error {
	return s.store.RecordVerifyResult(ctx, id, verifyStatus, verifyEvidence)
}

func (s *Service) Get(ctx context.Context, id string) (Finding, error) {
	finding, err := s.store.Get(ctx, id)
	if err != nil {
		return Finding{}, err
	}
	if finding.SourceUpdatedAt != nil && finding.SourceUpdatedAt.Before(s.currentLookbackCutoff()) {
		return Finding{}, ErrNotFound
	}
	return finding, nil
}

// UpdateStatus 状态更新（窗口外历史命中不可处置，与读取口径一致）。
func (s *Service) UpdateStatus(ctx context.Context, id, status string) (Finding, error) {
	if _, err := s.Get(ctx, id); err != nil {
		return Finding{}, err
	}
	return s.store.UpdateStatus(ctx, id, status)
}

// BackfillSecretValues 为未记录明文的历史命中找回原文：按 blob_sha 拉取文件、
// 重跑检测、指纹一致才回填（文件已删/已改则保持现状）。返回本次回填条数。
// 平台授权环境决策：明文入库直接展示研判；Provider 不支持 blob 拉取时静默跳过。
func (s *Service) BackfillSecretValues(ctx context.Context, maxItems int) (int, error) {
	if maxItems < 1 || maxItems > 200 {
		maxItems = 50
	}
	s.mu.Lock()
	detector, provider := s.detector, s.client
	configured := s.settings.Configured()
	s.mu.Unlock()
	if !configured || detector == nil {
		return 0, ErrUnconfigured
	}
	fetcher, ok := provider.(blobFetcher)
	if !ok {
		return 0, nil
	}
	findings, err := s.store.ListMissingSecret(ctx, maxItems)
	if err != nil {
		return 0, err
	}
	filled := 0
	for _, f := range findings {
		if ctx.Err() != nil {
			break
		}
		content, fetchErr := fetcher.FetchBlob(ctx, f.Repository, f.BlobSHA)
		if fetchErr != nil || len(content) == 0 {
			continue
		}
		item := SearchItem{Repository: f.Repository, Path: f.Path, BlobSHA: f.BlobSHA, HTMLURL: f.HTMLURL, Fragments: []string{string(content)}}
		for _, cand := range detector.Detect(f.Keyword, item) {
			if cand.Fingerprint == f.Fingerprint && cand.SecretValue != "" {
				if updateErr := s.store.UpdateSecretValue(ctx, f.ID, cand.SecretKey, cand.SecretValue); updateErr == nil {
					filled++
				}
				break
			}
		}
	}
	return filled, nil
}

// Stats 统计（按当前回溯窗口口径，与列表一致）。
func (s *Service) Stats(ctx context.Context) (Stats, error) {
	cutoff := s.currentLookbackCutoff()
	return s.store.Stats(ctx, &cutoff)
}

// currentLookbackCutoff 当前回溯窗口起点（考虑待生效设置）。
func (s *Service) currentLookbackCutoff() time.Time {
	s.mu.Lock()
	settings := s.settings
	if s.pending != nil {
		settings = s.pending.settings
	}
	s.mu.Unlock()
	return time.Now().UTC().AddDate(0, 0, -settings.ResolveLookbackDays())
}

func (s *Service) RuntimeStatus(ctx context.Context) (RuntimeStatus, error) {
	s.mu.Lock()
	settings := s.settings
	if s.pending != nil {
		settings = s.pending.settings
	}
	running := s.running
	next := copyTime(s.nextRun)
	s.mu.Unlock()
	status := RuntimeStatus{
		Enabled: settings.Enabled, Configured: settings.Configured(), Running: running,
		NextRunAt: next, RateRemaining: -1, IntervalSeconds: settings.PollIntervalSeconds,
		RequestIntervalSeconds: settings.IntervalSeconds,
		RequestTimeoutSeconds:  settings.RequestTimeoutSeconds,
		Keywords:               append([]string(nil), settings.Keywords...), Rules: []RuleStatus{},
		RepoMaxAgeDays:       settings.RepoMaxAgeDays,
		LookbackDays:         settings.ResolveLookbackDays(),
		NotifyEnabled:        settings.ResolveNotifyEnabled(),
		SearchQuotaRemaining: -1,
	}
	if rule, ruleErr := newKeywordRule(settings.Keywords); ruleErr == nil {
		status.Query = rule.Query
	}
	compiled, compileErr := compiledRules(settings, true)
	if compileErr != nil {
		return status, compileErr
	}
	for _, rule := range compiled {
		ruleStatus := RuleStatus{
			Enabled: rule.Enabled, Name: rule.Name,
			Keywords: append([]string(nil), rule.Keywords...), Query: rule.Query,
		}
		state, stateErr := s.store.KeywordState(ctx, rule.Query)
		if stateErr != nil {
			return status, stateErr
		}
		ruleStatus.LastAttemptAt = copyTime(state.LastAttemptAt)
		ruleStatus.LastSuccessAt = copyTime(state.LastSuccessAt)
		ruleStatus.LastStatus = strings.TrimSpace(state.LastStatus)
		ruleStatus.LastError = safeError(state.LastError)
		ruleStatus.Incomplete = state.Incomplete
		ruleStatus.Truncated = state.Truncated
		ruleStatus.PageCursor = state.PageCursor
		status.Rules = append(status.Rules, ruleStatus)
		if status.Query == "" && rule.Enabled {
			status.Keywords = append([]string(nil), rule.Keywords...)
			status.Query = rule.Query
		}
	}
	latest, err := s.store.LatestRun(ctx)
	if err != nil {
		return status, err
	}
	if latest.ID != "" {
		last := latest.StartedAt.UTC()
		status.LastRunAt = &last
		status.LastStatus = latest.Status
		message := safeError(latest.Error)
		if latest.Status == "partial" {
			status.LastWarning = message
		} else {
			status.LastError = message
		}
		status.RateRemaining = latest.RateRemaining
		status.RateResetAt = copyTime(latest.RateResetAt)
		status.LastRequests = latest.Requests
		status.LastProcessed = latest.Processed
		status.LastDetected = latest.Detected
	}
	// 实时 search 配额探测（R5-1）：/rate_limit 不计配额。运行中不探测——本轮
	// 响应头会持续刷新 RateRemaining；探测失败保持 -1 回退到最近一轮 run 的值。
	if settings.Configured() && !running {
		if prober, ok := s.client.(searchQuotaProber); ok {
			if quota, checkedAt, probed := s.cachedSearchQuota(ctx, prober); probed {
				status.SearchQuotaRemaining = quota.Remaining
				status.SearchQuotaLimit = quota.Limit
				status.SearchQuotaResetAt = copyTime(quota.ResetAt)
				status.SearchQuotaCheckedAt = copyTime(checkedAt)
			}
		}
	}
	return status, nil
}

// cachedSearchQuota 配额探测缓存读取/回填。TTL 内直接返回缓存；探测串行在
// quotaMu 内执行（/rate_limit 轻量且 10s 超时兜底，不会长时间占锁）。
func (s *Service) cachedSearchQuota(ctx context.Context, prober searchQuotaProber) (SearchQuota, *time.Time, bool) {
	s.quotaMu.Lock()
	defer s.quotaMu.Unlock()
	now := time.Now()
	if !s.quotaChecked.IsZero() && now.Sub(s.quotaChecked) < searchQuotaCacheTTL && s.quotaCache.Remaining >= 0 {
		checked := s.quotaChecked.UTC()
		return s.quotaCache, &checked, true
	}
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	quota, err := prober.SearchQuota(probeCtx)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("GitHub leak monitor search 配额探测失败", lz.Error(err))
		}
		return SearchQuota{}, nil, false
	}
	s.quotaCache = quota
	s.quotaChecked = now
	checked := now.UTC()
	return quota, &checked, true
}

func copyTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := value.UTC()
	return &copy
}

// deriveFingerprintKey 与 detector.NewDetector 的派生逻辑保持一致（SHA256 摘要）。
func deriveFingerprintKey(token string) string {
	digest := sha256.Sum256([]byte("4zreco/githubleak/fingerprint/v1\x00" + token))
	return "hex:" + hex.EncodeToString(digest[:])
}

// CurrentSettings 返回运行中的设置副本（供设置端点读取基线；Token 已脱敏为空）。
func (s *Service) CurrentSettings() Settings {
	s.mu.Lock()
	defer s.mu.Unlock()
	copy := s.settings
	copy.Token = ""
	copy.FingerprintKey = ""
	return copy
}

// PatchSettings 有限字段更新监控设置：enabled/巡查间隔/仓库时效/路径回溯窗口/规则。
// Token/FingerprintKey 沿用运行时现有值（HTTP 层永不提交密钥）。
// 返回更新后的 RuntimeStatus 便于前端即时刷新。
func (s *Service) PatchSettings(enabled *bool, pollIntervalSeconds, repoMaxAgeDays, lookbackDays *int, rules []Rule) (RuntimeStatus, error) {
	s.mu.Lock()
	base := s.settings
	s.mu.Unlock()
	next := base
	if enabled != nil {
		next.Enabled = *enabled
	}
	if pollIntervalSeconds != nil {
		next.PollIntervalSeconds = *pollIntervalSeconds
	}
	if repoMaxAgeDays != nil {
		next.RepoMaxAgeDays = *repoMaxAgeDays
	}
	if lookbackDays != nil {
		next.LookbackDays = *lookbackDays
	}
	if rules != nil {
		next.Rules = rules
		next.Keywords = nil // 命名规则生效时清掉 legacy 字段（Normalize 同样约定）
	}
	normalized, err := next.Normalize()
	if err != nil {
		return RuntimeStatus{}, err
	}
	normalized.Token = base.Token
	normalized.FingerprintKey = base.FingerprintKey
	if err := s.UpdateSettings(normalized); err != nil {
		return RuntimeStatus{}, err
	}
	status, err := s.RuntimeStatus(context.Background())
	if err != nil {
		return RuntimeStatus{}, err
	}
	return status, nil
}

// PatchNotifySettings 新命中通知开关（局部更新；未提供保持原值）。
func (s *Service) PatchNotifySettings(notifyEnabled *bool) (RuntimeStatus, error) {
	if notifyEnabled == nil {
		return s.RuntimeStatus(context.Background())
	}
	s.mu.Lock()
	next := s.settings
	s.mu.Unlock()
	next.NotifyEnabled = notifyEnabled
	if err := s.UpdateSettings(next); err != nil {
		return RuntimeStatus{}, err
	}
	return s.RuntimeStatus(context.Background())
}

// PatchAdvancedSettings 高级误报治理参数（boilerplate_repos/blob_rescan/
// max_blob_rescans_per_rule/extra_rules_path）；未提供的字段保持原值。
func (s *Service) PatchAdvancedSettings(boilerplateRepos *int, blobRescan *bool, maxBlobRescans *int, extraRulesPath *string) (RuntimeStatus, error) {
	s.mu.Lock()
	next := s.settings
	s.mu.Unlock()
	if boilerplateRepos != nil {
		next.BoilerplateRepos = *boilerplateRepos
	}
	if blobRescan != nil {
		next.BlobRescan = blobRescan
	}
	if maxBlobRescans != nil {
		next.MaxBlobRescansPerRule = *maxBlobRescans
	}
	if extraRulesPath != nil {
		next.ExtraRulesPath = *extraRulesPath
	}
	if err := s.UpdateSettings(next); err != nil {
		return RuntimeStatus{}, err
	}
	return s.RuntimeStatus(context.Background())
}

// AddAutoRules 组织/域名定向监控规则自动生成：按目标域名生成一组高频组合规则
// （域名命中 / 域名×password / ×secret / ×api_key / ×token / ×连接串），org
// 标识符非空时追加组织维度两条。按 Name 去重，返回新增条数与生成清单。
func (s *Service) AddAutoRules(domain, org string) ([]Rule, int, error) {
	domain = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(domain), "https://")))
	domain = strings.TrimSuffix(domain, "/")
	org = strings.ToLower(strings.TrimSpace(org))
	if domain == "" || !strings.Contains(domain, ".") || strings.ContainsAny(domain, " \t\"'") {
		return nil, 0, errors.New("domain 须为合法域名（含点号）")
	}
	s.mu.Lock()
	base := s.settings
	s.mu.Unlock()
	existing := map[string]bool{}
	for _, r := range base.Rules {
		existing[r.Name] = true
	}
	label := domain
	if org != "" {
		label = domain + "/" + org
	}
	prefix := "auto:" + label + ":"
	mk := func(suffix string, keywords ...string) Rule {
		return Rule{Enabled: true, Name: prefix + suffix, Keywords: keywords}
	}
	gen := []Rule{
		mk("域名命中", domain),
		mk("域名×password", domain, "password"),
		mk("域名×secret", domain, "secret"),
		mk("域名×api_key", domain, "api_key"),
		mk("域名×token", domain, "token"),
		mk("域名×连接串", domain, "jdbc"),
		// R6 定向模板（目标域 × 厂商凭据特征词；结果集小价值高，适合全分页）。
		mk("域名×AKIA", domain, "AKIA"),
		mk("域名×LTAI", domain, "LTAI"),
		mk("域名×AKID", domain, "AKID"),
		mk("域名×app_secret", domain, "app_secret"),
		mk("域名×数据源", domain, "spring.datasource"),
		mk("域名×private_key", domain, "private_key"),
	}
	if org != "" {
		gen = append(gen,
			mk("组织×access_key", org, "access_key"),
			mk("组织×appsecret", org, "app_secret"),
			mk("组织×token", org, "token"),
		)
	}
	// 文档 R6 的 org:filename:.env / path:.git-credentials / user:token 属于
	// GitHub 搜索限定符语法，newKeywordRule 会对关键词整体加引号导致限定符
	// 失效，无法经关键词规则表达——待查询构造支持限定符后再补。
	fresh := make([]Rule, 0, len(gen))
	for _, r := range gen {
		if !existing[r.Name] {
			fresh = append(fresh, r)
		}
	}
	if len(fresh) == 0 {
		return gen, 0, nil
	}
	next := base
	next.Rules = append(append([]Rule(nil), base.Rules...), fresh...)
	next.Keywords = nil
	normalized, err := next.Normalize()
	if err != nil {
		return nil, 0, err
	}
	if err := s.UpdateSettings(normalized); err != nil {
		return nil, 0, err
	}
	return fresh, len(fresh), nil
}
