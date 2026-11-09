package githubleak

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

type serviceTestPersistence struct {
	mu         sync.Mutex
	lock       bool
	states     map[string]KeywordState
	runs       []RunRecord
	candidates []Candidate
	finished   chan RunRecord
	// 读取口径记录（回溯窗口过滤断言用）
	lastListFilter  ListFilter
	lastStatsCutoff *time.Time
	getFinding      Finding
}

func newServiceTestPersistence() *serviceTestPersistence {
	return &serviceTestPersistence{
		lock: true, states: make(map[string]KeywordState), finished: make(chan RunRecord, 8),
	}
}

func (p *serviceTestPersistence) AcquireRunLock(context.Context) (func(), bool, error) {
	p.mu.Lock()
	locked := p.lock
	p.mu.Unlock()
	return func() {}, locked, nil
}

func (p *serviceTestPersistence) UpsertCandidates(_ context.Context, candidates []Candidate, _ time.Time) ([]Candidate, int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.candidates = append(p.candidates, candidates...)
	return candidates, 0, nil
}

func (p *serviceTestPersistence) List(_ context.Context, filter ListFilter) (ListResult, error) {
	p.mu.Lock()
	p.lastListFilter = filter
	p.mu.Unlock()
	return ListResult{}, nil
}

func (p *serviceTestPersistence) ListMissingSecret(context.Context, int) ([]Finding, error) {
	return []Finding{}, nil
}

func (p *serviceTestPersistence) UpdateSecretValue(context.Context, string, string, string) error {
	return nil
}

func (p *serviceTestPersistence) Get(context.Context, string) (Finding, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.getFinding.ID == "" {
		return Finding{}, ErrNotFound
	}
	return p.getFinding, nil
}

func (p *serviceTestPersistence) RecordVerifyResult(_ context.Context, _, _, _ string) error {
	return nil
}

func (p *serviceTestPersistence) UpdateStatus(_ context.Context, id, status string) (Finding, error) {
	if id == "" || !ValidStatus(status) {
		return Finding{}, ErrNotFound
	}
	return Finding{ID: id, Status: status}, nil
}

func (p *serviceTestPersistence) Stats(_ context.Context, sourceUpdatedAfter *time.Time) (Stats, error) {
	p.mu.Lock()
	p.lastStatsCutoff = sourceUpdatedAfter
	p.mu.Unlock()
	return Stats{}, nil
}

func (p *serviceTestPersistence) KeywordState(_ context.Context, keyword string) (KeywordState, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	state, ok := p.states[keyword]
	if !ok {
		state = KeywordState{Keyword: keyword}
	}
	return state, nil
}

func (p *serviceTestPersistence) SaveKeywordState(_ context.Context, state KeywordState) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.states[state.Keyword] = state
	return nil
}

func (p *serviceTestPersistence) BeginRun(_ context.Context, at time.Time) (RunRecord, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	run := RunRecord{ID: fmt.Sprintf("run-%d", len(p.runs)+1), Status: "running", StartedAt: at, RateRemaining: -1}
	p.runs = append(p.runs, run)
	return run, nil
}

func (p *serviceTestPersistence) FinishRun(_ context.Context, run RunRecord) error {
	p.mu.Lock()
	for i := range p.runs {
		if p.runs[i].ID == run.ID {
			p.runs[i] = run
			break
		}
	}
	p.mu.Unlock()
	select {
	case p.finished <- run:
	default:
	}
	return nil
}

func (p *serviceTestPersistence) LatestRun(context.Context) (RunRecord, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.runs) == 0 {
		return RunRecord{RateRemaining: -1}, nil
	}
	return p.runs[len(p.runs)-1], nil
}

type serviceProviderCall struct {
	keywords   []string
	etag       string
	maxResults int
	page       int
}

type serviceTestProvider struct {
	mu      sync.Mutex
	calls   []serviceProviderCall
	result  SearchResult
	err     error
	results []SearchResult
	errs    []error
	started chan struct{}
	release <-chan struct{}
	once    sync.Once
	// 路径时效校验桩：默认每次调用返回"现在"（窗口内、始终新鲜）；
	// commitTime 可固定时间，commitErrs 按调用序注入错误。
	metadataCalls []SearchItem
	commitTime    time.Time
	commitErr     error
	commitErrs    []error
	commitResults []time.Time
}

// LatestPathCommitAt 测试桩（searchProvider 接口要求）。
func (p *serviceTestProvider) LatestPathCommitAt(ctx context.Context, item SearchItem) (time.Time, error) {
	p.mu.Lock()
	callIndex := len(p.metadataCalls)
	p.metadataCalls = append(p.metadataCalls, item)
	commitTime, commitErr := p.commitTime, p.commitErr
	if callIndex < len(p.commitResults) {
		commitTime = p.commitResults[callIndex]
	}
	if callIndex < len(p.commitErrs) {
		commitErr = p.commitErrs[callIndex]
	}
	p.mu.Unlock()
	if commitErr != nil {
		return time.Time{}, commitErr
	}
	if commitTime.IsZero() {
		return time.Now().UTC(), nil
	}
	return commitTime.UTC(), nil
}

func (p *serviceTestProvider) metadataSnapshot() []SearchItem {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]SearchItem(nil), p.metadataCalls...)
}

func (p *serviceTestProvider) SearchKeywords(ctx context.Context, keywords []string, etag string, maxResults, page int) (SearchResult, error) {
	p.mu.Lock()
	callIndex := len(p.calls)
	p.calls = append(p.calls, serviceProviderCall{keywords: append([]string(nil), keywords...), etag: etag, maxResults: maxResults, page: page})
	result, err := p.result, p.err
	if callIndex < len(p.results) {
		result = p.results[callIndex]
	}
	if callIndex < len(p.errs) {
		err = p.errs[callIndex]
	}
	p.mu.Unlock()
	if p.started != nil {
		p.once.Do(func() { close(p.started) })
	}
	if p.release != nil {
		select {
		case <-ctx.Done():
			return SearchResult{}, ctx.Err()
		case <-p.release:
		}
	}
	return result, err
}

func (p *serviceTestProvider) callSnapshot() []serviceProviderCall {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]serviceProviderCall(nil), p.calls...)
}

type serviceTestDetector struct{ candidates []Candidate }

func (d serviceTestDetector) Detect(keyword string, item SearchItem) []Candidate {
	out := append([]Candidate(nil), d.candidates...)
	for i := range out {
		out[i].Keyword = keyword
		if out[i].Repository == "" {
			out[i].Repository = item.Repository
		}
		if out[i].Path == "" {
			out[i].Path = item.Path
		}
	}
	return out
}

func serviceSettings(enabled bool, keywords ...string) Settings {
	return Settings{
		Enabled: enabled, Token: "unit-test-token", FingerprintKey: "stable-unit-fingerprint-key",
		Keywords: keywords, IntervalSeconds: MinIntervalSeconds,
		RequestTimeoutSeconds: 5, PollIntervalSeconds: DefaultPollSeconds, MaxResultsPerKeyword: 25,
	}
}

// waitTimeout 测试内异步等待的上限。固定 2s 在并行全量测试/高负载机器上会被
// 调度延迟击穿(waitForServiceRun 曾因此偶发 "service run did not finish");
// WSL2/容器环境还有 CPU 配额节流,毛刺可达数秒——放宽到 30s。用例自带
// -timeout 预算时取「剩余预算 - 1s 收尾余量」与默认值的较小者,保证本等待
// 先于 go test 掐断、失败信息可读。
func waitTimeout(t *testing.T) time.Duration {
	const fallback = 30 * time.Second
	deadline, ok := t.Deadline()
	if !ok {
		return fallback
	}
	remain := time.Until(deadline) - time.Second
	if remain <= 0 || remain > fallback {
		return fallback
	}
	return remain
}

func waitForServiceRun(t *testing.T, finished <-chan RunRecord) RunRecord {
	t.Helper()
	select {
	case run := <-finished:
		return run
	case <-time.After(waitTimeout(t)):
		t.Fatal("service run did not finish")
		return RunRecord{}
	}
}

// triggerUntilAccepted 手动触发直到服务端受理。finished 记录由 execute 内部的
// persistence 投递(测试据此确认一轮跑完),而 worker 要等 execute 返回、重新拿锁
// 才清 running 标志——高负载下 goroutine 可能恰好停在两者之间,此刻 Trigger 会
// 返回 ErrBusy(「already running」,运行收尾期拒绝新触发是服务原生语义而非缺陷),
// 测试轮询到受理为止,超时按 waitTimeout。
func triggerUntilAccepted(t *testing.T, service *Service) {
	t.Helper()
	timeout := waitTimeout(t)
	deadline := time.Now().Add(timeout)
	for {
		err := service.Trigger(context.Background())
		if err == nil {
			return
		}
		if !errors.Is(err, ErrBusy) {
			t.Fatalf("trigger = %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("trigger not accepted within %v: %v", timeout, err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestServiceScheduledRunCoalescesQueuedManualTrigger(t *testing.T) {
	service := &Service{queue: make(chan struct{}, 1), queued: true}
	service.queue <- struct{}{}
	service.mu.Lock()
	manual := service.claimQueuedRunLocked(false)
	queued := service.queued
	service.mu.Unlock()
	if !manual || queued {
		t.Fatalf("coalesced trigger = manual:%v queued:%v", manual, queued)
	}
	select {
	case <-service.queue:
		t.Fatal("scheduled run left a second manual marker queued")
	default:
	}
}

func TestServiceLifecycleAndManualTriggerBypassesScheduledEnabledFlag(t *testing.T) {
	store := newServiceTestPersistence()
	provider := &serviceTestProvider{result: SearchResult{
		ETag: `"etag-1"`, RateRemaining: 19,
		Items: []SearchItem{{Repository: "owner/repo", Path: "config.env", BlobSHA: "blob", HTMLURL: "https://github.com/owner/repo/blob/main/config.env"}},
	}}
	detector := serviceTestDetector{candidates: []Candidate{{
		Line: 1, SecretType: "github_token", Confidence: "likely", Severity: "critical",
		Fingerprint: "sanitized-fingerprint", MaskedExcerpt: "token=<redacted:github_token>",
	}}}
	service, err := newService(store, serviceSettings(false, "vendor.example", "storage-service"), provider, detector, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = service.Trigger(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("trigger before Start = %v", err)
	}
	service.Start(context.Background())
	if err = service.Trigger(context.Background()); err != nil {
		service.Close()
		t.Fatalf("manual trigger for a configured disabled monitor = %v", err)
	}
	if err = service.Trigger(context.Background()); !errors.Is(err, ErrBusy) {
		service.Close()
		t.Fatalf("second trigger = %v, want busy", err)
	}
	run := waitForServiceRun(t, store.finished)
	if run.Status != "success" || run.Processed != 1 || run.Detected != 1 || run.RateRemaining != 19 {
		service.Close()
		t.Fatalf("finished run = %+v", run)
	}
	calls := provider.callSnapshot()
	if len(calls) != 1 || len(calls[0].keywords) != 2 || calls[0].keywords[0] != "storage-service" || calls[0].keywords[1] != "vendor.example" || calls[0].etag != "" || calls[0].maxResults != 25 {
		service.Close()
		t.Fatalf("provider calls = %+v", calls)
	}
	rule, ruleErr := newKeywordRule([]string{"storage-service", "vendor.example"})
	if ruleErr != nil {
		service.Close()
		t.Fatal(ruleErr)
	}
	store.mu.Lock()
	state := store.states[rule.Query]
	candidateCount := len(store.candidates)
	candidateRule := ""
	if candidateCount > 0 {
		candidateRule = store.candidates[0].Keyword
	}
	store.mu.Unlock()
	if state.LastStatus != "success" || state.ETag != `"etag-1"` || state.LastSuccessAt == nil || candidateCount != 1 || candidateRule != rule.Query {
		service.Close()
		t.Fatalf("state=%+v candidateCount=%d", state, candidateCount)
	}
	runtime, runtimeErr := service.RuntimeStatus(context.Background())
	if runtimeErr != nil || runtime.Query != rule.Query || len(runtime.Keywords) != 2 || runtime.Keywords[0] != "storage-service" {
		service.Close()
		t.Fatalf("runtime=%+v err=%v", runtime, runtimeErr)
	}
	service.Close()
	service.Close()
}

func TestServiceAppliesSettingsQueuedDuringActiveRun(t *testing.T) {
	store := newServiceTestPersistence()
	started := make(chan struct{})
	release := make(chan struct{})
	provider := &serviceTestProvider{
		started: started, release: release,
		result: SearchResult{ETag: `"old-etag"`, Items: []SearchItem{}},
	}
	service, err := newService(store, serviceSettings(false, "storage-service"), provider, serviceTestDetector{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	service.Start(context.Background())
	defer service.Close()
	if err = service.Trigger(context.Background()); err != nil {
		t.Fatalf("manual trigger = %v", err)
	}
	select {
	case <-started:
	case <-time.After(waitTimeout(t)):
		t.Fatal("provider did not start")
	}
	pending := serviceSettings(false, "vendor.example")
	pending.MaxResultsPerKeyword = 40
	if err = service.UpdateSettings(pending); err != nil {
		close(release)
		t.Fatalf("queue settings during active run = %v", err)
	}
	close(release)
	_ = waitForServiceRun(t, store.finished)

	deadline := time.Now().Add(waitTimeout(t))
	for {
		status, statusErr := service.RuntimeStatus(context.Background())
		if statusErr != nil {
			t.Fatal(statusErr)
		}
		if len(status.Keywords) == 1 && status.Keywords[0] == "vendor.example" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("pending settings were not applied: %+v", status)
		}
		time.Sleep(5 * time.Millisecond)
	}
	calls := provider.callSnapshot()
	if len(calls) != 1 || len(calls[0].keywords) != 1 || calls[0].keywords[0] != "storage-service" {
		t.Fatalf("active run did not retain its original settings snapshot: %+v", calls)
	}
}

func TestServiceIncompleteSearchClearsETagBeforeNextAttempt(t *testing.T) {
	store := newServiceTestPersistence()
	oldAttempt := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	freshnessCheckedAt := time.Now().UTC()
	rule, ruleErr := newKeywordRule([]string{"storage-service"})
	if ruleErr != nil {
		t.Fatal(ruleErr)
	}
	store.states[rule.Query] = KeywordState{Keyword: rule.Query, ETag: `"complete-etag"`, FreshnessPolicy: freshnessPolicy(DefaultLookbackDays), FreshnessCheckedAt: &freshnessCheckedAt, LastAttemptAt: &oldAttempt, LastStatus: "success"}
	provider := &serviceTestProvider{result: SearchResult{ETag: `"partial-etag"`, Incomplete: true, TotalCount: 500, Items: []SearchItem{}}}
	service, err := newService(store, serviceSettings(true, "storage-service"), provider, serviceTestDetector{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	service.execute(context.Background(), service.settings, provider, service.detector)
	run := waitForServiceRun(t, store.finished)
	store.mu.Lock()
	state := store.states[rule.Query]
	store.mu.Unlock()
	if run.Status != "partial" || state.LastStatus != "partial" || !state.Incomplete {
		t.Fatalf("run=%+v state=%+v", run, state)
	}
	if state.ETag != "" {
		t.Fatalf("incomplete response retained ETag %q", state.ETag)
	}
	service.execute(context.Background(), service.settings, provider, service.detector)
	_ = waitForServiceRun(t, store.finished)
	calls := provider.callSnapshot()
	if len(calls) != 2 || calls[0].etag != `"complete-etag"` || calls[1].etag != "" {
		t.Fatalf("ETags after partial state = %+v", calls)
	}
}

func TestServiceTruncatedSearchRotatesPagesAndStaysSuccess(t *testing.T) {
	store := newServiceTestPersistence()
	provider := &serviceTestProvider{result: SearchResult{ETag: `"truncated"`, Truncated: true, TotalCount: 200, Items: []SearchItem{}}}
	service, err := newService(store, serviceSettings(true, "storage-service"), provider, serviceTestDetector{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	service.execute(context.Background(), service.settings, provider, service.detector)
	run := waitForServiceRun(t, store.finished)
	status, err := service.RuntimeStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// 翻页模式下 truncated 是预期常态：run 不再降级 partial，Truncated 仍透出给前端。
	if run.Status != "success" || len(status.Rules) != 1 || !status.Rules[0].Truncated || status.Rules[0].Incomplete || status.Rules[0].LastStatus != "success" {
		t.Fatalf("run=%+v runtime=%+v", run, status)
	}
	store.mu.Lock()
	state := store.states[status.Rules[0].Query]
	store.mu.Unlock()
	// total=200/per=25 → 8 页：游标 1→2，旧页 ETag 作废。
	if state.ETag != "" || state.PageCursor != 2 {
		t.Fatalf("state after truncated page1 = %+v", state)
	}
	service.execute(context.Background(), service.settings, provider, service.detector)
	_ = waitForServiceRun(t, store.finished)
	calls := provider.callSnapshot()
	if len(calls) != 2 || calls[0].page != 1 || calls[1].page != 2 {
		t.Fatalf("page rotation calls = %+v", calls)
	}
}

func TestServicePageCursorWrapsAtLastReachablePage(t *testing.T) {
	store := newServiceTestPersistence()
	// total=5000/per=25 → 200 页，legacy API 仅前 maxSearchPagesPerRule 页可达。
	provider := &serviceTestProvider{result: SearchResult{ETag: `"deep"`, Truncated: true, TotalCount: 5000, Items: []SearchItem{}}}
	service, err := newService(store, serviceSettings(true, "storage-service"), provider, serviceTestDetector{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxSearchPagesPerRule+1; i++ {
		service.execute(context.Background(), service.settings, provider, service.detector)
		_ = waitForServiceRun(t, store.finished)
	}
	calls := provider.callSnapshot()
	if len(calls) != maxSearchPagesPerRule+1 {
		t.Fatalf("calls = %d", len(calls))
	}
	for i, call := range calls {
		want := i + 1
		if want > maxSearchPagesPerRule {
			want = 1 // 末页之后回卷到首页，滚动覆盖可达结果
		}
		if call.page != want {
			t.Fatalf("call[%d].page = %d, want %d", i, call.page, want)
		}
	}
}

func TestServiceSinglePageRuleKeepsEtagAndPinnedPage(t *testing.T) {
	store := newServiceTestPersistence()
	provider := &serviceTestProvider{result: SearchResult{ETag: `"single"`, TotalCount: 20, Items: []SearchItem{}}}
	service, err := newService(store, serviceSettings(true, "storage-service"), provider, serviceTestDetector{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	service.execute(context.Background(), service.settings, provider, service.detector)
	run := waitForServiceRun(t, store.finished)
	status, err := service.RuntimeStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	state := store.states[status.Rules[0].Query]
	store.mu.Unlock()
	// total≤单页：无翻页，304 快路径的 ETag 保留、游标停驻首页。
	if run.Status != "success" || state.ETag != `"single"` || state.PageCursor != 1 {
		t.Fatalf("run=%+v state=%+v", run, state)
	}
}

func TestServiceCanonicalRuleReusesStateAcrossKeywordOrder(t *testing.T) {
	store := newServiceTestPersistence()
	provider := &serviceTestProvider{result: SearchResult{ETag: `"combined-etag"`, Items: []SearchItem{}}}
	settings := serviceSettings(false, "vendor.example", "storage-service", "storage-service")
	service, err := newService(store, settings, provider, serviceTestDetector{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	service.execute(context.Background(), settings, provider, service.detector)
	_ = waitForServiceRun(t, store.finished)
	reordered := serviceSettings(false, "storage-service", "vendor.example")
	service.execute(context.Background(), reordered, provider, service.detector)
	_ = waitForServiceRun(t, store.finished)
	calls := provider.callSnapshot()
	if len(calls) != 2 || calls[0].etag != "" || calls[1].etag != `"combined-etag"` {
		t.Fatalf("combined query ETag calls = %+v", calls)
	}
	store.mu.Lock()
	stateCount := len(store.states)
	store.mu.Unlock()
	if stateCount != 1 {
		t.Fatalf("keyword reordering created %d state rows, want 1", stateCount)
	}
}

func TestServiceExecutesEnabledNamedRulesSeriallyAndAggregatesRunStats(t *testing.T) {
	store := newServiceTestPersistence()
	provider := &serviceTestProvider{results: []SearchResult{
		{ETag: `"example-corp"`, RateRemaining: 9, Items: []SearchItem{{Repository: "owner/one", Path: "one.env"}}},
		{ETag: `"access"`, RateRemaining: 8, Items: []SearchItem{{Repository: "owner/two", Path: "two.env"}, {Repository: "owner/three", Path: "three.env"}}},
	}}
	detector := serviceTestDetector{candidates: []Candidate{{
		SecretType: "generic_secret_assignment", Confidence: "suspected", Severity: "medium",
		Fingerprint: "sanitized-fingerprint", MaskedExcerpt: "value=<redacted>",
	}}}
	settings := serviceSettings(false)
	settings.Keywords = []string{"legacy.example", "hidden"}
	settings.Rules = []Rule{
		{Enabled: true, Name: "example-corp-clientid", Keywords: []string{"vendor.example", "clientid"}},
		{Enabled: false, Name: "disabled", Keywords: []string{"disabled.example", "secret"}},
		{Enabled: true, Name: "access-key", Keywords: []string{"example.com", "ACCESSKEY"}},
	}
	service, err := newService(store, settings, provider, detector, nil)
	if err != nil {
		t.Fatal(err)
	}
	service.execute(context.Background(), service.settings, provider, service.detector)
	run := waitForServiceRun(t, store.finished)
	// Requests 计 search + 路径时效元数据：2 次搜索 + 3 个命中条目各 1 次提交时间查询。
	if run.Status != "success" || run.Requests != 5 || run.Processed != 3 || run.Detected != 3 || run.RateRemaining != 8 {
		t.Fatalf("aggregated run = %+v", run)
	}
	calls := provider.callSnapshot()
	if len(calls) != 2 || calls[0].keywords[0] != "clientid" || calls[1].keywords[0] != "ACCESSKEY" {
		t.Fatalf("ordered provider calls = %+v", calls)
	}
	store.mu.Lock()
	ruleNames := make([]string, 0, len(store.candidates))
	for _, candidate := range store.candidates {
		ruleNames = append(ruleNames, candidate.RuleName)
	}
	store.mu.Unlock()
	if fmt.Sprint(ruleNames) != "[example-corp-clientid access-key access-key]" {
		t.Fatalf("candidate rule names = %v", ruleNames)
	}
	runtime, err := service.RuntimeStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(runtime.Rules) != 3 || runtime.Rules[0].Name != "example-corp-clientid" || runtime.Rules[0].Query != `"clientid" AND "vendor.example" in:file` ||
		runtime.Rules[1].Enabled || runtime.Rules[2].Name != "access-key" || runtime.RequestIntervalSeconds != MinIntervalSeconds ||
		runtime.LastRequests != 5 || runtime.LastProcessed != 3 || runtime.LastDetected != 3 || runtime.LookbackDays != DefaultLookbackDays {
		t.Fatalf("runtime named rule status = %+v", runtime)
	}
	if len(runtime.Keywords) != 2 || runtime.Query != runtime.Rules[0].Query {
		t.Fatalf("legacy runtime fallback fields = %+v", runtime)
	}
}

func TestServiceContinuesAfterOrdinaryRuleErrorButStopsOnRateLimit(t *testing.T) {
	rules := []Rule{
		{Enabled: true, Name: "first", Keywords: []string{"first.example", "clientid"}},
		{Enabled: true, Name: "second", Keywords: []string{"second.example", "accesskey"}},
	}
	t.Run("ordinary error continues", func(t *testing.T) {
		store := newServiceTestPersistence()
		provider := &serviceTestProvider{
			results: []SearchResult{{}, {ETag: `"second"`, Items: []SearchItem{{Repository: "owner/repo", Path: "config.env"}}}},
			errs:    []error{errors.New("synthetic network failure"), nil},
		}
		settings := serviceSettings(false)
		settings.Rules = rules
		service, err := newService(store, settings, provider, serviceTestDetector{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		service.execute(context.Background(), service.settings, provider, service.detector)
		run := waitForServiceRun(t, store.finished)
		if run.Status != "partial" || run.Requests != 2 || len(provider.callSnapshot()) != 2 {
			t.Fatalf("ordinary-error run = %+v calls=%+v", run, provider.callSnapshot())
		}
		status, statusErr := service.RuntimeStatus(context.Background())
		if statusErr != nil || status.LastError != "" || status.LastWarning == "" {
			t.Fatalf("partial error runtime = %+v err=%v", status, statusErr)
		}
	})

	t.Run("all rule errors remain errors", func(t *testing.T) {
		store := newServiceTestPersistence()
		provider := &serviceTestProvider{errs: []error{
			errors.New("synthetic first failure"), errors.New("synthetic second failure"),
		}}
		settings := serviceSettings(false)
		settings.Rules = rules
		service, err := newService(store, settings, provider, serviceTestDetector{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		service.execute(context.Background(), service.settings, provider, service.detector)
		run := waitForServiceRun(t, store.finished)
		status, statusErr := service.RuntimeStatus(context.Background())
		if run.Status != "error" || statusErr != nil || status.LastError == "" || status.LastWarning != "" {
			t.Fatalf("failed run=%+v runtime=%+v err=%v", run, status, statusErr)
		}
	})

	t.Run("rate limit stops", func(t *testing.T) {
		store := newServiceTestPersistence()
		reset := time.Now().UTC().Add(time.Minute)
		provider := &serviceTestProvider{errs: []error{&HTTPStatusError{StatusCode: 403, RateLimited: true, Retryable: true, RateReset: &reset}}}
		settings := serviceSettings(false)
		settings.Rules = rules
		service, err := newService(store, settings, provider, serviceTestDetector{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		service.execute(context.Background(), service.settings, provider, service.detector)
		run := waitForServiceRun(t, store.finished)
		if run.Status != "rate_limited" || run.Requests != 1 || len(provider.callSnapshot()) != 1 || run.RateResetAt == nil {
			t.Fatalf("rate-limited run = %+v calls=%+v", run, provider.callSnapshot())
		}
		status, statusErr := service.RuntimeStatus(context.Background())
		if statusErr != nil || status.LastError == "" || status.LastWarning != "" {
			t.Fatalf("rate-limited runtime = %+v err=%v", status, statusErr)
		}
	})

	t.Run("authentication failure stops remaining rules", func(t *testing.T) {
		store := newServiceTestPersistence()
		provider := &serviceTestProvider{errs: []error{
			&HTTPStatusError{StatusCode: 401, Retryable: false}, nil,
		}}
		settings := serviceSettings(false)
		settings.Rules = rules
		service, err := newService(store, settings, provider, serviceTestDetector{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		service.execute(context.Background(), service.settings, provider, service.detector)
		run := waitForServiceRun(t, store.finished)
		if run.Status != "error" || run.Requests != 1 || len(provider.callSnapshot()) != 1 ||
			!strings.Contains(strings.ToLower(run.Error), "authentication") {
			t.Fatalf("authentication-failure run = %+v calls=%+v", run, provider.callSnapshot())
		}
	})
}

func TestRunTimeoutScalesWithEnabledRuleCount(t *testing.T) {
	settings := serviceSettings(true)
	settings.IntervalSeconds = 60
	settings.RequestTimeoutSeconds = 45
	if got := runTimeoutForRules(settings, MaxRules); got < 61*time.Minute {
		t.Fatalf("32-rule timeout = %s, want at least 61m", got)
	}
	if got := runTimeoutForRules(settings, 1); got != 30*time.Minute {
		t.Fatalf("single-rule timeout = %s, want 30m", got)
	}
}

// ── 路径时效校验（freshness）：命中后按文件最近提交时间过滤陈旧代码 ──

func freshnessSettings() Settings {
	settings := serviceSettings(true)
	settings.Rules = []Rule{{Enabled: true, Name: "main", Keywords: []string{"storage-service"}}}
	return settings
}

func freshnessItem(path string) SearchItem {
	return SearchItem{
		Repository: "owner/repo", RepoNodeID: "node-" + path, Path: path, BlobSHA: strings.Repeat("a", 40),
		HTMLURL: "https://github.com/owner/repo/blob/main/" + path,
	}
}

func freshnessDetector() serviceTestDetector {
	return serviceTestDetector{candidates: []Candidate{{
		SecretType: "generic_secret_assignment", Confidence: "suspected", Severity: "medium",
		Fingerprint: strings.Repeat("e", 64), MaskedExcerpt: "value=<redacted>",
	}}}
}

func TestServiceDropsCandidatesOutsideLookbackWindow(t *testing.T) {
	store := newServiceTestPersistence()
	provider := &serviceTestProvider{
		result:     SearchResult{ETag: `"fresh"`, Items: []SearchItem{freshnessItem("old.env")}},
		commitTime: time.Now().UTC().AddDate(0, 0, -400), // 默认窗口 365 天之外
	}
	service, err := newService(store, freshnessSettings(), provider, freshnessDetector(), nil)
	if err != nil {
		t.Fatal(err)
	}
	service.execute(context.Background(), service.settings, provider, service.detector)
	run := waitForServiceRun(t, store.finished)
	if run.Status != "success" || run.Detected != 0 {
		t.Fatalf("stale-path run = %+v", run)
	}
	store.mu.Lock()
	stored := len(store.candidates)
	store.mu.Unlock()
	if stored != 0 {
		t.Fatalf("stale path candidates stored = %d, want 0", stored)
	}
	if got := len(provider.metadataSnapshot()); got != 1 {
		t.Fatalf("metadata calls = %d, want 1", got)
	}
}

func TestServiceKeepsFreshCandidatesAndRecordsSourceUpdatedAt(t *testing.T) {
	store := newServiceTestPersistence()
	commitAt := time.Now().UTC().Add(-30 * 24 * time.Hour).Truncate(time.Second)
	provider := &serviceTestProvider{
		result:     SearchResult{ETag: `"fresh"`, Items: []SearchItem{freshnessItem("config.env")}},
		commitTime: commitAt,
	}
	service, err := newService(store, freshnessSettings(), provider, freshnessDetector(), nil)
	if err != nil {
		t.Fatal(err)
	}
	service.execute(context.Background(), service.settings, provider, service.detector)
	run := waitForServiceRun(t, store.finished)
	if run.Status != "success" || run.Detected != 1 || run.Requests != 2 { // 1 搜索 + 1 元数据
		t.Fatalf("fresh-path run = %+v", run)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.candidates) != 1 {
		t.Fatalf("stored candidates = %d, want 1", len(store.candidates))
	}
	if !store.candidates[0].SourceUpdatedAt.Equal(commitAt) {
		t.Fatalf("source updated at = %s, want %s", store.candidates[0].SourceUpdatedAt, commitAt)
	}
}

func TestServiceMetadataRateLimitStopsRun(t *testing.T) {
	store := newServiceTestPersistence()
	provider := &serviceTestProvider{
		result:    SearchResult{ETag: `"fresh"`, Items: []SearchItem{freshnessItem("config.env")}},
		commitErr: &HTTPStatusError{StatusCode: 403, Retryable: true, RateLimited: true},
	}
	service, err := newService(store, freshnessSettings(), provider, freshnessDetector(), nil)
	if err != nil {
		t.Fatal(err)
	}
	service.execute(context.Background(), service.settings, provider, service.detector)
	run := waitForServiceRun(t, store.finished)
	if run.Status != "rate_limited" || !strings.Contains(run.Error, "metadata") {
		t.Fatalf("metadata rate-limited run = %+v", run)
	}
	store.mu.Lock()
	stored := len(store.candidates)
	store.mu.Unlock()
	if stored != 0 {
		t.Fatalf("candidates stored on metadata rate limit = %d, want 0", stored)
	}
}

func TestServiceItemLocalMetadataErrorSkipsOnlyThatItem(t *testing.T) {
	store := newServiceTestPersistence()
	provider := &serviceTestProvider{
		result:     SearchResult{ETag: `"fresh"`, Items: []SearchItem{freshnessItem("deleted.env"), freshnessItem("live.env")}},
		commitErrs: []error{errPathCommitUnavailable, nil},
	}
	service, err := newService(store, freshnessSettings(), provider, freshnessDetector(), nil)
	if err != nil {
		t.Fatal(err)
	}
	service.execute(context.Background(), service.settings, provider, service.detector)
	run := waitForServiceRun(t, store.finished)
	// 单项元数据错误（索引残留路径）本轮记为 partial，但只跳过该项，其余命中正常入库。
	if run.Status != "partial" || run.Detected != 1 {
		t.Fatalf("item-local metadata run = %+v", run)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.candidates) != 1 || store.candidates[0].Path != "live.env" {
		t.Fatalf("stored candidates = %+v, want only live.env", store.candidates)
	}
	if got := len(provider.metadataSnapshot()); got != 2 {
		t.Fatalf("metadata calls = %d, want 2", got)
	}
}

func TestServiceFreshnessBudgetRotatesCursorAcrossRuns(t *testing.T) {
	store := newServiceTestPersistence()
	items := make([]SearchItem, 0, maxFreshnessChecksPerRun+1)
	for i := 0; i <= maxFreshnessChecksPerRun; i++ {
		items = append(items, freshnessItem(fmt.Sprintf("p%03d.env", i)))
	}
	provider := &serviceTestProvider{result: SearchResult{ETag: `"budget"`, Items: items}}
	settings := freshnessSettings()
	service, err := newService(store, settings, provider, freshnessDetector(), nil)
	if err != nil {
		t.Fatal(err)
	}
	rule, err := newKeywordRule([]string{"storage-service"})
	if err != nil {
		t.Fatal(err)
	}

	service.execute(context.Background(), service.settings, provider, service.detector)
	first := waitForServiceRun(t, store.finished)
	if first.Status != "partial" || first.Processed != maxFreshnessChecksPerRun {
		t.Fatalf("budget-limited run = %+v", first)
	}
	if got := len(provider.metadataSnapshot()); got != maxFreshnessChecksPerRun {
		t.Fatalf("first-run metadata calls = %d, want %d", got, maxFreshnessChecksPerRun)
	}
	store.mu.Lock()
	state := store.states[rule.Query]
	store.mu.Unlock()
	if state.FreshnessCursor != maxFreshnessChecksPerRun || state.ETag != "" || state.FreshnessCursorETag != `"budget"` {
		t.Fatalf("budget-limited state = cursor:%d etag:%q cursorETag:%q", state.FreshnessCursor, state.ETag, state.FreshnessCursorETag)
	}

	// 快照未变（ETag 相同）→ 第二轮从游标处继续（轮转起点），而不是总从头部重来。
	service.execute(context.Background(), service.settings, provider, service.detector)
	second := waitForServiceRun(t, store.finished)
	if second.Status != "partial" || second.Processed != maxFreshnessChecksPerRun {
		t.Fatalf("cursor-rotation run = %+v", second)
	}
	metadata := provider.metadataSnapshot()
	if len(metadata) != 2*maxFreshnessChecksPerRun {
		t.Fatalf("metadata calls after two runs = %d, want %d", len(metadata), 2*maxFreshnessChecksPerRun)
	}
	if metadata[maxFreshnessChecksPerRun].Path != fmt.Sprintf("p%03d.env", maxFreshnessChecksPerRun) {
		t.Fatalf("second run started at %q, want rotated cursor p%03d.env", metadata[maxFreshnessChecksPerRun].Path, maxFreshnessChecksPerRun)
	}
	// 快照变化（ETag 不同）→ 游标失效，从头部重新校验。
	provider.mu.Lock()
	provider.result.ETag = `"budget-v2"`
	provider.mu.Unlock()
	service.execute(context.Background(), service.settings, provider, service.detector)
	_ = waitForServiceRun(t, store.finished)
	metadata = provider.metadataSnapshot()
	if metadata[2*maxFreshnessChecksPerRun].Path != "p000.env" {
		t.Fatalf("changed snapshot did not reset cursor: first new call %q", metadata[2*maxFreshnessChecksPerRun].Path)
	}
}

// 读取口径与回溯窗口一致：列表/统计注入窗口起点；详情与状态更新对窗口外
// 历史命中返回不存在；存量 NULL 行（本特性上线前入库）保守放行。
func TestServiceReadPathsApplyLookbackCutoff(t *testing.T) {
	store := newServiceTestPersistence()
	service, err := newService(store, freshnessSettings(), &serviceTestProvider{}, serviceTestDetector{}, nil)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := service.List(context.Background(), ListFilter{}); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	filter := store.lastListFilter
	store.mu.Unlock()
	if filter.SourceUpdatedAfter == nil {
		t.Fatal("list 未注入回溯窗口")
	}
	wantCutoff := time.Now().UTC().AddDate(0, 0, -DefaultLookbackDays)
	if diff := filter.SourceUpdatedAfter.Sub(wantCutoff); diff < -time.Minute || diff > time.Minute {
		t.Fatalf("list cutoff = %s, want ≈%s", filter.SourceUpdatedAfter, wantCutoff)
	}

	if _, err := service.Stats(context.Background()); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	statsCutoff := store.lastStatsCutoff
	store.mu.Unlock()
	if statsCutoff == nil {
		t.Fatal("stats 未注入回溯窗口")
	}

	inWindow := time.Now().UTC().AddDate(0, 0, -10)
	outdated := time.Now().UTC().AddDate(0, 0, -400)
	store.mu.Lock()
	store.getFinding = Finding{ID: "f-in", Status: "new", SourceUpdatedAt: &inWindow}
	store.mu.Unlock()
	if _, err := service.Get(context.Background(), "f-in"); err != nil {
		t.Fatalf("窗口内详情被拒: %v", err)
	}
	store.mu.Lock()
	store.getFinding = Finding{ID: "f-out", Status: "new", SourceUpdatedAt: &outdated}
	store.mu.Unlock()
	if _, err := service.Get(context.Background(), "f-out"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("窗口外详情 err = %v, want ErrNotFound", err)
	}
	if _, err := service.UpdateStatus(context.Background(), "f-out", "false_positive"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("窗口外状态更新 err = %v, want ErrNotFound", err)
	}
	store.mu.Lock()
	store.getFinding = Finding{ID: "f-null", Status: "new"}
	store.mu.Unlock()
	if _, err := service.Get(context.Background(), "f-null"); err != nil {
		t.Fatalf("存量 NULL 行应可见: %v", err)
	}
}

// 新命中 IM 通知（docs 方案 §通知链路）：命中入库 → 聚合一条事件广播；
// 开关关闭后不再发布。fake persistence 对同一候选恒返回"新增"，
// 这里只验证服务层聚合/开关语义，指纹去重语义由 store 层测试覆盖。
func TestServiceNotifiesNewFindingsAndRespectsSwitch(t *testing.T) {
	store := newServiceTestPersistence()
	provider := &serviceTestProvider{result: SearchResult{
		ETag: `"etag-1"`, RateRemaining: 19,
		Items: []SearchItem{{Repository: "owner/repo", Path: "config.env", BlobSHA: "blob", HTMLURL: "https://github.com/owner/repo/blob/main/config.env"}},
	}}
	detector := serviceTestDetector{candidates: []Candidate{{
		Line: 1, SecretType: "github_token", Confidence: "likely", Severity: "critical",
		Fingerprint: "sanitized-fingerprint", MaskedExcerpt: "token=<redacted:github_token>",
	}}}
	service, err := newService(store, serviceSettings(false, "storage-service"), provider, detector, nil)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var events []Event
	service.SetNotify(func(ev Event) {
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
	})
	if err = service.Trigger(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("trigger before Start = %v", err)
	}
	service.Start(context.Background())
	if err = service.Trigger(context.Background()); err != nil {
		service.Close()
		t.Fatalf("trigger = %v", err)
	}
	run := waitForServiceRun(t, store.finished)
	if run.Status != "success" {
		service.Close()
		t.Fatalf("run = %+v", run)
	}
	// 等异步通知落地（execute 在 run Finish 后发布）
	deadline := time.Now().Add(waitTimeout(t))
	for {
		mu.Lock()
		n := len(events)
		mu.Unlock()
		if n > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	mu.Lock()
	got := append([]Event(nil), events...)
	mu.Unlock()
	if len(got) != 1 {
		service.Close()
		t.Fatalf("events = %d, want 1", len(got))
	}
	ev := got[0]
	if ev.Kind != KindGithubLeakFound || !ev.Broadcast || len(ev.Items) != 1 ||
		ev.Items[0].Text != "owner/repo · github_token" || ev.DedupKey == "" {
		service.Close()
		t.Fatalf("event = %+v", ev)
	}
	runtime, runtimeErr := service.RuntimeStatus(context.Background())
	if runtimeErr != nil || !runtime.NotifyEnabled {
		service.Close()
		t.Fatalf("runtime notify_enabled = %+v err=%v", runtime, runtimeErr)
	}
	// 关闭开关后不再发布
	off := false
	if _, err = service.PatchNotifySettings(&off); err != nil {
		service.Close()
		t.Fatalf("patch notify = %v", err)
	}
	triggerUntilAccepted(t, service)
	waitForServiceRun(t, store.finished)
	time.Sleep(150 * time.Millisecond)
	mu.Lock()
	n := len(events)
	mu.Unlock()
	if n != 1 {
		service.Close()
		t.Fatalf("events after switch off = %d, want 1", n)
	}
	service.Close()
}
