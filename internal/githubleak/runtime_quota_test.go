package githubleak

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/internal/lz"
)

// runtime_quota_test.go — R5 配额可见化与 R8 值级频次抑制的回归
// （docs/GitHub敏感信息监控改进建议.md R5-1/R5-2/R8 闸门三）。

// R5-1：Client.SearchQuota 解析 /rate_limit 的 search 桶（不计入配额）。
func TestClientSearchQuotaParsesSearchBucket(t *testing.T) {
	reset := time.Now().Add(30 * time.Minute).UTC().Truncate(time.Second)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rate_limit" {
			t.Errorf("request path = %q, want /rate_limit", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer unit-test-token" {
			t.Errorf("Authorization header was not set")
		}
		_, _ = fmt.Fprintf(w, `{"resources":{"core":{"limit":5000,"remaining":4999,"reset":%d},"search":{"limit":30,"remaining":17,"reset":%d}}}`,
			reset.Unix(), reset.Unix())
	}))
	defer server.Close()

	client := providerClientForServer(t, server, newProviderTestClock())
	quota, err := client.SearchQuota(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if quota.Remaining != 17 || quota.Limit != 30 {
		t.Fatalf("search quota = %+v, want remaining 17 / limit 30", quota)
	}
	if quota.ResetAt == nil || !quota.ResetAt.Equal(reset) {
		t.Fatalf("search reset = %v, want %v", quota.ResetAt, reset)
	}
}

// R5-1：RuntimeStatus 在配置就绪且空闲时探测实时配额，TTL 内复用缓存（不放大请求）。
func TestRuntimeStatusProbesSearchQuotaWithCache(t *testing.T) {
	var probes atomic.Int64
	provider := &quotaProbingProvider{probes: &probes, quota: SearchQuota{Remaining: 11, Limit: 30}}
	store := newServiceTestPersistence()
	service, err := newService(store, serviceSettings(true, "storage-service"), provider, serviceTestDetector{}, lz.NewNop())
	if err != nil {
		t.Fatal(err)
	}

	status, err := service.RuntimeStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.SearchQuotaRemaining != 11 || status.SearchQuotaLimit != 30 {
		t.Fatalf("first probe quota = %d/%d, want 11/30", status.SearchQuotaRemaining, status.SearchQuotaLimit)
	}
	if status.SearchQuotaCheckedAt == nil {
		t.Fatal("SearchQuotaCheckedAt was not set")
	}
	// TTL 内第二次调用不触发新探测
	if _, err = service.RuntimeStatus(context.Background()); err != nil {
		t.Fatal(err)
	}
	if probes.Load() != 1 {
		t.Fatalf("probe calls = %d, want 1 (cache TTL)", probes.Load())
	}
}

// R5-1：探测失败时 Remaining 回退 -1（以最近一轮 run 的响应头为准），不影响 Runtime。
func TestRuntimeStatusQuotaProbeFailureFallsBack(t *testing.T) {
	provider := &quotaProbingProvider{err: errors.New("synthetic probe failure")}
	store := newServiceTestPersistence()
	service, err := newService(store, serviceSettings(true, "storage-service"), provider, serviceTestDetector{}, lz.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	status, err := service.RuntimeStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.SearchQuotaRemaining != -1 {
		t.Fatalf("quota remaining = %d, want -1 on probe failure", status.SearchQuotaRemaining)
	}
}

// R5-2：RuleStatus 暴露跨轮翻页游标。
func TestRuntimeStatusExposesRulePageCursor(t *testing.T) {
	store := newServiceTestPersistence()
	settings := serviceSettings(true, "storage-service")
	rule := Rule{Enabled: true, Name: "cursor-rule", Keywords: []string{"storage-service"}}
	settings.Rules = []Rule{rule}
	settings.Keywords = nil
	service, err := newService(store, settings, &quotaProbingProvider{}, serviceTestDetector{}, lz.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := newKeywordRule(rule.Keywords)
	if err != nil {
		t.Fatal(err)
	}
	state := KeywordState{Keyword: compiled.Query, PageCursor: 4, Truncated: true}
	if err := store.SaveKeywordState(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	status, err := service.RuntimeStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(status.Rules) != 1 || status.Rules[0].PageCursor != 4 {
		t.Fatalf("rule status = %+v, want page_cursor 4", status.Rules)
	}
}

// R8 闸门三：同一密钥值跨 ≥N 仓库 → likely 降级 suspected、suspected 丢弃；
// 无风暴的候选不受影响。
func TestFilterValueStormDowngradesAndDrops(t *testing.T) {
	service := &Service{logger: lz.NewNop()}
	sharedFingerprint := "fp-shared-value"
	uniqueFingerprint := "fp-unique-value"
	candidates := []Candidate{
		{Repository: "a/one", SecretType: "aws_access_key_id", Fingerprint: sharedFingerprint, Confidence: "likely"},
		{Repository: "b/two", SecretType: "aws_access_key_id", Fingerprint: sharedFingerprint, Confidence: "likely"},
		{Repository: "c/three", SecretType: "aws_access_key_id", Fingerprint: sharedFingerprint, Confidence: "likely"},
		{Repository: "d/four", SecretType: "aws_access_key_id", Fingerprint: sharedFingerprint, Confidence: "likely"},
		{Repository: "e/five", SecretType: "aws_access_key_id", Fingerprint: sharedFingerprint, Confidence: "likely"},
		{Repository: "f/six", SecretType: "aws_access_key_id", Fingerprint: sharedFingerprint, Confidence: "suspected"},
		{Repository: "g/unique", SecretType: "aws_access_key_id", Fingerprint: uniqueFingerprint, Confidence: "likely"},
	}
	kept, dropped := service.filterValueStorm("rule", candidates, 5)
	if dropped != 1 {
		t.Fatalf("dropped = %d, want 1 (single suspected in storm)", dropped)
	}
	likelyCount, stormKept := 0, 0
	for _, c := range kept {
		if c.Fingerprint == sharedFingerprint {
			stormKept++
			if c.Confidence != "suspected" {
				t.Fatalf("storm candidate from %s kept as %s, want downgraded suspected", c.Repository, c.Confidence)
			}
		}
		if c.Fingerprint == uniqueFingerprint && c.Confidence == "likely" {
			likelyCount++
		}
	}
	if stormKept != 5 {
		t.Fatalf("storm likely kept = %d, want 5 (downgraded, not dropped)", stormKept)
	}
	if likelyCount != 1 {
		t.Fatalf("unique candidate missing or downgraded: %d", likelyCount)
	}
}

// quotaProbingProvider 复用 serviceTestProvider（满足 searchProvider），
// 附加 SearchQuota 探测计数。
type quotaProbingProvider struct {
	serviceTestProvider
	probes *atomic.Int64
	quota  SearchQuota
	err    error
}

func (p *quotaProbingProvider) SearchQuota(context.Context) (SearchQuota, error) {
	if p.probes != nil {
		p.probes.Add(1)
	}
	return p.quota, p.err
}
