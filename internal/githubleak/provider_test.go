package githubleak

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type providerTestClock struct {
	mu    sync.Mutex
	now   time.Time
	waits []time.Duration
}

func newProviderTestClock() *providerTestClock {
	return &providerTestClock{now: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)}
}

func (c *providerTestClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *providerTestClock) Wait(ctx context.Context, delay time.Duration) error {
	if ctx != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if delay > 0 {
		c.waits = append(c.waits, delay)
		c.now = c.now.Add(delay)
	}
	return nil
}

func (c *providerTestClock) advance(delay time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(delay)
	c.mu.Unlock()
}

func providerClientForServer(t *testing.T, server *httptest.Server, clock timeSource) *Client {
	t.Helper()
	client, err := NewClient(Settings{
		Token:                 "unit-test-token",
		Keywords:              []string{"storage-service"},
		IntervalSeconds:       MinIntervalSeconds,
		RequestTimeoutSeconds: 5,
	}, withBaseURL(server.URL), withTimeSource(clock))
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestProviderExactLiteralQueryAndRequiredHeaders(t *testing.T) {
	clock := newProviderTestClock()
	keyword := `vendor.example org:evil`
	wantQuery := `"vendor.example org:evil" in:file`
	reset := clock.Now().Add(2 * time.Minute)
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodGet || r.URL.Path != "/search/code" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.URL.Query().Get("q"); got != wantQuery {
			t.Errorf("q = %q, want %q", got, wantQuery)
		}
		if r.URL.Query().Get("per_page") != "30" || r.URL.Query().Get("page") != "1" {
			t.Errorf("pagination query = %q", r.URL.RawQuery)
		}
		if got := r.Header.Get("X-GitHub-Api-Version"); got != "2026-03-10" {
			t.Errorf("API version = %q", got)
		}
		if got := r.Header.Get("Accept"); got != "application/vnd.github.text-match+json" {
			t.Errorf("Accept = %q", got)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer unit-test-token" {
			t.Errorf("Authorization header was not set on the approved origin")
		}
		w.Header().Set("ETag", `"search-v1"`)
		w.Header().Set("X-RateLimit-Remaining", "27")
		w.Header().Set("X-RateLimit-Reset", fmt.Sprint(reset.Unix()))
		_, _ = fmt.Fprint(w, `{"total_count":1,"incomplete_results":false,"items":[{"path":"config.env","sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","html_url":"https://github.com/owner/repo/blob/main/config.env","repository":{"full_name":"owner/repo","node_id":"R_unit","private":false,"visibility":"public"},"text_matches":[{"fragment":"ordinary fixture"}]}]}`)
	}))
	defer server.Close()

	result, err := providerClientForServer(t, server, clock).Search(context.Background(), keyword, "", 30)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || result.ETag != `"search-v1"` || result.TotalCount != 1 || len(result.Items) != 1 {
		t.Fatalf("calls=%d result=%+v", calls, result)
	}
	if result.RateRemaining != 27 || result.RateResetAt == nil || !result.RateResetAt.Equal(reset) {
		t.Fatalf("rate metadata = remaining:%d reset:%v", result.RateRemaining, result.RateResetAt)
	}
}

func TestProviderAcceptsOnlyExplicitlyPublicRepositories(t *testing.T) {
	clock := newProviderTestClock()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"total_count":4,"incomplete_results":false,"items":[
{"path":"public.env","sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","html_url":"https://github.com/owner/public/blob/main/public.env","repository":{"full_name":"owner/public","node_id":"R_public","private":false,"visibility":"public"}},
{"path":"private.env","sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","html_url":"https://github.com/owner/private/blob/main/private.env","repository":{"full_name":"owner/private","node_id":"R_private","private":true,"visibility":"private"}},
{"path":"missing.env","sha":"cccccccccccccccccccccccccccccccccccccccc","html_url":"https://github.com/owner/missing/blob/main/missing.env","repository":{"full_name":"owner/missing","node_id":"R_missing","visibility":"public"}},
{"path":"internal.env","sha":"dddddddddddddddddddddddddddddddddddddddd","html_url":"https://github.com/owner/internal/blob/main/internal.env","repository":{"full_name":"owner/internal","node_id":"R_internal","private":false,"visibility":"internal"}}
]}`)
	}))
	defer server.Close()

	result, err := providerClientForServer(t, server, clock).Search(context.Background(), "storage-service", "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Items) != 1 || result.Items[0].Repository != "owner/public" {
		t.Fatalf("public-only items = %+v", result.Items)
	}
	if !result.Truncated || result.Incomplete {
		t.Fatalf("visibility filtering must be reported as truncated, got %+v", result)
	}
}

func TestProviderMarksClientSideResultCapAsTruncated(t *testing.T) {
	clock := newProviderTestClock()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"total_count":2,"incomplete_results":false,"items":[
{"path":"one.env","sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","html_url":"https://github.com/owner/repo/blob/main/one.env","repository":{"full_name":"owner/repo","node_id":"R_one","private":false}},
{"path":"two.env","sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","html_url":"https://github.com/owner/repo/blob/main/two.env","repository":{"full_name":"owner/repo","node_id":"R_two","private":false}}
]}`)
	}))
	defer server.Close()
	result, err := providerClientForServer(t, server, clock).Search(context.Background(), "storage-service", "", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Items) != 1 || !result.Truncated || result.Incomplete {
		t.Fatalf("capped result = %+v", result)
	}
}

func TestProviderCombinesKeywordsIntoOneANDSearch(t *testing.T) {
	clock := newProviderTestClock()
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if got, want := r.URL.Query().Get("q"), `"storage-service" AND "vendor.example" in:file`; got != want {
			t.Errorf("q = %q, want %q", got, want)
		}
		_, _ = fmt.Fprint(w, `{"total_count":0,"incomplete_results":false,"items":[]}`)
	}))
	defer server.Close()

	result, err := providerClientForServer(t, server, clock).SearchKeywords(context.Background(), []string{"vendor.example", "storage-service"}, "", 30, 1)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || result.TotalCount != 0 {
		t.Fatalf("calls=%d result=%+v", calls, result)
	}
}

func TestProviderETagNotModifiedAndIncompletePropagation(t *testing.T) {
	t.Run("not modified keeps prior etag", func(t *testing.T) {
		clock := newProviderTestClock()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if got := r.Header.Get("If-None-Match"); got != `"prior"` {
				t.Errorf("If-None-Match = %q", got)
			}
			w.WriteHeader(http.StatusNotModified)
		}))
		defer server.Close()
		result, err := providerClientForServer(t, server, clock).Search(context.Background(), "storage-service", `"prior"`, 10)
		if err != nil {
			t.Fatal(err)
		}
		if !result.NotModified || result.ETag != `"prior"` || len(result.Items) != 0 {
			t.Fatalf("304 result = %+v", result)
		}
	})

	t.Run("incomplete flag survives normalization", func(t *testing.T) {
		clock := newProviderTestClock()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("ETag", `"partial"`)
			_, _ = fmt.Fprint(w, `{"total_count":500,"incomplete_results":true,"items":[]}`)
		}))
		defer server.Close()
		result, err := providerClientForServer(t, server, clock).Search(context.Background(), "storage-service", "", 10)
		if err != nil {
			t.Fatal(err)
		}
		if !result.Incomplete || result.NotModified || result.TotalCount != 500 || result.ETag != `"partial"` {
			t.Fatalf("incomplete result = %+v", result)
		}
	})
}

func TestProviderUnprocessableEntityIsNotRetried(t *testing.T) {
	clock := newProviderTestClock()
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusUnprocessableEntity)
	}))
	defer server.Close()
	_, err := providerClientForServer(t, server, clock).Search(context.Background(), "storage-service", "", 10)
	var statusErr *HTTPStatusError
	if !errors.As(err, &statusErr) || statusErr.StatusCode != http.StatusUnprocessableEntity || statusErr.Retryable || statusErr.RateLimited {
		t.Fatalf("422 error = %#v, %v", statusErr, err)
	}
	if calls != 1 {
		t.Fatalf("422 calls = %d, want 1", calls)
	}
}

func TestProviderClassifiesForbiddenAndRateLimitedResponses(t *testing.T) {
	tests := []struct {
		name          string
		status        int
		headers       http.Header
		wantCalls     int
		wantRetryable bool
		wantLimited   bool
		firstBackoff  time.Duration
	}{
		{name: "ordinary forbidden", status: http.StatusForbidden, headers: http.Header{}, wantCalls: 1},
		{name: "too many requests", status: http.StatusTooManyRequests, headers: http.Header{"Retry-After": []string{"45"}}, wantCalls: maxRetryAttempts, wantRetryable: true, wantLimited: true, firstBackoff: 45 * time.Second},
		{name: "forbidden with rate signal", status: http.StatusForbidden, headers: http.Header{"Retry-After": []string{"47"}, "X-RateLimit-Remaining": []string{"0"}}, wantCalls: maxRetryAttempts, wantRetryable: true, wantLimited: true, firstBackoff: 47 * time.Second},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clock := newProviderTestClock()
			var mu sync.Mutex
			requestTimes := make([]time.Time, 0, tc.wantCalls)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				mu.Lock()
				requestTimes = append(requestTimes, clock.Now())
				mu.Unlock()
				for key, values := range tc.headers {
					for _, value := range values {
						w.Header().Add(key, value)
					}
				}
				w.WriteHeader(tc.status)
			}))
			defer server.Close()
			_, err := providerClientForServer(t, server, clock).Search(context.Background(), "storage-service", "", 10)
			var statusErr *HTTPStatusError
			if !errors.As(err, &statusErr) || statusErr.StatusCode != tc.status {
				t.Fatalf("status error = %#v, %v", statusErr, err)
			}
			if statusErr.Retryable != tc.wantRetryable || statusErr.RateLimited != tc.wantLimited {
				t.Fatalf("classification = retryable:%v rateLimited:%v", statusErr.Retryable, statusErr.RateLimited)
			}
			mu.Lock()
			gotTimes := append([]time.Time(nil), requestTimes...)
			mu.Unlock()
			if len(gotTimes) != tc.wantCalls {
				t.Fatalf("calls = %d, want %d", len(gotTimes), tc.wantCalls)
			}
			if tc.firstBackoff > 0 && len(gotTimes) > 1 && gotTimes[1].Sub(gotTimes[0]) < tc.firstBackoff {
				t.Fatalf("first retry gap = %s, want at least %s", gotTimes[1].Sub(gotTimes[0]), tc.firstBackoff)
			}
		})
	}
}

func TestProviderOrdinaryServerErrorIgnoresRateLimitReset(t *testing.T) {
	clock := newProviderTestClock()
	reset := clock.Now().Add(time.Hour)
	requestTimes := make([]time.Time, 0, maxRetryAttempts)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestTimes = append(requestTimes, clock.Now())
		w.Header().Set("X-RateLimit-Reset", fmt.Sprint(reset.Unix()))
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	_, err := providerClientForServer(t, server, clock).Search(context.Background(), "storage-service", "", 10)
	var statusErr *HTTPStatusError
	if !errors.As(err, &statusErr) || statusErr.StatusCode != http.StatusInternalServerError ||
		!statusErr.Retryable || statusErr.RateLimited || statusErr.RateReset != nil {
		t.Fatalf("500 classification = %#v, %v", statusErr, err)
	}
	if len(requestTimes) != maxRetryAttempts {
		t.Fatalf("500 calls = %d, want %d", len(requestTimes), maxRetryAttempts)
	}
	firstGap := requestTimes[1].Sub(requestTimes[0])
	if firstGap < time.Minute || firstGap >= time.Hour {
		t.Fatalf("500 first retry gap = %s; reset header incorrectly affected ordinary server-error backoff", firstGap)
	}
}

func TestProviderServerErrorStillHonorsRetryAfter(t *testing.T) {
	clock := newProviderTestClock()
	requestTimes := make([]time.Time, 0, maxRetryAttempts)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestTimes = append(requestTimes, clock.Now())
		w.Header().Set("Retry-After", "45")
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	_, err := providerClientForServer(t, server, clock).Search(context.Background(), "storage-service", "", 10)
	var statusErr *HTTPStatusError
	if !errors.As(err, &statusErr) || statusErr.StatusCode != http.StatusServiceUnavailable ||
		!statusErr.Retryable || statusErr.RateLimited {
		t.Fatalf("503 classification = %#v, %v", statusErr, err)
	}
	if len(requestTimes) != maxRetryAttempts || requestTimes[1].Sub(requestTimes[0]) < 45*time.Second {
		t.Fatalf("503 request times = %v; Retry-After was not honored", requestTimes)
	}
}

func TestProviderGlobalSpacingUsesFakeTime(t *testing.T) {
	clock := newProviderTestClock()
	var mu sync.Mutex
	requestTimes := make([]time.Time, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		requestTimes = append(requestTimes, clock.Now())
		mu.Unlock()
		_, _ = fmt.Fprint(w, `{"total_count":0,"incomplete_results":false,"items":[]}`)
	}))
	defer server.Close()
	client := providerClientForServer(t, server, clock)
	for _, keyword := range []string{"storage-service", "vendor.example"} {
		if _, err := client.Search(context.Background(), keyword, "", 10); err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	got := append([]time.Time(nil), requestTimes...)
	mu.Unlock()
	if len(got) != 2 || got[1].Sub(got[0]) < time.Duration(MinIntervalSeconds)*time.Second {
		t.Fatalf("request times = %v", got)
	}
}

func TestProviderSpacingStartsAfterPreviousAttemptCompletes(t *testing.T) {
	clock := newProviderTestClock()
	requestTimes := make([]time.Time, 0, 2)
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestTimes = append(requestTimes, clock.Now())
		calls++
		if calls == 1 {
			clock.advance(45 * time.Second)
		}
		_, _ = fmt.Fprint(w, `{"total_count":0,"incomplete_results":false,"items":[]}`)
	}))
	defer server.Close()
	client := providerClientForServer(t, server, clock)
	if _, err := client.Search(context.Background(), "storage-service", "", 10); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Search(context.Background(), "vendor.example", "", 10); err != nil {
		t.Fatal(err)
	}
	wantGap := 45*time.Second + time.Duration(MinIntervalSeconds)*time.Second
	if len(requestTimes) != 2 || requestTimes[1].Sub(requestTimes[0]) < wantGap {
		t.Fatalf("request start gap = %v, want at least %v", requestTimes[1].Sub(requestTimes[0]), wantGap)
	}
}

func TestProviderErrorNeverIncludesResponseBody(t *testing.T) {
	clock := newProviderTestClock()
	canary := "client_secret=Ab9/7Kp2_Qx4-Zm8+Rt6"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprint(w, canary)
	}))
	defer server.Close()
	_, err := providerClientForServer(t, server, clock).Search(context.Background(), "storage-service", "", 10)
	if err == nil || strings.Contains(err.Error(), canary) {
		t.Fatalf("provider error leaked response body: %v", err)
	}
}

func TestProviderLatestPathCommitAtUsesCoreEndpointAndParsesDate(t *testing.T) {
	clock := newProviderTestClock()
	commitAt := time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/repos/owner/repo/commits" {
			t.Errorf("metadata path = %s", r.URL.Path)
		}
		if got := r.URL.Query().Get("path"); got != "config/prod.env" {
			t.Errorf("path query = %q", got)
		}
		if r.URL.Query().Get("per_page") != "1" || r.URL.Query().Get("page") != "1" {
			t.Errorf("metadata paging = %v", r.URL.Query())
		}
		if got := r.Header.Get("Authorization"); got != "Bearer unit-test-token" {
			t.Errorf("authorization = %q", got)
		}
		if strings.Contains(r.Header.Get("Accept"), "text-match") {
			t.Errorf("metadata request must not reuse code-search text-match accept: %q", r.Header.Get("Accept"))
		}
		_, _ = fmt.Fprintf(w, `[{"commit":{"author":{"date":"2026-08-29T10:00:00Z"},"committer":{"date":"%s"}}}]`, commitAt.Format(time.RFC3339))
	}))
	defer server.Close()
	client := providerClientForServer(t, server, clock)
	got, err := client.LatestPathCommitAt(context.Background(), SearchItem{Repository: "owner/repo", Path: "config/prod.env"})
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(commitAt) {
		t.Fatalf("commit time = %s, want %s", got, commitAt)
	}
	if calls != 1 {
		t.Fatalf("metadata calls = %d, want 1", calls)
	}
}

func TestProviderLatestPathCommitAtClassifiesFailuresAndPacesMetadata(t *testing.T) {
	clock := newProviderTestClock()
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		switch calls {
		case 1:
			w.WriteHeader(http.StatusNotFound)
		case 2:
			_, _ = fmt.Fprint(w, `[]`) // 索引残留：路径已删除/改名
		default:
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer server.Close()
	client := providerClientForServer(t, server, clock)
	item := SearchItem{Repository: "owner/repo", Path: "config.env"}

	if _, err := client.LatestPathCommitAt(context.Background(), item); err == nil {
		t.Fatal("404 metadata should fail")
	} else {
		var httpErr *HTTPStatusError
		if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusNotFound || httpErr.RateLimited {
			t.Fatalf("404 classification = %v", err)
		}
	}
	if _, err := client.LatestPathCommitAt(context.Background(), item); !errors.Is(err, errPathCommitUnavailable) {
		t.Fatalf("empty commit list = %v, want errPathCommitUnavailable", err)
	}
	if _, err := client.LatestPathCommitAt(context.Background(), item); err == nil {
		t.Fatal("403 metadata should fail")
	} else {
		var httpErr *HTTPStatusError
		if !errors.As(err, &httpErr) || !httpErr.RateLimited || httpErr.StatusCode != http.StatusForbidden {
			t.Fatalf("rate-limit classification = %v", err)
		}
	}
	if _, err := client.LatestPathCommitAt(context.Background(), SearchItem{Repository: "bad repo", Path: "x"}); err == nil {
		t.Fatal("invalid repository should fail before the request")
	}

	// 元数据请求串行且相邻完成间隔 ≥ metadataInterval（3 次网络调用 → 2 次等待）。
	clock.mu.Lock()
	waits := append([]time.Duration(nil), clock.waits...)
	clock.mu.Unlock()
	if len(waits) != 2 || waits[0] != metadataInterval || waits[1] != metadataInterval {
		t.Fatalf("metadata pacing waits = %v, want two %s waits", waits, metadataInterval)
	}
}
