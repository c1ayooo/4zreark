package cdnorigin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestFindSeparatesOriginFromCDN(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"name_value":"origin.example.com"}]`))
	}))
	defer srv.Close()

	old := crtShEndpoint
	crtShEndpoint = srv.URL
	defer func() { crtShEndpoint = old }()

	got, err := Find(context.Background(), "example.com", Options{
		HTTPClient: srv.Client(),
		Timeout:    2 * time.Second,
		Lookup: func(ctx context.Context, host string) ([]string, error) {
			if host == "origin.example.com" {
				return []string{"192.0.2.10"}, nil
			}
			return nil, nil
		},
	})
	if err != nil {
		t.Fatalf("Find 失败: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("期望 1 个候选，实际 %+v", got)
	}
	if got[0].IP != "192.0.2.10" || got[0].IsCDN {
		t.Fatalf("应把测试网段判为源站候选: %+v", got[0])
	}
	if len(got[0].Sources) == 0 || got[0].Sources[0] != "san:origin.example.com" {
		t.Fatalf("证据来源不符: %+v", got[0].Sources)
	}
}
