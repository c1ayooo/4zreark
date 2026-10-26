package legacyhunter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestQueryCDXEmptyHistoryIsNotAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("[]"))
	}))
	defer srv.Close()

	old := cdxEndpoint
	cdxEndpoint = srv.URL
	defer func() { cdxEndpoint = old }()

	got, err := QueryCDX(context.Background(), "example.com", CDXOptions{
		Limit: 10, Timeout: 2 * time.Second, Client: srv.Client(),
	})
	if err != nil {
		t.Fatalf("无历史记录不应报错: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("期望空结果，实际 %+v", got)
	}
}

func TestQueryCDXParsesEntries(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[["timestamp","original","statuscode"],["20200101000000","https://example.com/old.jsp","200"]]`))
	}))
	defer srv.Close()

	old := cdxEndpoint
	cdxEndpoint = srv.URL
	defer func() { cdxEndpoint = old }()

	got, err := QueryCDX(context.Background(), "example.com", CDXOptions{
		Limit: 10, Timeout: 2 * time.Second, Client: srv.Client(),
	})
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(got) != 1 || got[0].Original != "https://example.com/old.jsp" || got[0].StatusCode != "200" {
		t.Fatalf("解析结果不符: %+v", got)
	}
}
