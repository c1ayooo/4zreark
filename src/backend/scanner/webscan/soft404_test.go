package webscan

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFilterSoft404(t *testing.T) {
	softBody := "<html><head><title>Page Not Found</title></head><body>" + strings.Repeat("x", 400) + "</body></html>"
	realBody := "<html><head><title>Admin Panel</title></head><body>" + strings.Repeat("y", 1200) + "</body></html>"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.URL.Path == "/admin" {
			_, _ = w.Write([]byte(realBody))
			return
		}
		_, _ = w.Write([]byte(softBody))
	}))
	defer srv.Close()

	entries := []SprayEntry{
		{URL: srv.URL + "/nope", Path: "/nope", StatusCode: 200, BodyLength: int64(len(softBody)), Title: "Page Not Found", ContentType: "text/html"},
		{URL: srv.URL + "/admin", Path: "/admin", StatusCode: 200, BodyLength: int64(len(realBody)), Title: "Admin Panel", ContentType: "text/html"},
	}

	got := FilterSoft404(context.Background(), srv.URL, entries, srv.Client())
	if len(got) != 1 || got[0].Path != "/admin" {
		t.Fatalf("软 404 应被过滤，只保留 /admin，实际 %+v", got)
	}

	// 批量入口同样生效
	got = FilterSoft404Entries(context.Background(), entries, srv.Client())
	if len(got) != 1 || got[0].Path != "/admin" {
		t.Fatalf("批量过滤结果不符: %+v", got)
	}
}

func TestFilterSoft404NoBaselineWhenResponsesVary(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// 每个路径的标题与长度都不同 -> 不建立软 404 基线
		_, _ = fmt.Fprintf(w, "<html><head><title>%s</title></head><body>%s</body></html>",
			r.URL.Path, strings.Repeat("z", len(r.URL.Path)*37))
	}))
	defer srv.Close()

	entries := []SprayEntry{
		{URL: srv.URL + "/a", Path: "/a", StatusCode: 200, BodyLength: 100, Title: "a", ContentType: "text/html"},
		{URL: srv.URL + "/b", Path: "/b", StatusCode: 200, BodyLength: 200, Title: "b", ContentType: "text/html"},
	}
	got := FilterSoft404(context.Background(), srv.URL, entries, srv.Client())
	if len(got) != len(entries) {
		t.Fatalf("响应不一致时不应过滤: %+v", got)
	}
}
