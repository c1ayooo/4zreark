package subdomain

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// roundTripFunc 把工件请求重定向到本机 httptest 服务，
// 保留原始 URL 的域名字符串（提取器按域名后缀过滤）。
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestCollectFromArtifactsRobots(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			_, _ = io.WriteString(w, "User-agent: *\nDisallow: /private\nSitemap: https://api.example.test/sitemap.xml\n")
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		req.URL.Scheme = "http"
		req.URL.Host = strings.TrimPrefix(srv.URL, "http://")
		return http.DefaultTransport.RoundTrip(req)
	})}

	res := CollectFromArtifacts(context.Background(), "example.test", client, 100)
	if res == nil {
		t.Fatal("结果为空")
	}
	var found bool
	for _, h := range res.Hits {
		if h.Name == "api.example.test" {
			found = true
			if h.Source != "robots_txt" {
				t.Fatalf("来源应为 robots_txt，实际 %s", h.Source)
			}
		}
	}
	if !found {
		t.Fatalf("robots.txt 里的 api.example.test 未出现在结果中: hits=%+v per_src=%v", res.Hits, res.PerSrc)
	}
	if res.PerSrc["robots_txt"] == 0 {
		t.Fatalf("robots_txt 计数为 0: %v", res.PerSrc)
	}
}
