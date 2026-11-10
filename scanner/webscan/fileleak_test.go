package webscan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newFileLeakTestServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

func TestFileLeakDetectsGitConfig(t *testing.T) {
	srv := newFileLeakTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.git/config":
			w.Write([]byte("[core]\n\trepositoryformatversion = 0\n"))
		default:
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("not found"))
		}
	})
	s := NewFileLeakScanner()
	hits := s.ScanOrigin(context.Background(), srv.URL)
	found := false
	for _, h := range hits {
		if h.Path == "/.git/config" && h.Kind == "git" && h.Severity == "high" {
			found = true
		}
	}
	if !found {
		t.Fatalf("应命中 .git/config，实际: %+v", hits)
	}
}

func TestFileLeakIgnoresUniformResponse(t *testing.T) {
	// 统一响应页（SPA fallback/WAF）：任意路径都 200 + 同长正文。
	// .env 规则的字段格式不满足，本就应被特征闸挡住；这里验证基线闸
	// 能兜住「200 长度巧合接近」的情况（用宽松规则路径测）。
	srv := newFileLeakTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(strings.Repeat("x", 4096)))
	})
	s := NewFileLeakScanner()
	hits := s.ScanOrigin(context.Background(), srv.URL)
	if len(hits) != 0 {
		t.Fatalf("统一响应页不应产生命中: %+v", hits)
	}
}

func TestFileLeakDetectsZipMagic(t *testing.T) {
	srv := newFileLeakTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/backup.zip" {
			w.Write([]byte("PK\x03\x04" + strings.Repeat("\x00", 64)))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	})
	s := NewFileLeakScanner()
	hits := s.ScanOrigin(context.Background(), srv.URL)
	if len(hits) != 1 || hits[0].Evidence != "zip magic (PK)" {
		t.Fatalf("应命中 zip 魔数，实际: %+v", hits)
	}
}

func TestFileLeakEnvNeedsFormat(t *testing.T) {
	// .env 乱码页面不命中：特征闸要求 ≥2 个 KEY= 行。
	srv := newFileLeakTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" {
			w.Write([]byte("<html>this is not env</html>"))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	})
	s := NewFileLeakScanner()
	hits := s.ScanOrigin(context.Background(), srv.URL)
	for _, h := range hits {
		if h.Path == "/.env" {
			t.Fatalf("无 KEY= 格式的 .env 不应命中: %+v", hits)
		}
	}
}
