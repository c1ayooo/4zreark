package oob

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseDnslogRecords(t *testing.T) {
	jsonBody := `["a.example.test"," b.example.test ",""]`
	got := parseDnslogRecords(jsonBody)
	if len(got) != 2 || got[0] != "a.example.test" || got[1] != "b.example.test" {
		t.Fatalf("JSON 解析不符: %#v", got)
	}
	lineBody := "a.example.test%\nb.example.test%\n"
	got = parseDnslogRecords(lineBody)
	if len(got) != 2 || got[1] != "b.example.test" {
		t.Fatalf("行文本解析不符: %#v", got)
	}
}

func TestDnslogHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/getdomain.php":
			http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: "test-cookie"})
			_, _ = w.Write([]byte("abc.dnslog.test"))
		case "/getrecords.php":
			if c, err := r.Cookie("PHPSESSID"); err != nil || c.Value != "test-cookie" {
				http.Error(w, "missing cookie", http.StatusForbidden)
				return
			}
			_, _ = w.Write([]byte(`["x.abc.dnslog.test","y.abc.dnslog.test"]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	ctx := context.Background()
	domain, err := DnslogGetDomain(ctx, srv.URL)
	if err != nil || strings.TrimSpace(domain) != "abc.dnslog.test" {
		t.Fatalf("取域名失败: domain=%q err=%v", domain, err)
	}
	records, err := DnslogGetRecords(ctx, srv.URL, domain, 0)
	if err != nil || len(records) != 2 {
		t.Fatalf("取记录失败: %#v err=%v", records, err)
	}
	if _, err := DnslogGetRecords(ctx, srv.URL, "", 0); err == nil {
		t.Fatal("空 domain 应拒绝")
	}
}
