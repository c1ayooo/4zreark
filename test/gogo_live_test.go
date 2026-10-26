package test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/scanner/portscan"
)

// gogo 二进制可用性 + 本地端口识别。
func TestGogoLocalPort(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<title>gogo smoke</title>ok"))
	}))
	defer srv.Close()

	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portStr)

	scanner := portscan.NewGoGoScanner()
	if !scanner.IsAvailable() {
		t.Skip("跳过：tools/linux/gogo 不存在")
	}
	scanner.Threads = 10
	scanner.Timeout = 3

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := scanner.ScanPorts(ctx, host, portStr)
	if err != nil {
		t.Fatalf("gogo 扫描失败: %v", err)
	}
	for _, p := range res.Ports {
		if p.Port == port && p.State == "open" {
			t.Logf("gogo 命中 %s:%d service=%s title=%q", host, p.Port, p.Service, p.Banner)
			return
		}
	}
	t.Fatalf("gogo 未识别本地开放端口 %s:%d: %+v", host, port, res.Ports)
}
