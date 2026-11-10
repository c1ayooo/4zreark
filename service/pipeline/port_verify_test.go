package pipeline

import (
	"net"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/scanner/core"
)

func TestVerifyTCPPortsKeepsOnlyOpen(t *testing.T) {
	openLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer openLn.Close()
	openPort := openLn.Addr().(*net.TCPAddr).Port

	// 端口 1 通常没有服务；若被占用则跳过，避免测试偶发失败。
	if conn, err := net.DialTimeout("tcp", "127.0.0.1:1", 200*time.Millisecond); err == nil {
		_ = conn.Close()
		t.Skip("127.0.0.1:1 意外可连接，跳过关闭端口断言")
	}
	closedPort := 1

	got := verifyTCPPorts("127.0.0.1", []core.PortResult{
		{Port: openPort},
		{Port: closedPort},
	}, 500*time.Millisecond)

	if len(got) != 1 || got[0].Port != openPort {
		t.Fatalf("verifyTCPPorts = %+v, want only open port %d", got, openPort)
	}
}

func TestFilterCommonPorts(t *testing.T) {
	got := filterCommonPorts([]core.PortResult{
		{Port: 80}, {Port: 12345}, {Port: 443},
	}, 1)
	if len(got) != 2 {
		t.Fatalf("filterCommonPorts = %+v, want 80/443", got)
	}
}

func TestFilterCommonPortsFallsBackToPrefix(t *testing.T) {
	got := filterCommonPorts([]core.PortResult{
		{Port: 12345}, {Port: 23456}, {Port: 34567},
	}, 2)
	if len(got) != 2 {
		t.Fatalf("无可识别常见端口时应保留前 2 个，got %+v", got)
	}
}
