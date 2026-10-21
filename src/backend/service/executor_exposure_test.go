package service

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/internal/recon/svcid"
	"github.com/c1ayooo/4zreark/models"
)

func TestParsePortSpec(t *testing.T) {
	if got := parsePortSpec(""); len(got) == 0 || !containsPort(got, 6379) {
		t.Fatalf("空规格应回落到默认暴露面端口，实际 %v", got)
	}
	if got := parsePortSpec("quick"); len(got) == 0 || !containsPort(got, 9200) {
		t.Fatalf("quick 应回落到默认端口，实际 %v", got)
	}

	got := parsePortSpec("80,443,8000-8002")
	want := []int{80, 443, 8000, 8001, 8002}
	if len(got) != len(want) {
		t.Fatalf("端口数量不符: %v，期望 %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("端口顺序不符: %v，期望 %v", got, want)
		}
	}

	// 非法段落跳过、重复去重、越界丢弃
	got = parsePortSpec("443,443,abc,70000,0,1-3,3")
	want = []int{1, 2, 3, 443}
	if len(got) != len(want) {
		t.Fatalf("非法/重复端口未正确过滤: %v，期望 %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("端口结果不符: %v，期望 %v", got, want)
		}
	}
}

func TestSplitTarget(t *testing.T) {
	cases := []struct {
		in   string
		host string
		port int
	}{
		{"https://example.com:8443/login", "example.com", 8443},
		{"http://example.com/admin", "example.com", 0},
		{"example.com:8080", "example.com", 8080},
		{"example.com/path", "example.com", 0},
		{"127.0.0.1", "127.0.0.1", 0},
		{"127.0.0.1:6379", "127.0.0.1", 6379},
		{"  ", "", 0},
	}
	for _, c := range cases {
		host, port := splitTarget(c.in)
		if host != c.host || port != c.port {
			t.Fatalf("splitTarget(%q)=(%q,%d)，期望 (%q,%d)", c.in, host, port, c.host, c.port)
		}
	}
}

func TestExposureTargetsFromServices(t *testing.T) {
	svcs := []svcid.Service{
		{Port: 6379, Protocol: "redis"},
		{Port: 80, Protocol: "http"},
		{Port: 9200, Protocol: "elasticsearch"},
		{Port: 0, Protocol: "redis"},
		{Port: 6379, Protocol: "unknown"},
	}
	got := exposureTargetsFromServices("10.0.0.1", svcs)
	if len(got) != 2 {
		t.Fatalf("应只保留 redis/elasticsearch 两条，实际 %+v", got)
	}
	if got[0].Service != "redis" || got[0].Host != "10.0.0.1" || got[1].Service != "elasticsearch" {
		t.Fatalf("映射结果不符: %+v", got)
	}
}

func TestExposureScanFindsAnonymousVNC(t *testing.T) {
	host, port := startFakeVNC(t)
	task := &models.Task{
		Name:    "t5-exposure",
		Targets: []string{fmt.Sprintf("%s:%d", host, port)},
		Config:  models.TaskConfig{Timeout: 2, Threads: 8, PortRange: strconv.Itoa(port)},
	}
	e := &TaskExecutor{}
	results := e.runExposureScan(context.Background(), task)

	if len(results) != 1 {
		t.Fatalf("期望 1 条暴露面 finding，实际 %d 条: %+v", len(results), results)
	}
	r := results[0]
	if r.Type != models.ResultTypeExposure {
		t.Fatalf("结果类型应为 exposure，实际 %s", r.Type)
	}
	if r.Data["service"] != "vnc" || r.Data["port"] != port {
		t.Fatalf("finding 内容不符: %+v", r.Data)
	}
	if finding, _ := r.Data["finding"].(string); !strings.Contains(finding, "VNC 无认证可连接") {
		t.Fatalf("finding 文案不符: %q", finding)
	}
}

func TestServiceIdentifyUsesRealHandshake(t *testing.T) {
	host, port := startFakeVNC(t)
	task := &models.Task{
		Name:    "t5-svcid",
		Targets: []string{fmt.Sprintf("%s:%d", host, port)},
		Config:  models.TaskConfig{Timeout: 2, Threads: 8, PortRange: strconv.Itoa(port)},
	}
	e := &TaskExecutor{}
	results := e.runServiceIdentify(context.Background(), task)

	if len(results) != 1 {
		t.Fatalf("期望 1 条服务识别结果，实际 %d 条: %+v", len(results), results)
	}
	if results[0].Type != models.ResultTypeService || results[0].Data["protocol"] != "vnc" {
		t.Fatalf("服务识别结果不符: type=%s data=%+v", results[0].Type, results[0].Data)
	}
}

// startFakeVNC 在 5900 起一个最小 VNC 服务端（服务端先发协议版本）：
// 横幅 "RFB 003.008\n"；收到客户端版本后返回 1 种安全类型 None(0x01)。
// 选 5900 是因为 fingerprintx 只有标准端口才走 PortPriority 快路径；
// 非标准端口会逐插件试探，超出单端口预算。
func startFakeVNC(t *testing.T) (string, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:5900")
	if err != nil {
		t.Skipf("5900 被占用，跳过真实握手用例: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				// 服务端先发 12 字节协议版本
				if _, err := io.WriteString(c, "RFB 003.008\n"); err != nil {
					return
				}
				// 客户端回发版本；fingerprintx 只读横幅不回复，读失败正常退出
				ver := make([]byte, 12)
				if _, err := io.ReadFull(c, ver); err != nil {
					return
				}
				// 安全类型数量=1，类型=None（无认证）
				_, _ = c.Write([]byte{0x01, 0x01})
				buf := make([]byte, 64)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port
}

func containsPort(ports []int, want int) bool {
	for _, p := range ports {
		if p == want {
			return true
		}
	}
	return false
}
