package pipeline

import (
	"context"
	"testing"
	"time"
)

// captureModule 只收不处理：接收上游转发，供测试断言。
type captureModule struct {
	BaseModule
}

func newCaptureModule() *captureModule {
	m := &captureModule{}
	m.name = "capture"
	m.SetInput(make(chan interface{}, 8))
	return m
}

func (m *captureModule) ModuleRun() error {
	for range m.input {
	}
	return nil
}

// 只给 IP/CIDR 的任务此前会被子域模块当域名枚举，白烧测绘配额且 IP 永远进不了
// 端口阶段（任务空转零结果）。旁路后必须以 DomainSkip 形式出现在下游。
func TestSubdomainModuleBypassesIPOrCIDR(t *testing.T) {
	next := newCaptureModule()
	cfg := DefaultSubdomainScanConfig()
	cfg.EnableBrute = false
	cfg.EnableAPI = false
	sub := NewSubdomainScanModuleWithConfig(context.Background(), next, cfg)
	sub.SetInput(make(chan interface{}, 8))

	done := make(chan struct{})
	go func() {
		_ = sub.ModuleRun()
		close(done)
	}()

	sub.GetInput() <- "1.2.3.4"
	sub.GetInput() <- "192.168.31.0/24"
	sub.CloseInput()

	type expect struct {
		domain string
		ip     string
		cidr   bool
	}
	wants := []expect{{"1.2.3.4", "1.2.3.4", false}, {"192.168.31.0/24", "", true}}
	deadline := time.After(15 * time.Second)
	for _, w := range wants {
		var v interface{}
		select {
		case v = <-next.GetInput():
		case <-deadline:
			t.Fatalf("超时：旁路结果未产出，已收到 %d/%d", len(wants)-len(wants), 2)
		}
		ds, ok := v.(DomainSkip)
		if !ok {
			t.Fatalf("期望 DomainSkip，得到 %T: %+v", v, v)
		}
		if ds.Domain != w.domain {
			t.Fatalf("Domain = %q, 期望 %q", ds.Domain, w.domain)
		}
		if w.cidr {
			if !ds.CIDR {
				t.Fatalf("%s 应标记 CIDR", ds.Domain)
			}
			if len(ds.IP) != 0 {
				t.Fatalf("CIDR 目标不应带解析 IP，得到 %v", ds.IP)
			}
		} else {
			if ds.CIDR {
				t.Fatalf("%s 不应标记 CIDR", ds.Domain)
			}
			if len(ds.IP) != 1 || ds.IP[0] != w.ip {
				t.Fatalf("IP 目标应带自身 IP [%s]，得到 %v", w.ip, ds.IP)
			}
		}
		if ds.Skip {
			t.Fatalf("显式给定的目标不应被 CDN 跳过: %+v", ds)
		}
	}

	select {
	case extra := <-next.GetInput():
		t.Fatalf("不应有多余输出: %+v", extra)
	case <-time.After(500 * time.Millisecond):
	}
	select {
	case <-done:
	case <-deadline:
		t.Fatal("ModuleRun 未返回")
	}
}

// 域名验证模块此前丢弃一切非 SubdomainResult 类型，IP/CIDR 旁路信号会在此静默消失。
func TestDomainVerifyModulePassesThroughDomainSkip(t *testing.T) {
	next := newCaptureModule()
	v := NewDomainVerifyModule(context.Background(), next, 1)
	v.SetInput(make(chan interface{}, 8))

	done := make(chan struct{})
	go func() {
		_ = v.ModuleRun()
		close(done)
	}()

	in := DomainSkip{Domain: "1.2.3.4", IP: []string{"1.2.3.4"}}
	v.GetInput() <- in
	v.CloseInput()

	deadline := time.After(15 * time.Second)
	select {
	case got := <-next.GetInput():
		ds, ok := got.(DomainSkip)
		if !ok {
			t.Fatalf("期望原样透传 DomainSkip，得到 %T", got)
		}
		if ds.Domain != in.Domain || len(ds.IP) != 1 || ds.IP[0] != in.IP[0] {
			t.Fatalf("透传内容被改写: %+v", ds)
		}
	case <-deadline:
		t.Fatal("超时：DomainSkip 被验证模块吞掉")
	}
	select {
	case <-done:
	case <-deadline:
		t.Fatal("ModuleRun 未返回")
	}
}

func TestIsIPOrCIDR(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"1.2.3.4", true},
		{"::1", true},
		{"192.168.31.0/24", true},
		{"example.com", false},
		{"1.2.3.4:8080", false},
		{"http://1.2.3.4/", false},
		{"256.1.1.1", false},
		{"1.2.3.0/33", false},
		{"", false},
	}
	for _, c := range cases {
		if got := isIPOrCIDR(c.in); got != c.want {
			t.Fatalf("isIPOrCIDR(%q) = %v, 期望 %v", c.in, got, c.want)
		}
	}
}
