package pipeline

import (
	"context"
	"testing"
	"time"
)

// 目标形状校验：挡公司名/备注文本（曾静默走完流水线零产出），
// 放行全部合法扫描形态。规则与任务创建侧 validateScanTargets 同源。
func TestIsPlausibleDomainTarget(t *testing.T) {
	cases := []struct {
		target string
		want   bool
	}{
		// 合法形态：域名 / 裸 IP / CIDR / URL / 通配符 / 带端口 / IPv6
		{"zjenergy.com.cn", true},
		{"a.io", true},
		{"single-label", true},
		{"115.238.59.210", true},
		{"115.238.59.0/24", true},
		{"https://www.example.com", true},
		{"http://ldap.meituan.com:80", true},
		{"*.example.com", true},
		{"localhost", true},
		{"::1", true},
		{"http://[::1]:8080", true},
		{"2001:db8::1", true},

		// 非法形态：公司名 / 含空白 / 空 / 纯符号
		{"浙江省能源集团有限公司", false},
		{"浙江省 能源集团", false},
		{"", false},
		{"   ", false},
		{"foo bar.com", false},
		{"bad..domain/", false},
		{"target;", false},
	}
	for _, c := range cases {
		if got := IsPlausibleDomainTarget(c.target); got != c.want {
			t.Errorf("IsPlausibleDomainTarget(%q) = %v, want %v", c.target, got, c.want)
		}
	}
}

// 公司名/备注文本目标此前会被当域名送进枚举（「主域无效」静默零产出），
// 还会顺流污染下游。现在必须以 Skip=true 的 DomainSkip 旁路整条链，
// 端口阶段原样跳过，任务日志可查原因。
func TestSubdomainModuleSkipsImplausibleTarget(t *testing.T) {
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

	const company = "浙江省能源集团有限公司"
	sub.GetInput() <- company
	sub.CloseInput()

	deadline := time.After(15 * time.Second)
	var v interface{}
	var open bool
	select {
	case v, open = <-next.GetInput():
	case <-deadline:
		t.Fatal("超时：非域名目标未产出跳过条目")
	}
	if !open {
		t.Fatal("下游输入通道过早关闭")
	}
	ds, ok := v.(DomainSkip)
	if !ok {
		t.Fatalf("期望 DomainSkip，得到 %T: %+v", v, v)
	}
	if ds.Domain != company || !ds.Skip {
		t.Fatalf("期望 %q 带 Skip=true，得到 %+v", company, ds)
	}

	select {
	case <-done:
	case <-deadline:
		t.Fatal("模块未退出")
	}
}
