package scope

import (
	"net/netip"
	"testing"
)

func TestParseDenyList(t *testing.T) {
	d := ParseDenyList(
		[]string{"Gov.CN", "*.mil.cn", "", "example.com."},
		[]string{"10.0.0.0/8", "not-a-cidr", "192.168.1.0/24"},
	)
	cases := []struct {
		host string
		want bool
	}{
		{"gov.cn", true},
		{"www.gov.cn", true},
		{"GOV.CN", true},
		{"notgov.cn", false},
		{"mil.cn", true},
		{"a.b.mil.cn", true},
		{"example.com", true},
		{"sub.example.com", true},
		{"example.com.evil.io", false},
		{"10.1.2.3", true},
		{"10.255.255.255", true},
		{"11.0.0.1", false},
		{"192.168.1.5", true},
		{"example.org", false},
	}
	for _, c := range cases {
		if got := d.DeniesHost(c.host); got != c.want {
			t.Errorf("DeniesHost(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestDenyListNilAndEmpty(t *testing.T) {
	var nilList *DenyList
	if nilList.DeniesHost("gov.cn") {
		t.Error("nil 黑名单不应拦截任何主机")
	}
	empty := ParseDenyList(nil, nil)
	if empty.DeniesHost("gov.cn") {
		t.Error("空黑名单不应拦截任何主机")
	}
	// 带 host:port 的输入也应命中
	if !ParseDenyList([]string{"gov.cn"}, nil).DeniesHost("www.gov.cn:8443") {
		t.Error("host:port 应剥离端口后命中黑名单")
	}
}

func TestDeniesPrefix(t *testing.T) {
	d := ParseDenyList(nil, []string{"10.0.0.0/8"})
	cases := []struct {
		prefix string
		want   bool
	}{
		{"10.0.0.0/8", true},
		{"10.1.0.0/16", true},
		{"10.1.2.0/24", true},
		{"11.0.0.0/8", false},
		{"10.0.0.0/4", false}, // 比禁扫网段更大：部分重叠不算覆盖
	}
	for _, c := range cases {
		p, err := netip.ParsePrefix(c.prefix)
		if err != nil {
			t.Fatalf("bad prefix %q: %v", c.prefix, err)
		}
		if got := d.DeniesPrefix(p); got != c.want {
			t.Errorf("DeniesPrefix(%q) = %v, want %v", c.prefix, got, c.want)
		}
	}
}

func TestScopeDenyOverridesScope(t *testing.T) {
	deny := ParseDenyList([]string{"gov.cn"}, nil)
	// 目标在授权范围内但命中黑名单：黑名单优先，一律拒绝。
	s := NewWithDeny([]string{"www.gov.cn"}, deny)
	if s.AllowsHost("www.gov.cn") {
		t.Error("命中全局禁扫黑名单的目标应被拒绝，即使它在授权范围内")
	}
	if s.AllowsURL("http://sub.www.gov.cn/path") {
		t.Error("URL 形式的黑名单目标也应被拒绝")
	}
	// deny=nil 时不拦截，行为退化为纯授权边界。
	open := NewWithDeny([]string{"www.gov.cn"}, nil)
	if !open.AllowsURL("http://sub.www.gov.cn/path") {
		t.Error("无黑名单时不应影响原有授权判定")
	}
}
