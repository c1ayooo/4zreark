package service

import (
	"testing"

	"github.com/c1ayooo/4zreark/repo"
)

// 发现轮根域挑选：只取启用的 domain 种子、归一化、去重、限量；
// 禁用/非域名/脏值种子一律不参与（不烧配额）。
func TestCollectDiscoveryRoots(t *testing.T) {
	seeds := []*repo.Seed{
		{Kind: "domain", Value: "meituan.com", Enabled: true},
		{Kind: "domain", Value: "https://api.meituan.com:443/", Enabled: true}, // 归一成根域后与前条去重
		{Kind: "domain", Value: "*.vip.meituan.com.", Enabled: true},
		{Kind: "domain", Value: "disabled.com", Enabled: false}, // 禁用不参与
		{Kind: "ip", Value: "101.50.8.46", Enabled: true},       // 非 domain 不参与
		{Kind: "domain", Value: "localhost", Enabled: true},     // 无点无效
		{Kind: "domain", Value: "extra-a.com", Enabled: true},
		{Kind: "domain", Value: "extra-b.com", Enabled: true},
	}
	got := collectDiscoveryRoots(seeds, 5)
	// 归一化剥协议/端口/通配前缀/尾点，但不缩根域（api.meituan.com 保留——
	// 被动源对子域查询合法）；顺序保持种子顺序；禁用/非 domain/无点值剔除。
	want := []string{"meituan.com", "api.meituan.com", "vip.meituan.com", "extra-a.com", "extra-b.com"}
	if len(got) != len(want) {
		t.Fatalf("roots = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("roots[%d] = %q, want %q（全集: %v）", i, got[i], want[i], got)
		}
	}

	if got := collectDiscoveryRoots(seeds, 2); len(got) != 2 || got[0] != "meituan.com" {
		t.Fatalf("cap 截断失效: %v", got)
	}
	if got := collectDiscoveryRoots(nil, 5); len(got) != 0 {
		t.Fatalf("空种子应返回空: %v", got)
	}
}
