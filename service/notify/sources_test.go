package notify

import (
	"context"
	"testing"
)

// changeType 归一：精确匹配、证书前缀动态标题、未登记回落空串。
func TestAssetChangeTypeKey(t *testing.T) {
	cases := map[string]string{
		"站点页面内容变更":        "asset_monitor:site_content_change",
		"巡航发现新资产候选":       "asset_monitor:new_asset_candidate",
		"资产失联":            "asset_monitor:site_down",
		"失联资产恢复":          "asset_monitor:site_down",
		"证书已过期":           "asset_monitor:cert_expiry",
		"证书即将到期（剩余 3 天）":  "asset_monitor:cert_expiry",
		"证书到期提醒（剩余 30 天）": "asset_monitor:cert_expiry",
		"":                "",
		"某种未来新增的变更":       "",
	}
	for in, want := range cases {
		if got := AssetChangeTypeKey(in); got != want {
			t.Errorf("AssetChangeTypeKey(%q) = %q, want %q", in, got, want)
		}
	}
}

// 目录 key 白名单：顶级与子键都合法，任意串被拒。
func TestKnownSourceKey(t *testing.T) {
	for _, k := range []string{"asset_monitor", "sentinel", "asset_monitor:site_content_change", "cruise"} {
		if !KnownSourceKey(k) {
			t.Errorf("%q 应为合法 key", k)
		}
	}
	for _, k := range []string{"", "manual", "asset_monitor:bogus", "../../etc"} {
		if KnownSourceKey(k) {
			t.Errorf("%q 不应为合法 key", k)
		}
	}
}

// 关闭的通知对象：完全不发送——不进渠道、不进站内（saveNotification 在 repo 为 nil 时
// 本就跳过，这里断言 fake notifier 收不到即可）。
func TestSendSourceSuppressed(t *testing.T) {
	m := NewNotifyManager()
	fake := &fakeNotifier{}
	m.dispatch = []channelDispatch{{notifier: fake}}

	m.SetSourceEnabled("asset_monitor:site_content_change", false)
	// 模拟站点内容变更通知：NotifyAssetChangeWithLevel 会带上 change_type。
	msg := &NotifyMessage{
		Level:  NotifyLevelInfo,
		Title:  "资产变更: 站点页面内容变更",
		Source: "asset_monitor",
		Extra:  map[string]interface{}{"change_type": "站点页面内容变更"},
	}
	if !m.sourceSuppressed(msg) {
		t.Fatal("子键关闭后应被拦下")
	}
	_ = m.Send(context.Background(), msg)
	if len(fake.msgs) != 0 {
		t.Fatalf("被关闭的通知对象不应发送，实际 %d 条", len(fake.msgs))
	}

	// 其他资产变更子类型不受影响。
	ok := &NotifyMessage{
		Level:  NotifyLevelInfo,
		Title:  "资产变更: 资产失联",
		Source: "asset_monitor",
		Extra:  map[string]interface{}{"change_type": "资产失联"},
	}
	if m.sourceSuppressed(ok) {
		t.Fatal("未关闭的子类型不应被拦")
	}
	_ = m.Send(context.Background(), ok)
	if len(fake.msgs) != 1 {
		t.Fatalf("未关闭的子类型应正常发送，实际 %d 条", len(fake.msgs))
	}

	// 未登记的 change_type 回落到父键开关；父键关闭则全拦。
	m.SetSourceEnabled("sentinel", false)
	if !m.sourceSuppressed(&NotifyMessage{Source: "sentinel"}) {
		t.Fatal("父键关闭应拦截该源全部消息")
	}
	if m.sourceSuppressed(&NotifyMessage{Source: "asset_monitor", Extra: map[string]interface{}{"change_type": "某种未来新增的变更"}}) {
		t.Fatal("未登记 changeType 且父键未关，不应拦截")
	}
	_ = m.Send(context.Background(), &NotifyMessage{Source: "sentinel", Title: "x"})
	if len(fake.msgs) != 1 {
		t.Fatalf("sentinel 已关闭却仍发送")
	}
}

// ListSources 返回目录与开关状态：关闭的子键 enabled=false，其余 true。
func TestListSources(t *testing.T) {
	m := NewNotifyManager()
	m.SetSourceEnabled("asset_monitor:cert_expiry", false)
	items := m.ListSources()
	var asset *NotifySourceItem
	for i := range items {
		if items[i].Key == "asset_monitor" {
			asset = &items[i]
		}
	}
	if asset == nil {
		t.Fatal("目录应包含 asset_monitor")
	}
	if !asset.Enabled {
		t.Error("父键未关应为 enabled")
	}
	for _, c := range asset.Children {
		want := c.Key != "asset_monitor:cert_expiry"
		if c.Enabled != want {
			t.Errorf("%s enabled=%v, want %v", c.Key, c.Enabled, want)
		}
	}
}
