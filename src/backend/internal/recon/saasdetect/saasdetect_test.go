package saasdetect

import "testing"

func TestLoadBuiltinMatchesKnownSaaS(t *testing.T) {
	m, err := LoadBuiltin()
	if err != nil {
		t.Fatalf("内置规则加载失败: %v", err)
	}
	got, ok := m.Match("acme.zendesk.com")
	if !ok {
		t.Fatal("acme.zendesk.com 应命中 Zendesk")
	}
	if got.ID != "zendesk" {
		t.Fatalf("命中服务不符: %+v", got)
	}
	if _, ok := m.Match("totally-unknown.example"); ok {
		t.Fatal("自有域名不应命中 SaaS 规则")
	}
}
