package enterprise

import "testing"

// 小蓝本数字资产解析契约：字段名归类、条目取值、未知键安全忽略。
// fixture 为合成 __INITIAL_STATE__ 形状；真实形状首次 live 校准时如有出入，
// 以「键名归类表 + 条目键候选表」为准调整，测试锁定行为语义。
func TestParseXlbDigitalAssets(t *testing.T) {
	fixture := `{
		"__entityName": "示例公司",
		"apps": [
			{"appName": "示例App", "platform": "Android", "developer": "示例公司"},
			{"appName": "示例App", "platform": "iOS"},
			{"name": "  "}
		],
		"miniPrograms": [{"name": "示例小程序", "platform": "微信"}],
		"wxPublicAccounts": [{"nickname": "示例公众号", "type": "订阅号"}],
		"weiboList": [{"name": "示例微博", "channel": "微博"}],
		"investments": [{"name": "不该出现的子公司"}],
		"webSites": [{"domain": "example.com"}]
	}`
	hits, err := parseXlbDigitalAssets([]byte(fixture))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(hits) != 4 {
		t.Fatalf("应有 4 条（批内同名去重 + 空名丢弃 + 未知键忽略），实际 %d: %+v", len(hits), hits)
	}
	byName := map[string]DigitalHit{}
	for _, h := range hits {
		byName[h.Name] = h
	}
	app := byName["示例App"]
	if app.Kind != "app" || app.Platform != "Android" || app.Company != "示例公司" ||
		app.EntityName != "示例公司" || app.Evidence == "" {
		t.Fatalf("APP 条目解析不符: %+v", app)
	}
	if mp := byName["示例小程序"]; mp.Kind != "miniapp" || mp.Platform != "微信" {
		t.Fatalf("小程序条目解析不符: %+v", mp)
	}
	if gzh := byName["示例公众号"]; gzh.Kind != "official_account" || gzh.Platform != "订阅号" {
		t.Fatalf("公众号条目解析不符: %+v", gzh)
	}
	if wb := byName["示例微博"]; wb.Kind != "newmedia" {
		t.Fatalf("新媒体条目解析不符: %+v", wb)
	}
	if _, ok := byName["不该出现的子公司"]; ok {
		t.Fatal("未匹配键（investments）不应产出候选")
	}
}

func TestClassifyXlbKey(t *testing.T) {
	cases := map[string]string{
		"miniappList":      "miniapp",
		"miniPrograms":     "miniapp",
		"weChatApplets":    "miniapp",
		"appList":          "app",
		"apps":             "app",
		"officialAccounts": "official_account",
		"gzhList":          "official_account",
		"weiboList":        "newmedia",
		"newMedias":        "newmedia",
		"investments":      "",
		"webSites":         "",
		"branches":         "",
	}
	for key, want := range cases {
		if got := classifyXlbKey(key); got != want {
			t.Errorf("classifyXlbKey(%q) = %q, want %q", key, got, want)
		}
	}
}
