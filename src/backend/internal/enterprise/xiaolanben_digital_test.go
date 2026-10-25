package enterprise

import "testing"

// 小蓝本数字资产解析契约（2026-10-25 live 校准，实测腾讯/中小公司详情页）：
// - newMedias 混合桶：条目 accountName/typeName(码)/type(中文)，按条目拆 miniapp/official_account/newmedia；
// - products：APP 桶，productName/bundleid/dataType（dataType 纯数字码不作平台展示）；
// - 未匹配键（investments/webSites/trademarks/compets/tagList 等）安全忽略。
func TestParseXlbDigitalAssets(t *testing.T) {
	fixture := `{
		"__entityName": "示例公司",
		"apps": [
			{"appName": "示例App", "platform": "Android", "developer": "示例公司"},
			{"appName": "示例App", "platform": "iOS"},
			{"name": "  "}
		],
		"newMedias": [
			{"accountName": "示例微博", "typeName": "weibo", "type": "官方微博"},
			{"accountName": "示例公众号", "typeName": "wechat", "type": "官方微信"},
			{"accountName": "示例小程序", "typeName": "xcx", "type": "小程序"}
		],
		"products": [
			{"productName": "示例手游", "bundleid": "com.example.game", "dataType": "1"},
			{"productName": "示例产品"}
		],
		"investments": [{"name": "不该出现的子公司"}],
		"webSites": [{"domain": "example.com"}]
	}`
	hits, err := parseXlbDigitalAssets([]byte(fixture))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(hits) != 6 {
		t.Fatalf("应有 6 条（批内同名去重 + 空名丢弃 + 未知键忽略），实际 %d: %+v", len(hits), hits)
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
	if wb := byName["示例微博"]; wb.Kind != "newmedia" || wb.Platform != "官方微博" {
		t.Fatalf("微博条目解析不符: %+v", wb)
	}
	if gzh := byName["示例公众号"]; gzh.Kind != "official_account" || gzh.Platform != "官方微信" {
		t.Fatalf("公众号条目解析不符（应按 typeName=wechat 拆出）: %+v", gzh)
	}
	if mp := byName["示例小程序"]; mp.Kind != "miniapp" || mp.Platform != "小程序" {
		t.Fatalf("小程序条目解析不符（应按 typeName=xcx 拆出）: %+v", mp)
	}
	if g := byName["示例手游"]; g.Kind != "app" || g.Platform != "" {
		t.Fatalf("products 条目应为 app 且纯数字 dataType 不作平台: %+v", g)
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
		"products":         "app",
		"officialAccounts": "official_account",
		"gzhList":          "official_account",
		"weiboList":        "newmedia",
		"newMedias":        "newmedia",
		"investments":      "",
		"webSites":         "",
		"trademarks":       "",
		"compets":          "",
		"tagList":          "",
		"branches":         "",
	}
	for key, want := range cases {
		if got := classifyXlbKey(key); got != want {
			t.Errorf("classifyXlbKey(%q) = %q, want %q", key, got, want)
		}
	}
}
