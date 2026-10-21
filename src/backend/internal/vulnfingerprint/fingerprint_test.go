package vulnfingerprint

import "testing"

func TestNormalizeHost(t *testing.T) {
	cases := map[string]string{
		"https://OA.Example.com:8443/api": "oa.example.com:8443",
		"http://app.test.cn/":             "app.test.cn",
		"1.2.3.4:8080":                    "1.2.3.4:8080",
		"user@a.b.com/x":                  "a.b.com",
	}
	for in, want := range cases {
		if got := NormalizeHost(in); got != want {
			t.Fatalf("NormalizeHost(%q)=%q want %q", in, got, want)
		}
	}
}

func TestEndpointStripsValues(t *testing.T) {
	// 同一注入点不同参数值 → 同一 endpoint（对方口径的核心）
	a := Endpoint("https://x.com/api/order?id=1001", "", "")
	b := Endpoint("https://x.com/api/order?id=10086", "", "")
	if a != b || a != "/api/order?id" {
		t.Fatalf("参数值应剥掉: a=%q b=%q", a, b)
	}
	// 参数名集不同 → 不同 endpoint（不同注入面）
	if Endpoint("https://x.com/api/order?id=1&from=list", "", "") == a {
		t.Fatal("参数名集不同 endpoint 应不同")
	}
	// vuln_urls 优先
	if e := Endpoint("https://x.com/", "https://x.com/pay?orderNo=9&token=abc", ""); e != "/pay?orderno&token" {
		t.Fatalf("vuln_urls 优先级不符: %q", e)
	}
	// repro 兜底
	if e := Endpoint("目标: x.com", "", "1. GET https://x.com/u/profile?uid=7"); e != "/u/profile?uid" {
		t.Fatalf("repro 兜底不符: %q", e)
	}
	// 无 URL → 空
	if e := Endpoint("某管理系统", "", "手工测试"); e != "" {
		t.Fatalf("无 URL 应返回空: %q", e)
	}
}

func TestFingerprintStableAcrossParamValues(t *testing.T) {
	f1 := Fingerprint("x.com", "/api/order?id", "GET", "水平越权")
	f2 := Fingerprint("x.com", "/api/order?id", "GET", "水平越权")
	if f1 != f2 {
		t.Fatal("同面指纹应稳定")
	}
	if Fingerprint("x.com", "/api/order?id", "POST", "水平越权") == f1 {
		t.Fatal("方法不同指纹应不同")
	}
}

func TestMatchDupDetection(t *testing.T) {
	existing := []Existing{
		{ID: "v1", Title: "/api/order 接口水平越权读取他人订单", Type: "水平越权",
			Target: "https://x.com/api/order?id=1001", ReproSteps: "1. GET https://x.com/api/order?id=1001"},
		{ID: "v2", Title: "用户资料接口未授权访问", Type: "接口未授权",
			Target: "https://x.com/api/profile", ReproSteps: "1. GET https://x.com/api/profile"},
	}
	// 同注入点不同参数值 → exact
	cands := Match(existing, "x.com", "/api/order?id", "GET", "水平越权",
		"/api/order 接口水平越权读取他人订单", "1. GET https://x.com/api/order?id=10086")
	if len(cands) != 1 || cands[0].Kind != "exact" || cands[0].VulnID != "v1" {
		t.Fatalf("exact 命中不符: %+v", cands)
	}
	// 不同类型不误报
	cands = Match(existing, "x.com", "/api/order?id", "GET", "SQL注入",
		"/api/order 注入", "1. GET https://x.com/api/order?id=1")
	if len(cands) != 0 {
		t.Fatalf("不同类型不应软匹配: %+v", cands)
	}
	// 跨主机同 endpoint 同类型高相似
	existing2 := []Existing{{ID: "v3", Title: "/api/order 接口水平越权读取他人订单", Type: "水平越权",
		Target: "https://y.com/api/order?id=1", ReproSteps: "1. GET https://y.com/api/order?id=1"}}
	cands = Match(existing2, "x.com", "/api/order?id", "GET", "水平越权",
		"/api/order 接口水平越权读取他人订单", "1. GET https://x.com/api/order?id=10086")
	if len(cands) != 1 || cands[0].Kind != "cross_host" {
		t.Fatalf("cross_host 命中不符: %+v", cands)
	}
}

func TestTitleSimilarity(t *testing.T) {
	if s := TitleSimilarity("同一条", "同一条"); s != 1 {
		t.Fatal("相同标题相似度应为 1")
	}
	if s := TitleSimilarity("完全不同", "毫无关系"); s > 0.3 {
		t.Fatalf("无关标题相似度应低: %f", s)
	}
}
