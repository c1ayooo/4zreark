package enscan

import (
	"testing"
)

// parseAPIResponse 契约锁定：信封 {code,data,message}；data 键与 -field 取值一致；
// 元素字段名按多键容错提取（真实形状以首次 live 校准为准，未知键安全忽略）。
func TestParseAPIResponseAllFields(t *testing.T) {
	s := &ENScanScanner{}
	body := []byte(`{
	  "code": 200, "message": "查询成功",
	  "data": {
	    "app":     [{"name": "小米商城", "package": "com.xiaomi.shop", "market": "七麦"}],
	    "wx_app":  [{"name": "小米小程序", "appid": "wx123"}],
	    "wechat":  [{"nickname": "小米", "alias": "xiaomi"}],
	    "icp":     [{"domain": "mi.com", "icp": "京ICP备1号", "unit_name": "小米科技"}],
	    "weibo":   [{"nickname": "小米公司", "link": "weibo.com/xiaomi"}],
	    "copyright": [{"software_name": "小米OS", "regnum": "2023SR001"}],
	    "job":     [{"title": "安全工程师", "city": "北京"}],
	    "unknown_field": [{"x": 1}]
	  }
	}`)
	res, err := s.parseAPIResponse("小米科技", body, "aqc")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(res.Apps) != 1 || res.Apps[0].Name != "小米商城" || res.Apps[0].Package != "com.xiaomi.shop" {
		t.Errorf("Apps 解析不符: %+v", res.Apps)
	}
	if len(res.WxApps) != 1 || res.WxApps[0].AppID != "wx123" {
		t.Errorf("WxApps 别名键解析不符: %+v", res.WxApps)
	}
	if len(res.Wechats) != 1 || res.Wechats[0].Name != "小米" || res.Wechats[0].WechatID != "xiaomi" {
		t.Errorf("Wechats 解析不符: %+v", res.Wechats)
	}
	if len(res.ICPs) != 1 || res.ICPs[0].CompanyName != "小米科技" {
		t.Errorf("ICPs unit_name 别名解析不符: %+v", res.ICPs)
	}
	if len(res.Weibos) != 1 || res.Weibos[0].Name != "小米公司" || res.Weibos[0].URL != "weibo.com/xiaomi" {
		t.Errorf("Weibos 解析不符: %+v", res.Weibos)
	}
	if len(res.Copyrights) != 1 || res.Copyrights[0].Name != "小米OS" || res.Copyrights[0].RegisterNo != "2023SR001" {
		t.Errorf("Copyrights 解析不符: %+v", res.Copyrights)
	}
	if len(res.Jobs) != 1 || res.Jobs[0].Title != "安全工程师" || res.Jobs[0].Location != "北京" {
		t.Errorf("Jobs 解析不符: %+v", res.Jobs)
	}
}

// 实测信封：上游拒绝（无 cookie）时 data 为空对象，应得到零值结果而非错误。
func TestParseAPIResponseEmptyData(t *testing.T) {
	s := &ENScanScanner{}
	res, err := s.parseAPIResponse("小米科技", []byte(`{"code":200,"data":{},"message":"查询成功"}`), "aqc")
	if err != nil {
		t.Fatalf("空 data 不应报错: %v", err)
	}
	if len(res.Apps)+len(res.ICPs)+len(res.Weibos) != 0 {
		t.Errorf("空 data 应产生零结果: %+v", res)
	}
}

// 非法 JSON 也返回零值结果（wrapper 语义：解析失败不报错）。
func TestParseAPIResponseBadJSON(t *testing.T) {
	s := &ENScanScanner{}
	res, err := s.parseAPIResponse("x", []byte(`not-json`), "")
	if err != nil || res == nil {
		t.Fatalf("坏 JSON 应返回零值结果: %v %v", res, err)
	}
}

// getString 多键回退：第一个非空键生效。
func TestGetStringMultiKey(t *testing.T) {
	m := map[string]interface{}{"b": "second", "a": "first", "c": ""}
	if got := getString(m, "a", "b"); got != "first" {
		t.Errorf("优先第一个键: %q", got)
	}
	if got := getString(m, "c", "b"); got != "second" {
		t.Errorf("空值应跳过取下一个: %q", got)
	}
	if got := getString(m, "missing"); got != "" {
		t.Errorf("缺失键应为空: %q", got)
	}
}
