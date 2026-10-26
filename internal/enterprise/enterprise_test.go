package enterprise

import (
	"context"
	"testing"
)

func TestTransformAqcPID(t *testing.T) {
	cases := []struct {
		in   string
		ddw  int64
		want string
	}{
		{"1234567890", 1, "1235476980"},
		{"1234567890", 2, "1236894570"},
		{"1234567890", 9, "1234567890"}, // 未知置换表原样返回
		{"abc", 1, "abc"},               // 非数字不动
	}
	for _, c := range cases {
		if got := transformAqcPID(c.in, c.ddw); got != c.want {
			t.Errorf("transformAqcPID(%q,%d)=%q, want %q", c.in, c.ddw, got, c.want)
		}
	}
}

func TestEffectiveProxyAndFactory(t *testing.T) {
	if got := effectiveProxy(map[string]string{"proxy_url": "http://127.0.0.1:8888"}, "http://global:8080"); got != "http://127.0.0.1:8888" {
		t.Errorf("会话代理应覆盖全局代理，实际 %q", got)
	}
	if got := effectiveProxy(nil, "http://global:8080"); got != "http://global:8080" {
		t.Errorf("无会话代理应回落全局，实际 %q", got)
	}
	// qcc 已接入（Cookie 走 SSR 解析）：无 cookie 应报会话缺失，带 cookie 应构造成功
	if _, err := NewProvider("qcc", nil, ""); err == nil || !IsSessionMissing(err) {
		t.Errorf("qcc 无 cookie 应报会话缺失，实际 %v", err)
	}
	if _, err := NewProvider("qcc", map[string]string{"cookie": "QCCSESSID=x; acw_tc=y"}, ""); err != nil {
		t.Errorf("qcc 带 cookie 应构造成功: %v", err)
	}
	if _, err := NewProvider("unknown", nil, ""); err == nil {
		t.Error("未知 provider 应报错")
	}
	if _, err := NewProvider("aqc", nil, ""); err == nil || !IsSessionMissing(err) {
		t.Errorf("aqc 无 cookie 应报会话缺失，实际 %v", err)
	}
	if _, err := NewProvider("aqc", map[string]string{"cookie": "a=1"}, ""); err != nil {
		t.Errorf("aqc 带 cookie 应构造成功: %v", err)
	}
}

func TestSessionMissing(t *testing.T) {
	err := SessionMissing("需要 Cookie")
	if !IsSessionMissing(err) {
		t.Fatal("IsSessionMissing 应识别")
	}
	if IsSessionMissing(context.Canceled) {
		t.Fatal("普通错误不应被识别为会话缺失")
	}
}
