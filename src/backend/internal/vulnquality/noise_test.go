package vulnquality

import "testing"

// TestApplyNoiseSeverityCap D6-2 噪音降级表驱动：显式清单命中 → severity 封顶；
// 非命中保持原样；confirmed 永不降级；已低于封顶不处理。
func TestApplyNoiseSeverityCap(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		title     string
		vulnType  string
		severity  string
		confirmed bool
		wantDown  bool
		wantCap   string
	}{
		{"SSL 证书过期降为 low", "https 证书已过期 3 个月", "配置错误", "high", false, true, "low"},
		{"证书类型命中（title）", "检测到证书错误", "信息泄露", "critical", false, true, "low"},
		{"安全头缺失降为 info", "响应缺少 X-Frame-Options 安全头", "配置错误", "high", false, true, "info"},
		{"CSP 缺失降为 info", "CSP 缺失", "配置错误", "medium", false, true, "info"},
		{"版本信息泄露降为 info", "Nginx server 版本号泄露", "信息泄露", "medium", false, true, "info"},
		{"phpinfo 调试泄露降为 low", "phpinfo 调试信息泄露", "信息泄露", "high", false, true, "low"},
		{"弱口令封顶宽松为 medium", "Tomcat 默认弱口令 admin/admin", "弱口令", "high", false, true, "medium"},
		{"非噪音类型不降级", "存在 SQL 注入", "SQL注入", "high", false, false, "high"},
		{"已低于封顶不处理", "证书过期", "配置错误", "info", false, false, "info"},
		{"confirmed 永不降级", "ssl证书过期高危", "配置错误", "critical", true, false, "critical"},
		{"类型字段命中", "常规页面", "证书配置错误", "high", false, true, "low"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			down, cap := ApplyNoiseSeverityCap(tc.title, tc.vulnType, tc.severity, tc.confirmed)
			if down != tc.wantDown {
				t.Fatalf("downgraded = %v, want %v", down, tc.wantDown)
			}
			if cap != tc.wantCap {
				t.Fatalf("capped severity = %q, want %q", cap, tc.wantCap)
			}
		})
	}
}

// TestApplyNoiseSeverityCap_noWildcard 显式清单边界：不做「按关键词猜」——
// 未在显式枚举内的词（如仅有 "header" 字样）不触发降级。
func TestApplyNoiseSeverityCap_noWildcard(t *testing.T) {
	t.Parallel()

	down, _ := ApplyNoiseSeverityCap("某接口返回异常 header", "逻辑缺陷", "high", false)
	if down {
		t.Fatalf("未列入显式清单的泛词不应降级")
	}
}
