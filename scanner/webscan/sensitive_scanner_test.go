package webscan

import (
	"testing"

	"github.com/c1ayooo/4zreark/config"
)

// 内置缺省规则：全部可编译、正例命中、负例不误报。
// 这些规则在无 config 注入时是敏感信息检测的全部覆盖面，规则失效 =
// 能力静默归零，所以正负例都要锁住。
func TestGetDefaultSensitivePatterns(t *testing.T) {
	patterns := getDefaultSensitivePatterns()
	if len(patterns) < 14 {
		t.Fatalf("缺省规则数 = %d, 期望 >= 14（扩充后的密钥/PII 覆盖面）", len(patterns))
	}
	for name, p := range patterns {
		if p.Regex == nil {
			t.Errorf("规则 %s 未编译", name)
		}
	}

	cases := []struct {
		rule    string
		sample  string
		wantHit bool
	}{
		{"aws_access_key", "key = AKIAIOSFODNN7EXAMPLE", true},
		{"aws_access_key", "AKIA is a prefix only", false},
		{"aws_secret_key", `aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`, true},
		{"aws_secret_key", `aws_secret_access_key = "short"`, false},
		{"google_api_key", "AIzaSyD-1234567890abcdefghijklmnopqrstu", true},
		{"google_api_key", "AIza_short", false},
		{"alibaba_access_key", `accessKeyId: "LTAI5tABCdefGHijklmnoP"`, true},
		{"alibaba_access_key", "LTAI error word", false},
		{"tencent_secret_id", "secretId=AKIDz8krbsJ5yKBZQpn74WFkmLPx3EXAMPLE", true},
		{"tencent_secret_id", "AKID short", false},
		{"github_token", "token: ghp_0123456789abcdefghijklmnopqrstuvwxyz", true},
		{"github_token", "github_pat_0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", true},
		{"github_token", "ghp_short", false},
		{"slack_token", "xoxb-1234567890-abc", true},
		{"slack_token", "xox-123", false},
		{"jwt_token", "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJ", true},
		{"jwt_token", "eyJhbGciOiJIUzI1NiJ9", false}, // 只有两段不是 JWT
		{"connection_uri_with_credentials", "mongodb://admin:P@ssw0rd@10.0.0.1:27017/db", true},
		{"connection_uri_with_credentials", "mysql://root:secret@127.0.0.1:3306/app", true},
		{"connection_uri_with_credentials", "postgres://db.internal:5432/app", false}, // 无凭据
		{"connection_uri_with_credentials", "https://user:pass@example.com/", false},  // 普通 URL 不算
		{"private_key", "-----BEGIN RSA PRIVATE KEY-----", true},
		{"private_key", "-----BEGIN CERTIFICATE-----", false},
		{"password_field", `password = "hunter2secret"`, true},
		{"api_key", `apiKey: "abcdefghijklmnop"`, true},
		{"client_secret", `client_secret: "abcdefghijklmnopqrstuvwxyz"`, true},
		{"id_card_cn", "110101199003077578", true},
		{"id_card_cn", "110101189003077578", false}, // 19 世纪出生段不合法
		{"id_card_cn", "1101011990030", false},
		{"email", "admin@example.com", true},
	}
	for _, c := range cases {
		p, ok := patterns[c.rule]
		if !ok {
			t.Fatalf("缺规则 %s", c.rule)
		}
		if got := p.Regex.MatchString(c.sample); got != c.wantHit {
			t.Errorf("%s 匹配 %q = %v, want %v", c.rule, c.sample, got, c.wantHit)
		}
	}
}

// HaE 补充集（Apache-2.0，overspace-labs/HaE）：合并进缺省集、全部可编译、
// 正负例锁住——中文 PII/内网拓扑是这批规则的增量价值，规则失效等于盲区回归。
func TestHaeSensitivePatternsMerged(t *testing.T) {
	patterns := loadSensitivePatternsFromConfig()
	for _, name := range []string{"hae_mobile_cn", "hae_internal_ip", "hae_jdbc_connection",
		"hae_auth_header", "hae_sensitive_field", "hae_mobile_field"} {
		if _, ok := patterns[name]; !ok {
			t.Fatalf("HaE 规则 %s 未合并进缺省集", name)
		}
		if patterns[name].Regex == nil {
			t.Fatalf("HaE 规则 %s 未编译", name)
		}
	}

	cases := []struct {
		rule    string
		sample  string
		wantHit bool
	}{
		{"hae_mobile_cn", " 联系人 13812345678 请致电 ", true},
		{"hae_mobile_cn", "订单号 12345678901 无手机号", false},
		{"hae_internal_ip", "backend at 10.20.30.40", true},
		{"hae_internal_ip", "server 192.168.1.100", true},
		{"hae_internal_ip", "public 8.8.8.8", false},
		{"hae_jdbc_connection", "url: jdbc:mysql://rm-xx.mysql.rds.aliyuncs.com:3306/order", true},
		{"hae_auth_header", "Authorization: bearer eyJhbGciOiJIUzI1NiJ9.xxx.yyy", true},
		{"hae_auth_header", "Bearer token格式但小写混入大写", false},
		{"hae_sensitive_field", `"access_token":"ya29.a0AfH6SMx"`, true},
		{"hae_mobile_field", `{"mobile":"13812345678"}`, true},
	}
	for _, c := range cases {
		p, ok := patterns[c.rule]
		if !ok {
			t.Fatalf("缺规则 %s", c.rule)
		}
		if got := p.Regex.MatchString(c.sample); got != c.wantHit {
			t.Errorf("%s 匹配 %q = %v, want %v", c.rule, c.sample, got, c.wantHit)
		}
	}

	// config 显式注入时以配置为准，HaE 集不混入（沿用全量覆盖语义）
	if cfg := config.GetVulnConfig(); cfg != nil && len(cfg.SensitivePatterns) > 0 {
		t.Skip("本进程 config 注入了 sensitive_patterns，跳过覆盖语义断言")
	}
}
