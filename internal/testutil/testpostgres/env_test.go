package testpostgres

import "testing"

// TestBaseDSNFromEnv 钉住两个变量名的优先级与回退。
//
// 背景：newTestPGDB（24 个包）与 CI 用的是 TEST_POSTGRES_DSN，而本 helper 原先只认
// 4ZRECO_TEST_POSTGRES_DSN —— 结果本 helper 的使用方在 CI 里静默跳过，覆盖率门禁的
// 「缺 DSN 拒绝假绿」守卫又只查 TEST_POSTGRES_DSN，发现不了。此测试防回退。
func TestBaseDSNFromEnv(t *testing.T) {
	cases := []struct {
		name      string
		dedicated string
		generic   string
		want      string
	}{
		{"两者都设时优先专用变量", "postgres://a/db_a", "postgres://b/db_b", "postgres://a/db_a"},
		{"仅专用变量", "postgres://a/db_a", "", "postgres://a/db_a"},
		{"仅通用变量时回退（CI 场景）", "", "postgres://b/db_b", "postgres://b/db_b"},
		{"两者都无", "", "", ""},
		{"空白视为未设置", "   ", "postgres://b/db_b", "postgres://b/db_b"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("4ZRECO_TEST_POSTGRES_DSN", tc.dedicated)
			t.Setenv("TEST_POSTGRES_DSN", tc.generic)
			if got := baseDSNFromEnv(); got != tc.want {
				t.Fatalf("baseDSNFromEnv()=%q，期望 %q", got, tc.want)
			}
		})
	}
}
