package service

import "testing"

// T9 黄金值交叉验证：backend 自己实现的 favicon mmh3 必须与 reconkit
// （internal/recon/fingerprint）落在同一组值上。两处 fixture 与期望值保持一致，
// 任何一边改了折行规则都会在各自测试里转红。
func TestBackendFaviconMMH3GoldenValues(t *testing.T) {
	want := map[int]int32{
		1:   -1081388334,
		55:  -1127788618,
		57:  654477405,
		76:  -220008149,
		100: 1665491875,
		120: 406376946,
	}
	for n, w := range want {
		data := make([]byte, n)
		for i := range data {
			data[i] = byte(i*7 + 13)
		}
		if got := faviconMMH3(data); got != w {
			t.Fatalf("n=%d backend favicon mmh3=%d，期望 %d（与 reconkit/FOFA 空间不一致）", n, got, w)
		}
	}
}
