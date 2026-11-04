package repo

import "testing"

// 上游抓取被截断（半截 JSON、代理超时后拿到部分内容）时，规则集合会「合法地」
// 少掉一大片。按差集删下去会连带 CASCADE 掉历史命中，属于不可逆的数据损失，
// 所以这里锁住阈值行为。
func TestShouldSkipPrune(t *testing.T) {
	cases := []struct {
		name     string
		existing int
		incoming int
		want     bool
	}{
		{"小集合不受保护", 10, 1, false},
		{"小集合阈值下沿", 49, 0, false},
		{"大集合等量", 1000, 1000, false},
		{"大集合正常增删", 1000, 990, false},
		{"大集合 20% 收缩内", 1000, 801, false},
		{"大集合刚好 20% 收缩", 1000, 800, false},
		{"大集合超过 20% 收缩", 1000, 799, true},
		{"大集合被截断", 7829, 120, true},
		{"大集合全空", 7829, 0, true},
	}
	for _, c := range cases {
		if got := shouldSkipPrune(c.existing, c.incoming); got != c.want {
			t.Errorf("%s: shouldSkipPrune(%d, %d) = %v，期望 %v",
				c.name, c.existing, c.incoming, got, c.want)
		}
	}
}
