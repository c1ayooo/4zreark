package pipeline

import "testing"

// 模块并发推导：默认按 rate/divisor；任务配置了 threads（页面「并发」输入）
// 时作为固定覆盖值——用户显式设的并发优先于自动推导，rate 限速仍作为
// 安全网兜底（并发槽再多，令牌桶照样限 QPS）。
func TestModuleConcurrencyOverride(t *testing.T) {
	c := &PipelineConfig{} // rate 未设 → 默认 10
	if got := c.moduleConcurrency(4); got != 2 {
		t.Fatalf("默认推导 = %d, want 2 (10/4)", got)
	}
	if got := c.moduleConcurrency(8); got != 1 {
		t.Fatalf("默认推导 = %d, want 1 (10/8 下取整，最小 1)", got)
	}

	c.FixedModuleConcurrency = 30
	for _, divisor := range []int{2, 4, 8} {
		if got := c.moduleConcurrency(divisor); got != 30 {
			t.Fatalf("覆盖后 moduleConcurrency(%d) = %d, want 30（threads 生效，不随除数缩放）", divisor, got)
		}
	}

	// threads 小于 1 视为未设置，回落推导
	lo := &PipelineConfig{FixedModuleConcurrency: -5}
	if got := lo.moduleConcurrency(4); got != 2 {
		t.Fatalf("非法覆盖应被忽略 = %d, want 2", got)
	}

	// 高 rate 下的推导基线不受覆盖字段影响
	hi := &PipelineConfig{RatePerSec: 50}
	if got := hi.moduleConcurrency(4); got != 12 {
		t.Fatalf("rate=50 推导 = %d, want 12 (50/4)", got)
	}
}
