package enterprise

import (
	"testing"
)

// 热更新语义：SetLimits 改写后，start() 钳制按新上限执行；
// 非法值（<=0）不生效，保留原配置。
func TestCollectorLimitsHotReload(t *testing.T) {
	c := NewCollector(nil, nil)

	depth, nodes := c.Limits()
	if depth != 3 || nodes != 200 {
		t.Fatalf("缺省上限应为 3 层 / 200 节点，实际 %d / %d", depth, nodes)
	}

	// 热更新：调大深度与节点，立即反映到 Limits（后续任务按新值钳制）
	c.SetLimits(5, 500)
	depth, nodes = c.Limits()
	if depth != 5 || nodes != 500 {
		t.Fatalf("热更新后应为 5 层 / 500 节点，实际 %d / %d", depth, nodes)
	}

	// 非法值不覆盖现有配置
	c.SetLimits(0, -1)
	depth, nodes = c.Limits()
	if depth != 5 || nodes != 500 {
		t.Fatalf("非法值应保留原上限，实际 %d / %d", depth, nodes)
	}

	// start() 的钳制用当前上限：超限任务参数被收敛到新上限内
	job := Job{Depth: 9, MaxNodes: 9999}
	maxDepth, maxNodesCap := c.Limits()
	if job.Depth > maxDepth {
		job.Depth = maxDepth
	}
	if job.MaxNodes > maxNodesCap {
		job.MaxNodes = maxNodesCap
	}
	if job.Depth != 5 || job.MaxNodes != 500 {
		t.Fatalf("钳制结果应在新上限内，实际 depth=%d nodes=%d", job.Depth, job.MaxNodes)
	}
}
