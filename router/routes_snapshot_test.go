package router

import (
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/c1ayooo/4zreark/config"
)

// 路由快照：拆分巨型 Register 函数时，用它做「改前/改后逐条比对」。
// 只要方法+路径+处理器名三者完全一致，就说明纯搬代码没有动到对外契约。
//
// 用法：
//
//	CONFIG_PATH=/etc/4zreark/config.yaml ZRE_ROUTE_SNAPSHOT=/tmp/routes.tsv \
//	  go test ./router -run TestRouteSnapshot -v
//
// 快照不存在时写入（基线），存在时比对，不一致即失败并打印差异。
// 两个环境变量缺任一个就跳过，保证常规 go test ./... 不受影响。
func TestRouteSnapshot(t *testing.T) {
	path := os.Getenv("ZRE_ROUTE_SNAPSHOT")
	if path == "" {
		t.Skip("未设置 ZRE_ROUTE_SNAPSHOT，跳过路由快照比对")
	}
	cfg := os.Getenv("CONFIG_PATH")
	if cfg == "" {
		t.Skip("未设置 CONFIG_PATH：部分处理器在构造期读配置，未加载会直接退出")
	}
	// 处理器构造期读配置，缺失时 config 包会 log.Fatal 结束进程。
	config.LoadConfig(cfg)

	engine := SetupRouterWithWebSocket(nil, nil)
	routes := engine.Routes()
	lines := make([]string, 0, len(routes))
	for _, rt := range routes {
		lines = append(lines, rt.Method+"\t"+rt.Path+"\t"+shortHandler(rt.Handler))
	}
	sort.Strings(lines)
	got := strings.Join(lines, "\n") + "\n"

	want, err := os.ReadFile(path)
	if err != nil {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatalf("写入快照失败: %v", err)
		}
		t.Logf("已写入路由基线：%d 条 → %s", len(lines), path)
		return
	}
	if string(want) == got {
		t.Logf("路由快照一致：%d 条", len(lines))
		return
	}
	old := strings.Split(strings.TrimSpace(string(want)), "\n")
	t.Fatalf("路由快照不一致（基线 %d 条，当前 %d 条）:\n%s", len(old), len(lines),
		diffLines(old, strings.Split(strings.TrimSpace(got), "\n")))
}

// shortHandler 去掉包路径与一层闭包后缀，只留可读的处理器名，
// 避免内部重构（加壳、换包）造成假差异。
func shortHandler(name string) string {
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	if i := strings.Index(name, ".func"); i >= 0 {
		name = name[:i] + ".func"
	}
	return name
}

func diffLines(old, cur []string) string {
	seen := make(map[string]int, len(cur))
	for _, l := range cur {
		seen[l]++
	}
	var missing []string
	for _, l := range old {
		if seen[l] > 0 {
			seen[l]--
			continue
		}
		missing = append(missing, "- "+l)
	}
	for _, l := range cur {
		if seen[l] > 0 {
			seen[l]--
			missing = append(missing, "+ "+l)
		}
	}
	sort.Strings(missing)
	if len(missing) > 40 {
		missing = append(missing[:40], "...（其余省略）")
	}
	return strings.Join(missing, "\n")
}
