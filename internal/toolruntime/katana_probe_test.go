package toolruntime

import (
	"context"
	"os"
	"testing"
)

// 用 vendored katana 实跑 flag 门禁：RequiredFlags（含 headless 系）必须能被
// flagTokenRe 在 -h 输出中命中，否则换版门会误拦所有 katana 更新。
// 二进制不存在时跳过（CI 无 vendored tools 的环境）。
func TestKatanaProbeRequiredFlags(t *testing.T) {
	const bin = "../../tools/linux/katana"
	if _, err := os.Stat(bin); err != nil {
		t.Skip("跳过：vendored katana 不存在")
	}
	k, ok := Spec("katana")
	if !ok {
		t.Fatal("katana spec 不存在")
	}
	missing, err := checkFlags(context.Background(), bin, k)
	if err != nil {
		t.Fatalf("checkFlags: %v", err)
	}
	if len(missing) > 0 {
		t.Fatalf("探针未命中: %v", missing)
	}
}
