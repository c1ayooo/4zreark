package test

import (
	"os"
	"testing"
)

// requireLiveNetwork 把访问公网目标/外部工具的用例改成显式 opt-in，
// 避免在 CI 或本机离线时因等待超时拖垮整包测试（工具装齐后尤其明显）。
func requireLiveNetwork(t *testing.T) {
	t.Helper()
	if os.Getenv("ZRE_NETWORK_LIVE") != "1" {
		t.Skip("跳过真实网络测试：设置 ZRE_NETWORK_LIVE=1 打开")
	}
}
