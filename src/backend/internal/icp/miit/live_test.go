package miit

import (
	"context"
	"os"
	"testing"
	"time"
)

// 真连工信部的活体测试：MIIT_LIVE=1 go test ./internal/services/icpmonitor/miit/ -run TestLive -v
// 只发 1 页 5 条的最小查询，避免触发限频。
func TestLiveQuery(t *testing.T) {
	if os.Getenv("MIIT_LIVE") != "1" {
		t.Skip("需要 MIIT_LIVE=1")
	}
	c := New("", 30*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	page, err := c.Query(ctx, "深圳市腾讯计算机系统有限公司", ServiceTypeWeb, 1, 5)
	if err != nil {
		t.Fatalf("Query 失败: %v", err)
	}
	t.Logf("total=%d pages=%d items=%d", page.Total, page.Pages, len(page.Items))
	if page.Total <= 0 || len(page.Items) == 0 {
		t.Fatalf("查询返回空")
	}
	for _, it := range page.Items {
		t.Logf("  %s  %s  %s", it.Domain, it.ServiceLicence, it.UnitName)
	}
}
