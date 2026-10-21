package test

import (
	"context"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/service"
)

// 自动验证台账：投递写入 queued，7 天窗口内同 (target, product) 不重复排队。
func TestVulnVerifyEnqueueDedup(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	target := "http://auto-verify-test.example.com"
	product := "test-product-" + time.Now().Format("150405.000000")
	t.Cleanup(func() {
		_, _ = r.Pool().Exec(context.Background(),
			`DELETE FROM vulnverify_jobs WHERE target = $1 AND product = $2`, target, product)
	})

	svc := service.NewVulnVerifyService()
	svc.Enqueue("1", target, product)
	svc.Enqueue("1", target, product) // 第二次应被在途去重

	var n int
	if err := r.Pool().QueryRow(ctx,
		`SELECT COUNT(*) FROM vulnverify_jobs WHERE target=$1 AND product=$2`, target, product).Scan(&n); err != nil {
		t.Fatalf("查询台账失败: %v", err)
	}
	if n != 1 {
		t.Fatalf("同目标同产品应只有 1 条在途任务，实际 %d", n)
	}
	if _, err := svc.Stats(ctx, 30); err != nil {
		t.Fatalf("读取统计失败: %v", err)
	}
}
