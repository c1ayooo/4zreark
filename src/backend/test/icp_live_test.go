package test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/service"
)

// 官方工信部查询活体测试：验证限速 worker、状态流转与结果落库。
// 只查 1 页 5 条，避免触发官方站风控。MIIT_LIVE=1 打开。
func TestICPOfficialQueryLive(t *testing.T) {
	if os.Getenv("MIIT_LIVE") != "1" {
		t.Skip("跳过官方 ICP 查询：设置 MIIT_LIVE=1 打开")
	}
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	code := fmt.Sprintf("icp-%d", time.Now().UnixNano())
	var projectID int64
	if err := r.Pool().QueryRow(ctx,
		`INSERT INTO projects (code,name) VALUES ($1,$2) RETURNING id`, code, code).Scan(&projectID); err != nil {
		t.Fatalf("建测试项目失败: %v", err)
	}
	t.Cleanup(func() {
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM projects WHERE id=$1`, projectID)
	})

	svc := service.NewICPService()
	svc.SetMaxPages(1)   // 只取第一页
	svc.SetPagePacing(0) // 页间不额外等待；请求级 5s 限速仍生效

	start := time.Now()
	q, err := svc.Enqueue(ctx, projectID, "深圳市腾讯计算机系统有限公司", 1, 5)
	if err != nil {
		t.Fatalf("入队失败: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("Enqueue 不应阻塞，实际 %s", elapsed)
	}

	deadline := time.Now().Add(2 * time.Minute)
	var status, errMsg string
	var total, fetched int
	for {
		row, err := svc.Get(ctx, q.ID)
		if err != nil {
			t.Fatalf("读取任务失败: %v", err)
		}
		status, errMsg, total, fetched = row.Status, row.Error, row.Total, row.Fetched
		if status != "queued" && status != "running" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("查询超时: status=%s fetched=%d", status, fetched)
		}
		time.Sleep(500 * time.Millisecond)
	}
	if status != "done" {
		t.Fatalf("查询失败: status=%s error=%s", status, errMsg)
	}
	if total <= 0 || fetched != 5 {
		t.Fatalf("结果计数不符: total=%d fetched=%d", total, fetched)
	}
	filings, err := svc.Filings(ctx, q.ID, 10)
	if err != nil || len(filings) != 5 {
		t.Fatalf("备案记录不符: len=%d err=%v", len(filings), err)
	}
	if filings[0].UnitName == "" || filings[0].ServiceLicence == "" {
		t.Fatalf("备案字段为空: %+v", filings[0])
	}

	// 排队中取消：不产生上游请求。
	q2, err := svc.Enqueue(ctx, projectID, "深圳市腾讯计算机系统有限公司", 1, 5)
	if err != nil {
		t.Fatalf("第二次入队失败: %v", err)
	}
	if !svc.Cancel(q2.ID) {
		t.Fatal("排队中的任务应可取消")
	}
	row, _ := svc.Get(ctx, q2.ID)
	if row != nil && row.Status != "canceled" && row.Status != "queued" && row.Status != "running" {
		t.Fatalf("取消状态异常: %s", row.Status)
	}
}
