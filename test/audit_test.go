package test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/repo"
)

// 审计日志：写入 -> 过滤查询（用户/动作/结果/分页） -> 清理。
func TestAuditFiltered(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	username := fmt.Sprintf("audit-test-%d", time.Now().UnixNano())
	entry := &models.OperationLog{
		Username: username, Action: "delete", Module: "assets",
		Target: "example.com", Detail: "test", IP: "127.0.0.1", Status: 1,
	}
	if err := r.Audits().Add(ctx, entry); err != nil {
		t.Fatalf("写审计日志失败: %v", err)
	}
	t.Cleanup(func() {
		_, _ = r.Pool().Exec(context.Background(), `delete from operation_logs where username=$1`, username)
	})

	status := 1
	logs, total, err := r.Audits().ListFiltered(ctx, repo.AuditFilter{
		Username: username, Action: "delete", Status: &status, Page: 1, PageSize: 10,
	})
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if total != 1 || len(logs) != 1 {
		t.Fatalf("过滤结果不符: total=%d len=%d", total, len(logs))
	}
	if logs[0].Module != "assets" || logs[0].Target != "example.com" || logs[0].Status != 1 {
		t.Fatalf("字段不符: %+v", logs[0])
	}

	// 不匹配的动作
	_, total, err = r.Audits().ListFiltered(ctx, repo.AuditFilter{
		Username: username, Action: "update", Page: 1, PageSize: 10,
	})
	if err != nil || total != 0 {
		t.Fatalf("动作过滤不符: total=%d err=%v", total, err)
	}
}
