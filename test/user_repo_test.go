package test

import (
	"context"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/oid"
)

// 用户列表扫描列必须与 userColumns 对齐：List 的 SELECT 带 count(*) over()
// 共 15 列，Scan 漏掉 must_change_password 曾把 bool 扫进 TokenVersion（int），
// /api/users 整页 1007。
func TestUserListScansAllColumns(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	users := r.Users()
	marker := "test:userlist-" + time.Now().Format("150405.000000")
	u := &models.User{
		ID:                 oid.NewObjectID(),
		Username:           marker,
		Password:           "x",
		Email:              marker + "@example.invalid",
		Role:               "viewer",
		Status:             1,
		MustChangePassword: true,
		TokenVersion:       0,
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
	}
	if err := users.Create(ctx, u); err != nil {
		t.Fatalf("造数失败: %v", err)
	}
	t.Cleanup(func() { _ = users.Delete(context.Background(), u.ID.Hex()) })

	got, total, err := users.List(ctx, 1, 20, marker)
	if err != nil {
		t.Fatalf("List 不应报错（列错位会在这里爆 1007）: %v", err)
	}
	if total != 1 || len(got) != 1 {
		t.Fatalf("期望恰好命中 1 条，实际 total=%d len=%d", total, len(got))
	}
	if !got[0].MustChangePassword {
		t.Fatalf("must_change_password 应为 true（写入 true、读出 false 说明列错位）")
	}
	if got[0].TokenVersion != 0 {
		t.Fatalf("token_version 应为 0，实际 %d", got[0].TokenVersion)
	}
}
