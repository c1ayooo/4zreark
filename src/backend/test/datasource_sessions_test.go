package test

import (
	"context"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
)

// 数据源会话托管：存储 CRUD + 凭据字段级回落 + 保存合并语义。
func TestDatasourceSessions(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	rs := r.DatasourceSessions()
	t.Cleanup(func() {
		_, _ = rs.Delete(context.Background(), "aqc")
		_, _ = rs.Delete(context.Background(), "xiaolanben")
	})

	// Upsert/Get 回读
	now := time.Now()
	if err := rs.Upsert(ctx, &repo.DatasourceSession{
		Provider: "aqc", Cookie: "BAIDUID=abc", Status: "active", LastLoginAt: &now,
	}); err != nil {
		t.Fatalf("upsert 失败: %v", err)
	}
	s, err := rs.Get(ctx, "aqc")
	if err != nil || s.Cookie != "BAIDUID=abc" || s.Status != "active" || s.LastLoginAt == nil {
		t.Fatalf("回读不符: %+v err=%v", s, err)
	}

	// 凭据字段级回落：请求体字段优先，空字段回落存储
	c, u, p := service.ResolveDatasourceSession("aqc", "", "user@x", "")
	if c != "BAIDUID=abc" || u != "user@x" {
		t.Fatalf("回落语义不符: cookie=%q user=%q pass=%q", c, u, p)
	}
	c, u, p = service.ResolveDatasourceSession("aqc", "BODY=1", "", "")
	if c != "BODY=1" {
		t.Fatalf("请求体 Cookie 应优先: %q", c)
	}
	// 未配置的源原样返回
	if c, u, p := service.ResolveDatasourceSession("qcc", "", "", ""); c != "" || u != "" || p != "" {
		t.Fatalf("未配置源不应有回落: %q %q %q", c, u, p)
	}

	// 保存合并：nil 字段保持原值，密码补存后仍保留原 Cookie
	if err := service.SaveDatasourceSession(ctx, "aqc",
		service.DatasourceSessionSaveInput{Password: strPtr("secret")}); err != nil {
		t.Fatalf("save 失败: %v", err)
	}
	s, _ = rs.Get(ctx, "aqc")
	if s.Cookie != "BAIDUID=abc" || s.Password != "secret" || s.Username != "" || s.Status != "active" {
		t.Fatalf("合并语义不符: %+v", s)
	}

	// MarkStatus + 清除
	if err := rs.MarkStatus(ctx, "aqc", "expired"); err != nil {
		t.Fatalf("mark 失败: %v", err)
	}
	s, _ = rs.Get(ctx, "aqc")
	if s.Status != "expired" {
		t.Fatalf("状态标记不符: %s", s.Status)
	}
	if ok, _ := rs.Delete(ctx, "aqc"); !ok {
		t.Fatal("删除应命中")
	}
	if _, err := rs.Get(ctx, "aqc"); err != repo.ErrNotFound {
		t.Fatalf("删除后应 ErrNotFound: %v", err)
	}

	// 账号密码源（xiaolanben）全链路走 service 层
	if err := service.SaveDatasourceSession(ctx, "xiaolanben",
		service.DatasourceSessionSaveInput{Username: strPtr("13800000000"), Password: strPtr("pw")}); err != nil {
		t.Fatalf("save xlb 失败: %v", err)
	}
	c, u, p = service.ResolveDatasourceSession("xiaolanben", "", "", "")
	if u != "13800000000" || p != "pw" {
		t.Fatalf("账号密码回落不符: %q %q", u, p)
	}
	list, err := service.ListDatasourceSessions(ctx)
	if err != nil {
		t.Fatalf("清单失败: %v", err)
	}
	found := false
	for _, v := range list {
		if v.Name == "xiaolanben" {
			found = true
			if v.Status != "active" || !v.HasAccount {
				t.Fatalf("xiaolanben 清单不符: %+v", v)
			}
			// 凭据内容不得回传
			if v.Hint == "" {
				t.Fatalf("hint 缺失")
			}
		}
	}
	if !found {
		t.Fatal("清单缺 xiaolanben")
	}
}

func strPtr(s string) *string { return &s }
