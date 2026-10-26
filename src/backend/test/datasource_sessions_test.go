package test

import (
	"context"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
)

// 数据源会话托管：存储 CRUD + 凭据字段级回落 + 保存合并语义。
// 安全红线：本测试绝不触碰真实数据源条目（aqc/tyc/fengniao/qcc/xiaolanben
// 里可能存着用户扫码/账号会话）——repo 层用合成名 "zz-test-src"，service 层
// 用 registry 内但未配置的 "kuaicha"，t.Cleanup 只删自己创建的行。
func TestDatasourceSessions(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	rs := r.DatasourceSessions()
	const fakeSrc = "zz-test-src"
	const svcSrc = "kuaicha" // registry 合法名；快照-恢复模式保证测试后与测试前完全一致
	// 快照用户当前行（若配置过）：测试结束后原样写回，绝不丢用户会话。
	orig, origExists, err := snapshotSession(ctx, rs, svcSrc)
	if err != nil {
		t.Fatalf("快照失败: %v", err)
	}
	if origExists {
		t.Skipf("用户已配置 %s 会话，跳过 service 层测试以防覆盖", svcSrc)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = rs.Delete(bg, fakeSrc)
		// 恢复语义：开始前行不存在 → 删除测试行；存在 → 原样写回
		if origExists {
			_ = rs.Upsert(bg, orig)
		} else {
			_, _ = rs.Delete(bg, svcSrc)
		}
	})

	// Upsert/Get 回读（repo 层，合成源名）
	now := time.Now()
	if err := rs.Upsert(ctx, &repo.DatasourceSession{
		Provider: fakeSrc, Cookie: "BAIDUID=abc", Status: "active", LastLoginAt: &now,
	}); err != nil {
		t.Fatalf("upsert 失败: %v", err)
	}
	s, err := rs.Get(ctx, fakeSrc)
	if err != nil || s.Cookie != "BAIDUID=abc" || s.Status != "active" || s.LastLoginAt == nil {
		t.Fatalf("回读不符: %+v err=%v", s, err)
	}

	// 凭据字段级回落：请求体字段优先，空字段回落存储
	c, u, p := service.ResolveDatasourceSession(fakeSrc, "", "user@x", "")
	if c != "BAIDUID=abc" || u != "user@x" {
		t.Fatalf("回落语义不符: cookie=%q user=%q pass=%q", c, u, p)
	}
	c, u, p = service.ResolveDatasourceSession(fakeSrc, "BODY=1", "", "")
	if c != "BODY=1" {
		t.Fatalf("请求体 Cookie 应优先: %q", c)
	}
	// 未配置的源原样返回
	if c, u, p := service.ResolveDatasourceSession("no-such-source", "", "", ""); c != "" || u != "" || p != "" {
		t.Fatalf("未配置源不应有回落: %q %q %q", c, u, p)
	}

	// 保存合并（service 层，kuaicha 未配置无覆盖风险）：nil 字段保持原值
	if err := service.SaveDatasourceSession(ctx, svcSrc,
		service.DatasourceSessionSaveInput{Cookie: strPtr("KC=1")}); err != nil {
		t.Fatalf("save 失败: %v", err)
	}
	if err := service.SaveDatasourceSession(ctx, svcSrc,
		service.DatasourceSessionSaveInput{Password: strPtr("secret")}); err != nil {
		t.Fatalf("save 二次失败: %v", err)
	}
	s, _ = rs.Get(ctx, svcSrc)
	if s.Cookie != "KC=1" || s.Password != "secret" || s.Status != "active" {
		t.Fatalf("合并语义不符: %+v", s)
	}

	// MarkStatus + 清除
	if err := rs.MarkStatus(ctx, fakeSrc, "expired"); err != nil {
		t.Fatalf("mark 失败: %v", err)
	}
	s, _ = rs.Get(ctx, fakeSrc)
	if s.Status != "expired" {
		t.Fatalf("状态标记不符: %s", s.Status)
	}
	if ok, _ := rs.Delete(ctx, fakeSrc); !ok {
		t.Fatal("删除应命中")
	}
	if _, err := rs.Get(ctx, fakeSrc); err != repo.ErrNotFound {
		t.Fatalf("删除后应 ErrNotFound: %v", err)
	}

	// service 清单应包含 registry 全部源（含刚清理的 kuaicha，状态回未配置）
	list, err := service.ListDatasourceSessions(ctx)
	if err != nil {
		t.Fatalf("清单失败: %v", err)
	}
	if len(list) == 0 {
		t.Fatal("清单为空")
	}
	found := false
	for _, v := range list {
		if v.Name == svcSrc {
			found = true
		}
	}
	// 注意：此时清理尚未执行（t.Cleanup 在测试结束后跑），
	// kuaicha 行仍是本测试的测试数据；断言只验证 registry 全量出现在清单里。
	if !found {
		t.Fatal("清单缺 kuaicha")
	}
}

func strPtr(s string) *string { return &s }


// snapshotSession 读取某源当前会话行（不存在时 exists=false）。
func snapshotSession(ctx context.Context, rs repo.DatasourceSessionRepo, provider string) (*repo.DatasourceSession, bool, error) {
	s, err := rs.Get(ctx, provider)
	if err == repo.ErrNotFound {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return s, true, nil
}
