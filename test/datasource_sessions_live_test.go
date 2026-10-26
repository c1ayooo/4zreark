package test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/internal/enterprise"
	"github.com/c1ayooo/4zreark/service"
)

// TestDatasourceSessionsLive 实测会话存储里的全部数据源（DS_LIVE=1 门控）：
// 凭据从 datasource_sessions 字段级回落，依次做一次轻量企业检索，验证会话可用性。
func TestDatasourceSessionsLive(t *testing.T) {
	if os.Getenv("DS_LIVE") == "" {
		t.Skip("未设置 DS_LIVE=1")
	}
	openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	views, err := service.ListDatasourceSessions(ctx)
	if err != nil {
		t.Fatalf("清单失败: %v", err)
	}
	for _, v := range views {
		if !v.HasCookie && !v.HasAccount {
			t.Logf("[%s] 未配置，跳过", v.Name)
			continue
		}
		cookie, username, password := service.ResolveDatasourceSession(v.Name, "", "", "")
		provider, err := enterprise.NewProvider(v.Name, map[string]string{
			"cookie": cookie, "username": username, "password": password,
		}, "")
		if err != nil {
			t.Logf("[%s] 构造失败: %v", v.Name, err)
			continue
		}
		start := time.Now()
		refs, err := provider.Search(ctx, "腾讯", 1)
		if err != nil {
			msg := err.Error()
			if len(msg) > 120 {
				msg = msg[:120] + "…"
			}
			tag := "FAIL"
			if strings.Contains(msg, "失效") || strings.Contains(msg, "验证") || strings.Contains(msg, "登录") {
				tag = "SESSION_EXPIRED"
			}
			t.Logf("[%s] %s: %s", v.Name, tag, msg)
		} else {
			name := ""
			if len(refs) > 0 {
				name = refs[0].Name
			}
			t.Logf("[%s] OK: 检索返回 %d 条（%s），耗时 %s", v.Name, len(refs), name, time.Since(start).Round(time.Millisecond))
		}
		time.Sleep(2 * time.Second)
	}
}
