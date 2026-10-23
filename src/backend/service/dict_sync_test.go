package service

import (
	"context"
	"os"
	"testing"

	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/repo"
)

func TestBuiltinDictType(t *testing.T) {
	cases := map[string]string{
		"subdomains":    "subdomain",
		"admin":         "directory",
		"springboot":    "directory",
		"weblogic":      "directory",
		"dir":           "directory",
		"anything-else": "directory",
	}
	for stem, want := range cases {
		if got := builtinDictType(stem); got != want {
			t.Fatalf("builtinDictType(%s) = %s, 期望 %s", stem, got, want)
		}
	}
	// top1000/top5000 是端口扫描用的端口列表，必须跳过不进字典库
	if !skippedDictFiles()["top1000.txt"] || !skippedDictFiles()["top5000.txt"] {
		t.Fatal("top1000/top5000 端口列表应在跳过清单里")
	}
}

func TestParseDictValues(t *testing.T) {
	got := parseDictValues("admin\n# comment\n\nlogin\r\n  \nlogout\n#another\n")
	if len(got) != 3 {
		t.Fatalf("应解析出 3 条（去空行/注释）, got %v", got)
	}
	if got[0] != "admin" || got[1] != "login" || got[2] != "logout" {
		t.Fatalf("内容不符: %v", got)
	}
}

// 打真库的同步集成验证（缺 ZRE_PG_PASSWORD 跳过）：
// 首跑把内置词表入库，二跑凭 sha 指纹跳过条目重写（幂等）。
func TestDictSyncIntegration(t *testing.T) {
	if os.Getenv("ZRE_PG_PASSWORD") == "" {
		t.Skip("跳过：未设置 ZRE_PG_PASSWORD")
	}
	cfg := config.LoadConfig("../config/config.yaml")
	if _, err := repo.Open(context.Background(), &cfg.Postgres); err != nil {
		t.Fatalf("连接 PG 失败: %v", err)
	}
	ctx := context.Background()
	store := repo.Default().Dictionaries()
	svc := GetDictSyncService()

	first, err := svc.Sync(ctx)
	if err != nil {
		t.Fatalf("首次同步失败: %v", err)
	}
	if first.Files == 0 {
		t.Fatal("没有枚举到任何内置词表文件")
	}

	// 内置词表应在库里可查且有条目
	dicts, _, err := store.List(ctx, "", 1, 100)
	if err != nil {
		t.Fatal(err)
	}
	builtin := 0
	for _, d := range dicts {
		if !d.IsBuiltin || d.LineCount <= 0 {
			continue
		}
		builtin++
		vals, err := store.ListEntriesForExpand(ctx, d.ID.Hex(), 10)
		if err != nil || len(vals) == 0 {
			t.Fatalf("内置字典 %s(%s) 条目为空: %v", d.Name, d.Type, err)
		}
	}
	if builtin < 10 {
		t.Fatalf("内置字典应至少 10 个（22 个词表文件）, got %d", builtin)
	}

	// 二跑：内容没变，不应重写任何词表
	second, err := svc.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if second.Rewrote != 0 {
		t.Fatalf("内容未变化时二跑不应重写任何词表, got %d", second.Rewrote)
	}
}
