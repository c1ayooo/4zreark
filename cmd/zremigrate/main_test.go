package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/repo"
)

func TestNormalizeDoc(t *testing.T) {
	doc := map[string]any{
		"_id":        map[string]any{"$oid": "0123456789abcdef01234567"},
		"created_at": map[string]any{"$date": map[string]any{"$numberLong": "1750000000000"}},
		"count":      map[string]any{"$numberLong": "42"},
		"ratio":      map[string]any{"$numberDouble": "0.5"},
		"tags":       []any{"a", "b"},
		"nested": map[string]any{
			"id": map[string]any{"$oid": "aaaaaaaaaaaaaaaaaaaaaaaa"},
		},
	}
	got := normalizeDoc(doc)

	if got["id"] != "0123456789abcdef01234567" {
		t.Fatalf("_id 未转成 id: %v", got["id"])
	}
	if _, ok := got["_id"]; ok {
		t.Fatal("_id 应被删除")
	}
	if got["count"] != int64(42) || got["ratio"] != 0.5 {
		t.Fatalf("数字扩展 JSON 未展开: %v / %v", got["count"], got["ratio"])
	}
	ts, ok := got["created_at"].(string)
	if !ok {
		t.Fatalf("created_at 应为字符串: %T", got["created_at"])
	}
	if _, err := time.Parse(time.RFC3339Nano, ts); err != nil {
		t.Fatalf("created_at 不是 RFC3339: %q", ts)
	}
	nested := got["nested"].(map[string]any)
	if nested["id"] != "aaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("嵌套 $oid 未展开: %v", nested["id"])
	}
}

func TestReadDocumentsJSONL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "users.jsonl")
	content := `{"_id":{"$oid":"0123456789abcdef01234567"},"name":"a"}` + "\n\n" +
		`{"_id":"aaaaaaaaaaaaaaaaaaaaaaaa","name":"b"}` + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	docs, err := readDocuments(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) != 2 || docs[0]["id"] != "0123456789abcdef01234567" || docs[1]["id"] != "aaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("JSONL 解析不符: %+v", docs)
	}
}

func TestReadDocumentsJSONArray(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roles.json")
	content := `[{"_id":{"$oid":"0123456789abcdef01234567"},"name":"admin"}]`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	docs, err := readDocuments(path)
	if err != nil || len(docs) != 1 || docs[0]["name"] != "admin" {
		t.Fatalf("JSON 数组解析不符: %+v err=%v", docs, err)
	}
}

func TestResolveCollections(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"users.json", "tasks.jsonl", "readme.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("[]"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	names, err := resolveCollections(dir, "")
	if err != nil || len(names) != 2 || names[0] != "tasks" || names[1] != "users" {
		t.Fatalf("集合发现不符: %v err=%v", names, err)
	}
	names, err = resolveCollections(dir, "users")
	if err != nil || len(names) != 1 || names[0] != "users" {
		t.Fatalf("集合过滤不符: %v err=%v", names, err)
	}
}

// 真实库：mongoexport 扩展 JSON -> dictionaries 表，含坏文档隔离与清理。
func TestMigrateDictionaryLive(t *testing.T) {
	if os.Getenv("ZRE_PG_PASSWORD") == "" {
		t.Skip("跳过：未设置 ZRE_PG_PASSWORD")
	}
	cfg := config.LoadConfig("../../config/config.yaml")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r, err := repo.Open(ctx, &cfg.Postgres)
	if err != nil {
		t.Fatalf("连接 PG 失败: %v", err)
	}
	t.Cleanup(r.Close)
	mr := r.Migrate()

	name := "zremigrate-test-" + time.Now().Format("150405.000000")
	dir := t.TempDir()
	path := filepath.Join(dir, "dictionaries.jsonl")
	content := `{"_id":{"$oid":"eeeeeeeeeeeeeeeeeeee0001"},"name":"` + name +
		`","type":"subdomain","description":"","file_path":"","line_count":1,"is_builtin":false,"created_at":{"$date":{"$numberLong":"1750000000000"}}}` +
		"\n{\"name\":\"bad-no-id\"}\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	docs, err := readDocuments(path)
	if err != nil {
		t.Fatal(err)
	}
	inserted, failed := insertDocs(ctx, mr, "dictionaries", docs, 10)
	if inserted != 1 || failed != 1 {
		t.Fatalf("迁移结果不符: inserted=%d failed=%d", inserted, failed)
	}
	t.Cleanup(func() {
		_, _ = r.Pool().Exec(context.Background(), `delete from dictionaries where id=$1`, "eeeeeeeeeeeeeeeeeeee0001")
	})

	var gotName string
	var gotCreated time.Time
	if err := r.Pool().QueryRow(ctx,
		`select name, created_at from dictionaries where id=$1`, "eeeeeeeeeeeeeeeeeeee0001").
		Scan(&gotName, &gotCreated); err != nil {
		t.Fatalf("读取迁移行失败: %v", err)
	}
	if gotName != name {
		t.Fatalf("name 不符: %q", gotName)
	}
	if gotCreated.UTC().Format("2006-01-02") != "2025-06-15" {
		t.Fatalf("created_at 未按 $date 保留: %s", gotCreated)
	}
}
