package service

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/repo"
)

func TestTaskDictionaryLoadAndTempFile(t *testing.T) {
	if os.Getenv("ZRE_PG_PASSWORD") == "" {
		t.Skip("跳过：未设置 ZRE_PG_PASSWORD")
	}
	cfg := config.LoadConfig("../config/config.yaml")
	r, err := repo.Open(context.Background(), &cfg.Postgres)
	if err != nil {
		t.Fatalf("连接 PG 失败: %v", err)
	}
	t.Cleanup(r.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	name := "task-dict-" + time.Now().Format("150405.000000")
	dict := &models.Dictionary{Name: name, Type: "subdomain", Description: "test"}
	if _, err := r.Dictionaries().CreateWithEntries(ctx, dict, DictSegmentSize, []string{"www", "api", "mail"}); err != nil {
		t.Fatalf("创建字典失败: %v", err)
	}
	t.Cleanup(func() {
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM dict_entries WHERE dict_id = $1`, dict.ID.Hex())
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM dictionaries WHERE id = $1`, dict.ID.Hex())
	})

	values, err := loadTaskDictionary(ctx, dict.ID.Hex(), "subdomain", 100)
	if err != nil || len(values) != 3 {
		t.Fatalf("加载字典失败: values=%v err=%v", values, err)
	}
	if _, err := loadTaskDictionary(ctx, dict.ID.Hex(), "directory", 100); err == nil {
		t.Fatal("类型不匹配应被拒绝")
	}
	if values, err := loadTaskDictionary(ctx, "", "subdomain", 100); err != nil || values != nil {
		t.Fatalf("空字典 ID 应返回 nil：%v %v", values, err)
	}

	path, err := writeTempWordlist(values)
	if err != nil {
		t.Fatalf("写临时词表失败: %v", err)
	}
	defer os.Remove(path)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "api\nmail\nwww\n" {
		t.Fatalf("临时词表内容不符: %q", data)
	}
}
