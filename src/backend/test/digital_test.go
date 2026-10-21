package test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
)

// 本地文档只做文本解析：HAR 取请求 URL、CSV 取 host/name 列、TXT 按行分类。
func TestLocalDocParse(t *testing.T) {
	ctx := context.Background()
	svc := service.NewLocalDocService()

	har := `{"log":{"entries":[
	  {"request":{"url":"https://a.example.test/x"}},
	  {"request":{"url":"https://a.example.test/y"}},
	  {"request":{"url":"http://b.example.test:8080/"}}
	]}}`
	preview, err := svc.Preview(ctx, 1, "sample.har", []byte(har))
	if err != nil {
		t.Fatalf("HAR 解析失败: %v", err)
	}
	// 同 host+port+scheme 去重；http:8080 与 https:443 各一条
	if preview.Hosts != 2 || preview.Duplicates != 1 || preview.Names != 0 {
		t.Fatalf("HAR 计数不符: hosts=%d dup=%d names=%d", preview.Hosts, preview.Duplicates, preview.Names)
	}

	csvDoc := "host,name,kind,company\n" +
		"c.example.test,示例应用,app,示例公司\n" +
		"https://d.example.test/,另一个应用,miniapp,\n"
	preview, err = svc.Preview(ctx, 1, "list.csv", []byte(csvDoc))
	if err != nil {
		t.Fatalf("CSV 解析失败: %v", err)
	}
	if preview.Hosts != 2 || preview.Names != 2 {
		t.Fatalf("CSV 计数不符: hosts=%d names=%d", preview.Hosts, preview.Names)
	}

	txt := "e.example.test\n示例公众号\n"
	preview, err = svc.Preview(ctx, 1, "list.txt", []byte(txt))
	if err != nil {
		t.Fatalf("TXT 解析失败: %v", err)
	}
	if preview.Hosts != 1 || preview.Names != 1 {
		t.Fatalf("TXT 计数不符: hosts=%d names=%d", preview.Hosts, preview.Names)
	}

	// 超限与不支持的格式
	if _, err := svc.Preview(ctx, 1, "big.txt", make([]byte, service.MaxLocalDocBytes+1)); err == nil {
		t.Fatal("超过 4 MiB 应被拒绝")
	}
	if _, err := svc.Preview(ctx, 1, "book.xlsx", []byte("x")); err == nil ||
		!strings.Contains(err.Error(), "XLSX") {
		t.Fatalf("XLSX 应明确提示另存 CSV，实际 %v", err)
	}
}

// 数字资产名单：预览去重/对账 -> 确认 -> 列表 -> 撤销；本地文档 host 与名称同一事务链。
func TestG4DigitalAssetsAndLocalDoc(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	code := fmt.Sprintf("dig-%d", time.Now().UnixNano())
	var projectID int64
	if err := r.Pool().QueryRow(ctx,
		`INSERT INTO projects (code, name) VALUES ($1, $2) RETURNING id`, code, code).Scan(&projectID); err != nil {
		t.Fatalf("建测试项目失败: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = r.Pool().Exec(bg, `DELETE FROM import_batches WHERE project_id = $1`, projectID)
		_, _ = r.Pool().Exec(bg, `DELETE FROM projects WHERE id = $1`, projectID)
	})

	dig := service.NewDigitalService()
	names := []string{"示例应用", "示例应用", "  ", "另一个应用"}

	preview, err := dig.Preview(ctx, projectID, "app", names, "示例公司", "", "test")
	if err != nil {
		t.Fatalf("名单预览失败: %v", err)
	}
	if preview.Total != 4 || preview.Unique != 2 || preview.Duplicates != 1 || preview.Invalid != 1 {
		t.Fatalf("名单计数不符: %+v", preview)
	}

	batch, inserted, err := dig.Commit(ctx, preview.Token, "tester")
	if err != nil {
		t.Fatalf("名单确认失败: %v", err)
	}
	if inserted != 2 || batch == nil || batch.Status != "committed" {
		t.Fatalf("名单入库不符: inserted=%d batch=%+v", inserted, batch)
	}
	if _, _, err := dig.Commit(ctx, preview.Token, "tester"); err == nil {
		t.Fatal("预览 token 应一次性消费")
	}

	items, total, err := dig.List(ctx, repo.DigitalFilter{ProjectID: projectID, Query: "应用"})
	if err != nil || total != 2 || len(items) != 2 {
		t.Fatalf("名单列表不符: total=%d len=%d err=%v", total, len(items), err)
	}

	// 库内已有：再预览同一批应全部视为 existing
	if _, err := dig.Preview(ctx, projectID, "app", names, "", "", "test"); err == nil {
		t.Fatal("全部已存在时应拒绝生成空预览")
	}

	// 本地文档：CSV 同时产出 host 与名称
	localdoc := service.NewLocalDocService()
	host := fmt.Sprintf("doc-%d.%s.test", time.Now().UnixNano(), code)
	csvDoc := "host,name,kind\n" + host + ",文档应用,app\n"
	docPreview, err := localdoc.Preview(ctx, projectID, "list.csv", []byte(csvDoc))
	if err != nil {
		t.Fatalf("文档预览失败: %v", err)
	}
	if docPreview.Hosts != 1 || docPreview.Names != 1 {
		t.Fatalf("文档计数不符: %+v", docPreview)
	}
	commit, err := localdoc.Commit(ctx, docPreview.Token, "tester")
	if err != nil {
		t.Fatalf("文档确认失败: %v", err)
	}
	if commit.Batch == nil || commit.Inserted != 1 || commit.Hosts == nil || commit.Hosts.NewSites != 1 {
		t.Fatalf("文档入库不符: %+v", commit)
	}

	// 撤销只回滚名单批次，host 站点保留
	deleted, err := dig.Undo(ctx, batch.ID)
	if err != nil || deleted != 2 {
		t.Fatalf("撤销名单失败: deleted=%d err=%v", deleted, err)
	}
	_, total, err = dig.List(ctx, repo.DigitalFilter{ProjectID: projectID})
	if err != nil || total != 1 {
		t.Fatalf("撤销后应只剩文档批次 1 条: total=%d err=%v", total, err)
	}
	var sites int
	if err := r.Pool().QueryRow(ctx, `SELECT count(*) FROM sites WHERE project_id=$1 AND host=$2`, projectID, host).Scan(&sites); err != nil || sites != 1 {
		t.Fatalf("host 站点应保留: sites=%d err=%v", sites, err)
	}
	if _, err := dig.Undo(ctx, batch.ID); err == nil {
		t.Fatal("重复撤销应报回执不存在")
	}
}
