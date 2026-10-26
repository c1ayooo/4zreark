package test

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/service"
	"github.com/xuri/excelize/v2"
)

// 字典 XLSX 导入：第一列取词表、表头跳过、去重、分段、确认落库。
func TestDictionaryXLSXPreview(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	f := excelize.NewFile()
	rows := [][]string{
		{"word"}, {"www"}, {"api"}, {"www"}, {"admin"}, {"mail"},
	}
	for i, row := range rows {
		cell, err := excelize.CoordinatesToCellName(1, i+1)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.SetCellValue("Sheet1", cell, row[0]); err != nil {
			t.Fatal(err)
		}
	}
	var buf bytes.Buffer
	if err := f.Write(&buf); err != nil {
		t.Fatal(err)
	}

	svc := service.NewPluginService()
	name := fmt.Sprintf("xlsx-dict-%d", time.Now().UnixNano())
	preview, err := svc.PreviewDictionaryXLSX(name, "subdomain", buf.Bytes())
	if err != nil {
		t.Fatalf("XLSX 预览失败: %v", err)
	}
	if preview.Total != 5 || preview.Unique != 4 || preview.Duplicates != 1 {
		t.Fatalf("XLSX 统计不符: %+v", preview)
	}
	// 表头 word 不应出现在词表里
	for _, s := range preview.Sample {
		if s == "word" {
			t.Fatal("表头行未被跳过")
		}
	}

	dict, inserted, err := svc.ImportDictionary(ctx, preview.Token)
	if err != nil || inserted != 4 {
		t.Fatalf("导入失败: inserted=%d err=%v", inserted, err)
	}
	dictID := dict.ID.Hex()
	t.Cleanup(func() {
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM dict_entries WHERE dict_id=$1`, dictID)
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM dictionaries WHERE id=$1`, dictID)
	})
	entries, total, err := svc.ListDictionaryEntries(ctx, dictID, 0, 1, 100)
	if err != nil || total != 4 || len(entries) != 4 {
		t.Fatalf("词表条目不符: total=%d len=%d err=%v", total, len(entries), err)
	}
}
