package service

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestPreviewDictionary(t *testing.T) {
	svc := &PluginService{}
	p, err := svc.PreviewDictionary("d1", "subdomain", "a\nb\na\n\n c \n")
	if err != nil {
		t.Fatalf("预览失败: %v", err)
	}
	if p.Total != 4 || p.Unique != 3 || p.Duplicates != 1 || p.Segments != 1 {
		t.Fatalf("字典预览统计不符: %+v", p)
	}
	if len(p.Sample) != 3 {
		t.Fatalf("样例数量不符: %+v", p.Sample)
	}

	if _, err := svc.PreviewDictionary("d1", "not-a-type", "a"); err == nil {
		t.Fatal("非法字典类型应被拒绝")
	}
	if _, err := svc.PreviewDictionary("d1", "subdomain", " \n\n"); err == nil {
		t.Fatal("空词表应被拒绝")
	}
}

func TestImportDictionaryExpired(t *testing.T) {
	svc := &PluginService{}
	p, err := svc.PreviewDictionary("d2", "subdomain", "a\nb")
	if err != nil {
		t.Fatal(err)
	}
	dictPreviews.mu.Lock()
	dictPreviews.items[p.Token].expiresAt = time.Now().Add(-time.Minute)
	dictPreviews.mu.Unlock()

	if _, _, err := svc.ImportDictionary(context.Background(), p.Token); !errors.Is(err, ErrDictPreviewExpired) {
		t.Fatalf("过期字典预览应返回 ErrDictPreviewExpired，实际 %v", err)
	}
}

func TestPreviewDictionaryCSVAndTSV(t *testing.T) {
	svc := &PluginService{}
	csvText := "\ufeffword,note\na,x\na,y\nb,z\n"
	p, err := svc.PreviewDictionaryFormatted("d3", "subdomain", csvText, "csv")
	if err != nil {
		t.Fatalf("CSV 预览失败: %v", err)
	}
	if p.Total != 3 || p.Unique != 2 || p.Duplicates != 1 {
		t.Fatalf("CSV 统计不符: %+v", p)
	}
	if p.Sample[0] != "a" || p.Sample[1] != "b" {
		t.Fatalf("CSV 应取第一列: %+v", p.Sample)
	}

	tsv, err := svc.PreviewDictionaryFormatted("d4", "directory", "path\nadmin\napi\n", "tsv")
	if err != nil || tsv.Total != 2 || tsv.Unique != 2 {
		t.Fatalf("TSV 预览不符: %+v err=%v", tsv, err)
	}

	if _, err := svc.PreviewDictionaryFormatted("d5", "subdomain", "x", "xlsx"); err == nil {
		t.Fatal("XLSX 应明确提示另存 CSV")
	}
}
