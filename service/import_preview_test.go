package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/repo"
)

func TestPreviewImportCounts(t *testing.T) {
	svc := &AssetService{}
	recs := []repo.RawRecord{
		{Host: "A.example.com", Port: 443, Protocol: "https", Value: "https://a.example.com"},
		{Host: "a.example.com.", Port: 443, Protocol: "https", Value: "https://a.example.com"},
		{Host: "", Port: 443, Protocol: "https"},
		{Host: "b.example.com", Port: 80, Protocol: "http", Value: "http://b.example.com"},
	}
	p, err := svc.PreviewImport(context.Background(), 1, "test", recs)
	if err != nil {
		t.Fatalf("预览失败: %v", err)
	}
	if p.Total != 4 || p.Unique != 2 || p.Duplicates != 1 || p.Invalid != 1 {
		t.Fatalf("预览统计不符: %+v", p)
	}
	if p.Token == "" || len(p.Sample) != 2 {
		t.Fatalf("token/sample 不符: %+v", p)
	}
	if d := time.Until(p.ExpiresAt); d < 14*time.Minute || d > 16*time.Minute {
		t.Fatalf("预览有效期应约 15 分钟，实际 %s", d)
	}
}

func TestCommitImportExpired(t *testing.T) {
	old := importPreviewNow
	defer func() { importPreviewNow = old }()

	base := time.Now()
	importPreviewNow = func() time.Time { return base }

	svc := &AssetService{}
	p, err := svc.PreviewImport(context.Background(), 1, "test", []repo.RawRecord{{Host: "a.example.com"}})
	if err != nil {
		t.Fatal(err)
	}

	importPreviewNow = func() time.Time { return base.Add(16 * time.Minute) }
	if _, err := svc.CommitImport(context.Background(), p.Token); !errors.Is(err, ErrImportPreviewExpired) {
		t.Fatalf("过期预览应返回 ErrImportPreviewExpired，实际 %v", err)
	}
	// 一次性消费：再次提交应报不存在
	if _, err := svc.CommitImport(context.Background(), p.Token); err == nil {
		t.Fatal("过期 token 应已被消费")
	}
}
