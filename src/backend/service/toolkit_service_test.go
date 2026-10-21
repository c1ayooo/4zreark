package service

import (
	"context"
	"testing"

	"github.com/c1ayooo/4zreark/internal/githubleak"
)

func TestToolkitQuoteCheck(t *testing.T) {
	s := NewToolkitService()
	text := "HTTP/1.1 200 OK\n\nroot:x:0:0:root:/root:/bin/bash"
	ok, err := s.QuoteCheck("root:x:0:0", text)
	if err != nil || !ok {
		t.Fatalf("应命中: ok=%v err=%v", ok, err)
	}
	ok, err = s.QuoteCheck("root:x:0:1", text)
	if err != nil || ok {
		t.Fatalf("不应命中: ok=%v err=%v", ok, err)
	}
	if _, err := s.QuoteCheck("x", ""); err == nil {
		t.Fatal("空回执应报错")
	}
}

func TestToolkitPlaybooksLoaded(t *testing.T) {
	items, errs, err := NewToolkitService().Playbooks()
	if err != nil {
		t.Fatalf("读取剧本失败: %v", err)
	}
	if len(items) == 0 {
		t.Fatal("未加载到内置剧本")
	}
	if len(errs) > 0 {
		t.Fatalf("剧本解析错误: %v", errs)
	}
}

func TestGithubLeakDorksAndDetector(t *testing.T) {
	svc := NewGithubLeakService()
	if len(svc.Dorks()) == 0 {
		t.Fatal("dork 模板为空")
	}
	if _, err := githubleak.NewDetector(githubleak.Settings{
		Enabled: true, FingerprintKey: leakFingerprintKey(), MaxResultsPerKeyword: 100,
	}); err != nil {
		t.Fatalf("检测器初始化失败: %v", err)
	}
}

func TestToolkitEnterpriseProviders(t *testing.T) {
	if len(NewToolkitService().EnterpriseProviders()) == 0 {
		t.Fatal("企业数据源清单为空")
	}
}

func TestToolkitExtractGitConfig(t *testing.T) {
	resp := "HTTP/1.1 200 OK\n\n[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://admin:secret123@git.example.com/team/repo.git\n"
	f, err := NewToolkitService().Extract(context.Background(), ExtractInput{
		TemplateID: "git-config", Target: "git.example.com", Response: resp,
	})
	if err != nil {
		t.Fatalf("提取失败: %v", err)
	}
	if f == nil || f.Category == "" {
		t.Fatalf("未提取到产物: %+v", f)
	}
}
