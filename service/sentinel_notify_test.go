package service

import (
	"strings"
	"testing"

	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service/notify"
)

// severity 5 档应 1:1 传给通知级别，渠道 MinLevel 才能精确到「medium 及以上」。
func TestNotifyLevelBySeverity(t *testing.T) {
	cases := map[string]notify.NotifyLevel{
		"critical": notify.NotifyLevelCritical,
		"high":     notify.NotifyLevelHigh,
		"medium":   notify.NotifyLevelMedium,
		"low":      notify.NotifyLevelLow,
		"info":     notify.NotifyLevelInfo,
		"":         notify.NotifyLevelInfo,
		"CRITICAL": notify.NotifyLevelCritical, // 大小写容错
		"unknown":  notify.NotifyLevelInfo,
	}
	for sev, want := range cases {
		if got := notifyLevelBySeverity(sev); got != want {
			t.Errorf("notifyLevelBySeverity(%q) = %s, want %s", sev, got, want)
		}
	}
}

// 渠道门槛对审计 severity 的端到端语义：medium 渠道收 medium 命中、拦 low 命中。
func TestNotifyLevelBySeverityMeetsChannelGate(t *testing.T) {
	if !notify.ChannelLevelAllowed(notifyLevelBySeverity("medium"), notify.NotifyLevelMedium) {
		t.Fatal("medium 命中应到达 medium 门槛渠道")
	}
	if notify.ChannelLevelAllowed(notifyLevelBySeverity("low"), notify.NotifyLevelMedium) {
		t.Fatal("low 命中不应到达 medium 门槛渠道")
	}
	// 旧 warning 门槛（=high）：medium 命中被拦，与 3 档时代行为一致。
	if notify.ChannelLevelAllowed(notifyLevelBySeverity("medium"), notify.NotifyLevelWarning) {
		t.Fatal("medium 命中不应到达旧 warning 门槛渠道")
	}
}

// 命中通知的标题模板应带上仓库与漏洞类别（notifyJudgeHit 组装标题的约定）。
func TestNotifyJudgeHitTitle(t *testing.T) {
	commit := &repo.GitCommit{RepoFullName: "nginx/nginx", Subject: "fix sqli"}
	v := &JudgeVerdict{
		IsSecurityFix: true,
		VulnClass:     "SQLI",
		Severity:      "high",
		Confidence:    0.9,
		Reasoning:     "补丁在拼接 SQL 前引入参数化查询",
	}
	title := "提交哨兵: " + commit.RepoFullName + " 命中 " + v.VulnClass + " 修复"
	if !strings.Contains(title, "SQLI") || !strings.Contains(title, commit.RepoFullName) {
		t.Fatalf("标题应含仓库与漏洞类别: %s", title)
	}
	if notifyLevelBySeverity(v.Severity) != notify.NotifyLevelHigh {
		t.Fatalf("high 命中通知级别 = %s", notifyLevelBySeverity(v.Severity))
	}
}
