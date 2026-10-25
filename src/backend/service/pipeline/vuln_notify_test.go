package pipeline

import (
	"strings"
	"testing"

	"github.com/c1ayooo/4zreark/service/notify"
)

func TestVulnFindingsMessageSkipsLowSeverityAndEmpty(t *testing.T) {
	if msg := vulnFindingsMessage(nil); msg != nil {
		t.Fatalf("空列表应返回 nil, got %+v", msg)
	}
	lowOnly := []VulnResult{
		{Severity: "medium", Name: "M", Target: "a.com"},
		{Severity: "low", Name: "L", Target: "a.com"},
	}
	if msg := vulnFindingsMessage(lowOnly); msg != nil {
		t.Fatalf("中低危不应触发高危通知, got %+v", msg)
	}
}

func TestVulnFindingsMessageAggregates(t *testing.T) {
	found := []VulnResult{
		{Severity: "high", Name: "Swagger 泄漏", Target: "https://a.com"},
		{Severity: "critical", Name: "RCE-2026", Target: "https://b.com"},
		{Severity: "high", Name: "弱口令", Target: "https://a.com"},
		{Severity: "critical", Name: "未授权访问", Target: "https://c.com"},
	}
	msg := vulnFindingsMessage(found)
	if msg == nil {
		t.Fatal("want message")
	}
	if msg.Level != notify.NotifyLevelCritical {
		t.Errorf("含严重的级别 = %s, want critical", msg.Level)
	}
	if !strings.Contains(msg.Title, "4 个高危漏洞") || !strings.Contains(msg.Title, "3 个目标") {
		t.Errorf("标题统计不符: %s", msg.Title)
	}
	if c := strings.Index(msg.Content, "[严重]"); c < 0 || c > strings.Index(msg.Content, "[高危]") {
		t.Errorf("严重应排在高危之前: %s", msg.Content)
	}
	if msg.Source != "vuln_scanner" {
		t.Errorf("source = %s, want vuln_scanner", msg.Source)
	}
}

func TestVulnFindingsMessageHighOnlyIsWarning(t *testing.T) {
	msg := vulnFindingsMessage([]VulnResult{{Severity: "high", Name: "H", Target: "x.com"}})
	if msg == nil || msg.Level != notify.NotifyLevelWarning {
		t.Fatalf("仅高危时级别应为 warning: %+v", msg)
	}
}

func TestVulnFindingsMessageTruncates(t *testing.T) {
	found := make([]VulnResult, vulnNotifyTopN+5)
	for i := range found {
		found[i] = VulnResult{Severity: "high", Name: "V", Target: "t.com"}
	}
	msg := vulnFindingsMessage(found)
	if msg == nil {
		t.Fatal("want message")
	}
	if got := strings.Count(msg.Content, "- ["); got != vulnNotifyTopN {
		t.Errorf("明细行数 = %d, want %d", got, vulnNotifyTopN)
	}
	if !strings.Contains(msg.Content, "共 15 条") {
		t.Errorf("截断后应保留总数: %s", msg.Content)
	}
}
