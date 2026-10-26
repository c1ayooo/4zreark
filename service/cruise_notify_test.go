package service

import (
	"strings"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/oid"
	"github.com/c1ayooo/4zreark/service/notify"
)

func TestCruiseRunMessageSuccessGatedByConfig(t *testing.T) {
	cruise := &models.CruiseTask{ID: oid.NewObjectID(), Name: "每日资产巡航"}
	if msg := cruiseRunMessage(cruise, "success", 90*time.Minute, 12, 3, "", "task123"); msg != nil {
		t.Fatalf("未开启 NotifyOnComplete 的成功巡航不应通知，got %+v", msg)
	}

	cruise.NotifyOnComplete = true
	msg := cruiseRunMessage(cruise, "success", 90*time.Minute, 12, 3, "", "task123")
	if msg == nil {
		t.Fatal("开启 NotifyOnComplete 后应产出通知")
	}
	if msg.Level != notify.NotifyLevelInfo {
		t.Errorf("成功通知级别 = %s, want info", msg.Level)
	}
	if msg.Extra["link"] != "/tasks/task123" {
		t.Errorf("link = %v, want /tasks/task123", msg.Extra["link"])
	}
	for _, want := range []string{"每日资产巡航", "1小时30分", "12", "3"} {
		if !strings.Contains(msg.Content, want) {
			t.Errorf("通知内容缺 %q: %s", want, msg.Content)
		}
	}
}

func TestCruiseRunMessageFailureAlwaysNotifies(t *testing.T) {
	cruise := &models.CruiseTask{ID: oid.NewObjectID(), Name: "漏洞巡航"} // NotifyOnComplete=false
	failed := cruiseRunMessage(cruise, "failed", time.Minute, 0, 0, "nuclei 不可用", "")
	if failed == nil {
		t.Fatal("失败必须无条件告警，即使未开 NotifyOnComplete")
	}
	if failed.Level != notify.NotifyLevelWarning {
		t.Errorf("失败通知级别 = %s, want warning", failed.Level)
	}
	if !strings.Contains(failed.Title, "巡航失败") || !strings.Contains(failed.Content, "nuclei 不可用") {
		t.Errorf("失败通知标题/内容不完整: %s / %s", failed.Title, failed.Content)
	}

	timeout := cruiseRunMessage(cruise, "timeout", 24*time.Hour, 0, 0, "任务执行超时", "t1")
	if timeout == nil || timeout.Level != notify.NotifyLevelWarning || !strings.Contains(timeout.Title, "巡航超时") {
		t.Fatalf("超时通知不符合预期: %+v", timeout)
	}

	cancelled := cruiseRunMessage(cruise, "cancelled", time.Minute, 0, 0, "", "")
	if cancelled == nil || !strings.Contains(cancelled.Title, "巡航被取消") {
		t.Fatalf("取消通知不符合预期: %+v", cancelled)
	}
}

func TestCruiseVulnDigestMessage(t *testing.T) {
	cruise := &models.CruiseTask{ID: oid.NewObjectID(), Name: "全量巡航"}
	if msg := cruiseVulnDigestMessage(cruise, nil, ""); msg != nil {
		t.Fatalf("无漏洞时不应产出摘要通知, got %+v", msg)
	}

	items := []vulnDigestItem{
		{Severity: "high", Name: "H1", Target: "a.com"},
		{Severity: "medium", Name: "M1", Target: "a.com"},
		{Severity: "critical", Name: "C1", Target: "b.com"},
		{Severity: "high", Name: "H2", Target: "b.com"},
		{Severity: "Critical", Name: "C2", Target: "c.com"},
	}
	msg := cruiseVulnDigestMessage(cruise, items, "task9")
	if msg == nil {
		t.Fatal("有漏洞应产出摘要通知")
	}
	if msg.Level != notify.NotifyLevelCritical {
		t.Errorf("含严重的摘要级别 = %s, want critical", msg.Level)
	}
	if c := strings.Index(msg.Content, "[严重]"); c < 0 || c > strings.Index(msg.Content, "[高危]") {
		t.Errorf("严重应排在高危之前: %s", msg.Content)
	}
	if !strings.Contains(msg.Content, "共 5 条") || msg.Extra["link"] != "/tasks/task9" {
		t.Errorf("汇总计数或链接不符: %s / %v", msg.Content, msg.Extra)
	}

	// 无 critical 时降为 warning。
	msg = cruiseVulnDigestMessage(cruise, items[:1], "")
	if msg == nil || msg.Level != notify.NotifyLevelWarning {
		t.Fatalf("仅高危时级别应为 warning: %+v", msg)
	}
}

func TestCruiseVulnDigestMessageTruncates(t *testing.T) {
	cruise := &models.CruiseTask{ID: oid.NewObjectID(), Name: "c"}
	items := make([]vulnDigestItem, cruiseVulnDigestLimit+5)
	for i := range items {
		items[i] = vulnDigestItem{Severity: "high", Name: "V", Target: "t.com"}
	}
	msg := cruiseVulnDigestMessage(cruise, items, "")
	if msg == nil {
		t.Fatal("want message")
	}
	if got := strings.Count(msg.Content, "- [高危]"); got != cruiseVulnDigestLimit {
		t.Errorf("明细行数 = %d, want %d", got, cruiseVulnDigestLimit)
	}
	if !strings.Contains(msg.Content, "共 15 条") {
		t.Errorf("截断后应保留总数: %s", msg.Content)
	}
}

func TestDigitalCruiseRunMessage(t *testing.T) {
	cruise := &models.CruiseTask{ID: oid.NewObjectID(), Name: "数字资产巡航", ProjectID: 7}
	if msg := digitalCruiseRunMessage(cruise, &DigitalCruiseCycleResult{Found: 3}); msg != nil {
		t.Fatalf("未开启 NotifyOnComplete 不应通知, got %+v", msg)
	}
	cruise.NotifyOnComplete = true
	msg := digitalCruiseRunMessage(cruise, &DigitalCruiseCycleResult{
		Entities: 6, Checked: 5, Found: 8, Candidates: 4, Imported: 1,
		Warnings: []string{"某企业：Cookie 过期"},
	})
	if msg == nil {
		t.Fatal("want message")
	}
	for _, want := range []string{"数字资产巡航", "6", "5", "8", "4", "1", "Cookie 过期"} {
		if !strings.Contains(msg.Content, want) {
			t.Errorf("内容缺 %q: %s", want, msg.Content)
		}
	}
	if msg.Extra["link"] != "/projects/7" {
		t.Errorf("link = %v, want /projects/7", msg.Extra["link"])
	}
}

func TestFmtCruiseDuration(t *testing.T) {
	cases := map[time.Duration]string{
		45 * time.Second:               "45秒",
		5*time.Minute + 30*time.Second: "5分30秒",
		(2*time.Hour + 5*time.Minute):  "2小时5分",
		-1 * time.Second:               "0秒",
	}
	for in, want := range cases {
		if got := fmtCruiseDuration(in); got != want {
			t.Errorf("fmtCruiseDuration(%v) = %q, want %q", in, got, want)
		}
	}
}
