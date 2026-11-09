package service

// 提交哨兵 → IM 通知的旁路接线（v0.3 §8.5 的最小落地）。
//
// 发送原则：只发「人必须知道」的两类事——判定命中安全修复、采集批次失败；
// 其余过程一律留在 run_event，靠前端批次视图回放，避免刷屏。
// 未配置任何渠道时 SendAsync 仍会落一条站内通知（notifications 表），行为安全。

import (
	"fmt"
	"strings"

	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/repo"

	"github.com/c1ayooo/4zreark/service/notify"
)

// notifyLevelBySeverity 把判定 severity 映射到通知级别：5 档 1:1 传递，
// 渠道侧 MinLevel 即可按「medium 及以上」这类门槛精确过滤。
func notifyLevelBySeverity(severity string) notify.NotifyLevel {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return notify.NotifyLevelCritical
	case "high":
		return notify.NotifyLevelHigh
	case "medium":
		return notify.NotifyLevelMedium
	case "low":
		return notify.NotifyLevelLow
	default:
		return notify.NotifyLevelInfo
	}
}

// sentinelCommitLink 生成提交详情的深链：配了 public_url 给 IM 用绝对链接，
// 没配则回退站内相对路径（notifications.extra.link 由前端 notifyLink 消费）。
func sentinelCommitLink(commitID int64) string {
	path := fmt.Sprintf("/sentinel/commits/%d", commitID)
	if cfg := config.GetConfig(); cfg != nil && cfg.Server.PublicURL != "" {
		return strings.TrimRight(cfg.Server.PublicURL, "/") + path
	}
	return path
}

// notifyJudgeHit 判定命中安全修复：站内 + 外发渠道各一条，reasoning 截断防长文。
func notifyJudgeHit(commit *repo.GitCommit, v *JudgeVerdict, judgmentID int64) {
	mgr := notify.GetGlobalManager()
	if mgr == nil || commit == nil || v == nil {
		return
	}
	reasoning := strings.TrimSpace(v.Reasoning)
	if len(reasoning) > 300 {
		reasoning = reasoning[:300] + "…"
	}
	msg := &notify.NotifyMessage{
		Level: notifyLevelBySeverity(v.Severity),
		Title: fmt.Sprintf("提交哨兵: %s 命中 %s 修复", commit.RepoFullName, v.VulnClass),
		Content: fmt.Sprintf(
			"**仓库**: %s\n**提交**: %s\n**漏洞类别**: %s　**级别**: %s　**置信度**: %.2f\n%s",
			commit.RepoFullName, commit.Subject, v.VulnClass, v.Severity, v.Confidence, reasoning),
		Source: "sentinel",
		Extra: map[string]interface{}{
			"link":       sentinelCommitLink(commit.ID),
			"finding_id": judgmentID,
			"sha":        commit.SHA,
		},
	}
	mgr.SendAsync(msg)
}

// notifyCollectFailed 采集批次失败告警（repo 名从 emit 的 payload 里取，取不到就用占位）。
func notifyCollectFailed(repoFullName, errMsg string) {
	mgr := notify.GetGlobalManager()
	if mgr == nil {
		return
	}
	if strings.TrimSpace(repoFullName) == "" {
		repoFullName = "未知仓库"
	}
	if len(errMsg) > 300 {
		errMsg = errMsg[:300] + "…"
	}
	mgr.SendAsync(&notify.NotifyMessage{
		Level:   notify.NotifyLevelWarning,
		Title:   fmt.Sprintf("提交哨兵: %s 采集失败", repoFullName),
		Content: fmt.Sprintf("**仓库**: %s\n**错误**: %s", repoFullName, errMsg),
		Source:  "sentinel",
		Extra:   map[string]interface{}{"link": "/sentinel/audit/tasks"},
	})
}
