package service

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service/notify"
)

// 巡航通知出口。此前 NotifyOnComplete/NotifyOnVuln/NotifyChannels 只落库不生效、
// 巡航失败只写 CruiseLog——本轮统一收口：
//   - 成功通知受 NotifyOnComplete 门控；
//   - 失败/超时/取消无条件告警（巡航静默失败比通知噪音更危险）；
//   - NotifyChannels 为空走全渠道，配置了渠道类型则只投指定渠道。

// cruiseVulnDigestLimit 漏洞摘要通知里最多展示的明细条数。
const cruiseVulnDigestLimit = 10

// vulnDigestItem 通知里展示的漏洞摘要行。
type vulnDigestItem struct {
	Severity string
	Name     string
	Target   string
}

var vulnSeverityRanks = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

// vulnSeverityRankOf 未知严重度排在最后，而不是当 critical（map 零值陷阱）。
func vulnSeverityRankOf(sev string) int {
	if r, ok := vulnSeverityRanks[strings.ToLower(strings.TrimSpace(sev))]; ok {
		return r
	}
	return len(vulnSeverityRanks)
}

func vulnSeverityLabel(sev string) string {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return "严重"
	case "high":
		return "高危"
	case "medium":
		return "中危"
	case "low":
		return "低危"
	case "info":
		return "提示"
	default:
		return strings.TrimSpace(sev)
	}
}

func fmtCruiseDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	sec := int64(d.Seconds())
	switch {
	case sec < 60:
		return fmt.Sprintf("%d秒", sec)
	case sec < 3600:
		return fmt.Sprintf("%d分%d秒", sec/60, sec%60)
	default:
		return fmt.Sprintf("%d小时%d分", sec/3600, sec%3600/60)
	}
}

// cruiseRunMessage 巡航一轮结束的通知。返回 nil 表示按配置不需要发：
// 成功且未开 NotifyOnComplete 时静默；失败/超时/取消无视开关直接告警。
func cruiseRunMessage(cruise *models.CruiseTask, status string, duration time.Duration,
	resultCount, vulnCount int, errMsg, taskID string) *notify.NotifyMessage {

	if status == "success" && !cruise.NotifyOnComplete {
		return nil
	}
	level := notify.NotifyLevelInfo
	icon := "✅"
	title := "巡航完成"
	switch status {
	case "failed":
		level, icon, title = notify.NotifyLevelWarning, "⚠️", "巡航失败"
	case "timeout":
		level, icon, title = notify.NotifyLevelWarning, "⏰", "巡航超时"
	case "cancelled":
		level, icon, title = notify.NotifyLevelWarning, "🛑", "巡航被取消"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "**巡航**: %s\n**耗时**: %s\n**新资产**: %d\n**漏洞**: %d",
		cruise.Name, fmtCruiseDuration(duration), resultCount, vulnCount)
	if errMsg != "" {
		fmt.Fprintf(&b, "\n**错误**: %s", errMsg)
	}

	extra := map[string]interface{}{"cruise_id": cruise.ID.Hex(), "status": status}
	if taskID != "" {
		extra["link"] = "/tasks/" + taskID
	}
	return &notify.NotifyMessage{
		Level:   level,
		Title:   icon + " " + title + ": " + cruise.Name,
		Content: b.String(),
		Source:  "cruise",
		Extra:   extra,
	}
}

// cruiseVulnDigestMessage NotifyOnVuln 开启且本轮有漏洞时的汇总通知：
// 带按严重度排序的明细（最多 cruiseVulnDigestLimit 条），不只是一个数字。
func cruiseVulnDigestMessage(cruise *models.CruiseTask, items []vulnDigestItem, taskID string) *notify.NotifyMessage {
	if len(items) == 0 {
		return nil
	}
	sorted := make([]vulnDigestItem, len(items))
	copy(sorted, items)
	sort.SliceStable(sorted, func(i, j int) bool {
		return vulnSeverityRankOf(sorted[i].Severity) < vulnSeverityRankOf(sorted[j].Severity)
	})

	byBucket := map[string]int{}
	for _, it := range sorted {
		switch strings.ToLower(strings.TrimSpace(it.Severity)) {
		case "critical", "high", "medium":
			byBucket[strings.ToLower(strings.TrimSpace(it.Severity))]++
		default:
			byBucket["other"]++
		}
	}
	level := notify.NotifyLevelWarning
	if byBucket["critical"] > 0 {
		level = notify.NotifyLevelCritical
	}

	var b strings.Builder
	fmt.Fprintf(&b, "**巡航**: %s\n**汇总**: 严重 %d / 高危 %d / 中危 %d / 其他 %d，共 %d 条\n**明细**:",
		cruise.Name, byBucket["critical"], byBucket["high"], byBucket["medium"], byBucket["other"], len(sorted))
	shown := sorted
	if len(shown) > cruiseVulnDigestLimit {
		shown = shown[:cruiseVulnDigestLimit]
	}
	for _, it := range shown {
		fmt.Fprintf(&b, "\n- [%s] %s — %s", vulnSeverityLabel(it.Severity), it.Name, it.Target)
	}
	if len(sorted) > len(shown) {
		fmt.Fprintf(&b, "\n- ……等共 %d 条", len(sorted))
	}

	extra := map[string]interface{}{"cruise_id": cruise.ID.Hex()}
	if taskID != "" {
		extra["link"] = "/tasks/" + taskID
	}
	return &notify.NotifyMessage{
		Level:   level,
		Title:   fmt.Sprintf("🚨 巡航发现 %d 个漏洞: %s", len(sorted), cruise.Name),
		Content: b.String(),
		Source:  "cruise",
		Extra:   extra,
	}
}

// digitalCruiseRunMessage 数字资产巡航完成通知（NotifyOnComplete 门控）。
// 数字资产巡航不产生扫描任务，失败走 cruiseRunMessage 的统一失败告警。
func digitalCruiseRunMessage(cruise *models.CruiseTask, res *DigitalCruiseCycleResult) *notify.NotifyMessage {
	if !cruise.NotifyOnComplete || res == nil {
		return nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "**巡航**: %s\n**企业**: %d 个（成功采集 %d）\n**新发现资产**: %d\n**新候选**: %d\n**已在名单**: %d",
		cruise.Name, res.Entities, res.Checked, res.Found, res.Candidates, res.Imported)
	if len(res.Warnings) > 0 {
		fmt.Fprintf(&b, "\n**警告**: %s", strings.Join(res.Warnings, "；"))
	}
	return &notify.NotifyMessage{
		Level:   notify.NotifyLevelInfo,
		Title:   "✅ 数字资产巡航完成: " + cruise.Name,
		Content: b.String(),
		Source:  "cruise",
		Extra: map[string]interface{}{
			"cruise_id": cruise.ID.Hex(),
			"link":      fmt.Sprintf("/projects/%d", cruise.ProjectID),
		},
	}
}

// sendCruiseNotification 按巡航自带配置路由：NotifyChannels 为空走全渠道。
func (s *CruiseService) sendCruiseNotification(cruise *models.CruiseTask, msg *notify.NotifyMessage) {
	if cruise == nil || msg == nil {
		return
	}
	notify.GetGlobalManager().SendTargetedAsync(msg, cruise.NotifyChannels)
}

// cruiseVulnItems 拉本轮任务的漏洞结果明细（限量），供摘要通知展示。
// 拉不到明细时返回空——调用方降级为不发摘要，仍保留完成通知里的计数。
func (s *CruiseService) cruiseVulnItems(taskID string) []vulnDigestItem {
	r := repo.Default()
	if r == nil || taskID == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rows, _, err := r.Results().ListByTask(ctx, taskID, string(models.ResultTypeVuln), 1, cruiseVulnDigestLimit, "", 0)
	if err != nil {
		log.Printf("[CruiseService] 加载漏洞明细用于通知失败: %v", err)
		return nil
	}
	items := make([]vulnDigestItem, 0, len(rows))
	for _, row := range rows {
		name, _ := row.Data["name"].(string)
		target, _ := row.Data["target"].(string)
		severity, _ := row.Data["severity"].(string)
		items = append(items, vulnDigestItem{Severity: severity, Name: name, Target: target})
	}
	return items
}
