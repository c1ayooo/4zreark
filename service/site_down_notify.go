package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service/notify"
)

// 站点连通性事件的通知接入：判死（down）走 repo 钩子，恢复（reappear）
// 在 VerifyService 事件落库处直调。IM 侧 critical=失联、info=恢复。

// InstallSiteDownNotifyHook 把站点判死接入通知漏斗（critical 级）。
// master 启动时安装一次；worker 不安装、不发通知。
func InstallSiteDownNotifyHook() {
	repo.OnSiteDown = func(projectID, siteID int64, value, reason string) {
		content := fmt.Sprintf("**资产**: %s\n**失败原因**: %s\n连续探测失败达到阈值，已标记失联；恢复后会再通知。",
			value, connectivityReasonLabel(reason))
		notify.GetGlobalManager().NotifyAssetChangeWithLevel(
			notify.NotifyLevelCritical, "资产失联", content,
			map[string]interface{}{
				"link":       fmt.Sprintf("/assets/%d", siteID),
				"site_id":    siteID,
				"project_id": projectID,
			})
	}
}

// NotifySiteReappear 失联资产恢复通知（info 级）。调用方自带带超时的 ctx。
func NotifySiteReappear(ctx context.Context, siteID int64, prevState string) {
	host, err := repo.NewAssetRepo().SiteHost(ctx, siteID)
	if err != nil {
		host = ""
	}
	content := fmt.Sprintf("**资产**: %s\n已从「%s」恢复可达。", host, stateLabelCN(prevState))
	notify.GetGlobalManager().NotifyAssetChangeWithLevel(
		notify.NotifyLevelInfo, "失联资产恢复", content,
		map[string]interface{}{
			"link":    fmt.Sprintf("/assets/%d", siteID),
			"site_id": siteID,
		})
}

// connectivityReasonLabel 把探测失败原因码翻译成人话；未知码原样透出。
func connectivityReasonLabel(reason string) string {
	switch strings.TrimSpace(reason) {
	case "":
		return "未知"
	case "http_5xx", "5xx":
		return "服务端 5xx 错误"
	case "timeout":
		return "连接超时"
	case "conn_refused", "refused":
		return "连接被拒绝"
	case "dns_fail", "nxdomain":
		return "域名解析失败"
	default:
		return reason
	}
}

func stateLabelCN(state string) string {
	switch state {
	case "lost":
		return "失联"
	case "archived":
		return "已归档"
	default:
		if state == "" {
			return "未知状态"
		}
		return state
	}
}
