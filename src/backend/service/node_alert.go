package service

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service/notify"
)

const (
	// nodeOfflineThreshold：worker 每 30 秒一次心跳，5 分钟足够容忍网络抖动，
	// 又不会让一次容器重启拖太久才告警。
	nodeOfflineThreshold = 5 * time.Minute
	nodeAlertInterval    = 60 * time.Second
)

// nodeAlertMarked 记录"已经就离线告过警"的节点，保证一个故障只推一条，
// 恢复时再推一条。进程重启会丢标记，此时已离线的节点不会重复补发。
var nodeAlertMarked sync.Map

// StartNodeWatchdog 巡检节点心跳，把超时节点置为离线并推送告警，心跳恢复后再推一条恢复通知。
func StartNodeWatchdog(ctx context.Context) {
	go func() {
		log.Printf("[NodeWatchdog] 启动：离线阈值 %s，巡检间隔 %s", nodeOfflineThreshold, nodeAlertInterval)
		ticker := time.NewTicker(nodeAlertInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				log.Println("[NodeWatchdog] 已停止")
				return
			case <-ticker.C:
				sweepNodeHeartbeats(ctx)
			}
		}
	}()
}

func sweepNodeHeartbeats(ctx context.Context) {
	r := repo.Default()
	if r == nil {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	nodes, _, err := r.Nodes().List(cctx, "", "", 1, 200)
	if err != nil {
		log.Printf("[NodeWatchdog] 查询节点失败: %v", err)
		return
	}

	for _, n := range nodes {
		// 停用和已吊销的节点本来就不该在线，不参与告警。
		if n.Status == models.NodeStatusDisabled || n.RevokedAt != nil {
			continue
		}
		age := time.Since(n.LastHeartbeat)
		_, marked := nodeAlertMarked.Load(n.NodeID)

		if age <= nodeOfflineThreshold {
			if marked {
				nodeAlertMarked.Delete(n.NodeID)
				log.Printf("[NodeWatchdog] 节点 %s 恢复心跳，延迟 %s", n.Name, age.Round(time.Second))
				pushNodeEvent(n, true, age)
			}
			continue
		}

		// 心跳超时：数据库状态还是 online/busy 的先翻成 offline，让界面上立刻可见。
		if n.Status == models.NodeStatusOnline || n.Status == models.NodeStatusBusy {
			if uerr := r.Nodes().UpdateFields(cctx, n.ID.Hex(), map[string]any{
				"status": string(models.NodeStatusOffline),
			}); uerr != nil {
				log.Printf("[NodeWatchdog] 置离线失败 %s: %v", n.Name, uerr)
			}
		}
		if !marked {
			nodeAlertMarked.Store(n.NodeID, struct{}{})
			log.Printf("[NodeWatchdog] 节点 %s 离线，最后心跳 %s", n.Name, n.LastHeartbeat.Format("2006-01-02 15:04:05"))
			pushNodeEvent(n, false, age)
		}
	}
}

func pushNodeEvent(n *models.ScannerNode, online bool, age time.Duration) {
	m := notify.GetGlobalManager()
	if m == nil {
		return
	}

	title := fmt.Sprintf("节点离线：%s", n.Name)
	level := notify.NotifyLevelCritical
	content := fmt.Sprintf(
		"节点 %s 已超过 %s 无心跳，判定离线。\n\n节点 ID：%s\n最后心跳：%s\n离线时长：%s\n版本：%s",
		n.Name, nodeOfflineThreshold, n.NodeID,
		n.LastHeartbeat.Format("2006-01-02 15:04:05"),
		age.Round(time.Second), n.Version,
	)
	if online {
		title = fmt.Sprintf("节点恢复：%s", n.Name)
		level = notify.NotifyLevelInfo
		content = fmt.Sprintf(
			"节点 %s 心跳已恢复，重新上线。\n\n节点 ID：%s\n当前心跳延迟：%s\n版本：%s",
			n.Name, n.NodeID, age.Round(time.Second), n.Version,
		)
	}

	m.SendAsync(&notify.NotifyMessage{
		Level:   level,
		Title:   title,
		Content: content,
		Source:  "node-watchdog",
	})
}
