package service

import (
	"context"
	"log"
	"time"

	"github.com/c1ayooo/4zreark/models"
)

const (
	staleNodeHeartbeat = 2 * time.Minute
	staleTaskIdle      = 5 * time.Minute
	staleTaskHard      = 6 * time.Hour
)

// StartStaleTaskReaper 定期回收「执行节点已离线」或「长时间无进展」的 running 任务。
// 不依赖人工改库：任务状态和 River job 一起收口，避免队列里留下 running 僵尸。
func StartStaleTaskReaper(ctx context.Context) {
	go func() {
		reapStaleTasks(ctx)
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				reapStaleTasks(ctx)
			}
		}
	}()
}

func reapStaleTasks(ctx context.Context) {
	// 终态任务遗留的 running/queued River job 一并清掉。
	if q := DefaultScanQueue(); q != nil {
		if n, err := q.CancelTerminal(ctx); err != nil {
			log.Printf("[StaleReaper] 清理终态任务队列失败: %v", err)
		} else if n > 0 {
			log.Printf("[StaleReaper] 清理终态任务 River job %d 个", n)
		}
	}

	svc := NewTaskService()
	store, _, err := svc.stores()
	if err != nil {
		return
	}
	now := time.Now()
	tasks, err := store.ListStaleRunning(ctx,
		now.Add(-staleNodeHeartbeat),
		now.Add(-staleTaskIdle),
		now.Add(-staleTaskHard),
	)
	if err != nil {
		log.Printf("[StaleReaper] 查询僵尸任务失败: %v", err)
		return
	}
	for _, task := range tasks {
		id := task.ID.Hex()
		msg := "执行节点离线或任务长时间无进展，已自动回收"
		if err := svc.UpdateTask(id, map[string]interface{}{
			"status":       models.TaskStatusFailed,
			"last_error":   msg,
			"completed_at": now,
		}); err != nil {
			log.Printf("[StaleReaper] 标记任务 %s 失败: %v", id, err)
			continue
		}
		if q := DefaultScanQueue(); q != nil {
			if _, err := q.CancelAll(ctx, id); err != nil {
				log.Printf("[StaleReaper] 取消任务 %s 的 River job 失败: %v", id, err)
			}
		}
		log.Printf("[StaleReaper] 已回收任务 %s（node=%s, updated=%s）", id, task.NodeID, task.UpdatedAt.Format(time.RFC3339))
	}
}
