package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"strconv"
	"strings"

	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/internal/entityid"
	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/repo"
)

// IngestTaskRaw 在任务完成后把本任务落库的 raw_records 转成原文快照，
// 并按 gate_mode 投入 collection_gate 影子队列。
//
// 该函数在独立 goroutine + 独立超时 ctx 中执行：写快照/入队失败只记日志，
// 不回滚任务状态、不阻塞完成通知。
func IngestTaskRaw(ctx context.Context, task *models.Task) {
	if task == nil || task.ID.IsZero() {
		return
	}
	cfg := config.GetConfig().Collection
	if cfg.GateMode == "" || cfg.GateMode == "off" {
		return
	}
	store := repo.NewCollectionRepo()
	aiStore := repo.NewCollectionAIRepo()
	if store == nil || aiStore == nil {
		log.Printf("[Collection] 跳过 raw 快照：数据层未初始化")
		return
	}

	rows, err := store.TaskRawForSnapshot(ctx, task.ID.Hex(), 500)
	if err != nil {
		log.Printf("[Collection] 读取任务 %s raw_records 失败: %v", task.ID.Hex(), err)
		return
	}
	if len(rows) == 0 {
		return
	}

	gate := DefaultCollectionGateQueue()
	written := 0
	for _, r := range rows {
		body := strings.TrimSpace(r.Evidence)
		if body == "" {
			body = strings.TrimSpace(r.Value)
		}
		if body == "" {
			continue
		}
		entity := entityid.HostPort(r.Host, strconv.Itoa(r.Port))
		sum := sha256.Sum256([]byte(body))
		if err := aiStore.UpsertSnapshot(ctx, &repo.SnapshotRow{
			RawID:       r.RawID,
			TaskID:      task.ID.Hex(),
			EntityID:    entity,
			Source:      "scan",
			Body:        body,
			ContentHash: hex.EncodeToString(sum[:]),
		}); err != nil {
			log.Printf("[Collection] 写 raw 快照失败 task=%s raw=%s: %v", task.ID.Hex(), r.RawID, err)
			continue
		}
		written++
		if gate != nil {
			if err := gate.Enqueue(ctx, r.RawID); err != nil {
				log.Printf("[Collection] Gate 入队失败 raw=%s: %v", r.RawID, err)
			}
		}
	}
	log.Printf("[Collection] 任务 %s 写入 %d/%d 条 raw 快照（gate=%s）",
		task.ID.Hex(), written, len(rows), cfg.GateMode)
}
