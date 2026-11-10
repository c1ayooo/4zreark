// 高危产物流水线的 River 持久化作业。
//
// 之前的实现是「判定命中瞬间起 goroutine」——不持久、重启即丢、存量数据永远
// 不会补跑，导致高危发现大量没有 python-poc / nuclei 产物。现在改为 river job：
// 判定命中入队、启动时回填存量、幂等可重试。
//
// worker 在主进程消费（产物生成依赖 LLM 客户端与本地 mirror，不需要 docker），
// 串行 MaxWorkers=1 控制 LLM 成本与速率。
package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/c1ayooo/4zreark/repo"
	"github.com/riverqueue/river"
)

const (
	SentinelArtifactsQueueName = "sentinel_artifacts"
	SentinelArtifactsJobKind   = "sentinel_artifacts_finding"
)

// SentinelArtifactsArgs 为一条发现生成 LLM 验证产物（深审 → python-poc → exploit-guide）。
type SentinelArtifactsArgs struct {
	FindingID int64 `json:"finding_id" river:"unique"`
	CommitID  int64 `json:"commit_id"`
}

// Kind 实现 river.JobArgs。
func (SentinelArtifactsArgs) Kind() string { return SentinelArtifactsJobKind }

type sentinelArtifactsWorker struct {
	river.WorkerDefaults[SentinelArtifactsArgs]
	judge *SentinelJudge
}

func (w *sentinelArtifactsWorker) Work(ctx context.Context, job *river.Job[SentinelArtifactsArgs]) error {
	if w.judge == nil {
		return errors.New("产物流水线 worker 归属主进程（需 LLM 客户端），本进程不应执行该作业")
	}
	if err := sentinelGate.Acquire(ctx); err != nil {
		return sentinelJobError(err)
	}
	defer sentinelGate.Release()
	// 单条流水线最多三次长 LLM 调用；限时略低于全局 JobTimeout（30m）。
	// 超时则 river 重试（MaxAttempts=2），而产物生成幂等（同名 draft 跳过），
	// 重试会接着补齐缺失的产物，不会重复消耗。
	runCtx, cancel := context.WithTimeout(ctx, 25*time.Minute)
	defer cancel()
	store := repo.Default().Sentinel()
	f, err := store.GetFinding(runCtx, job.Args.FindingID)
	if err != nil {
		// 发现被删等永久性缺失：取消而不是重试。
		return river.JobCancel(fmt.Errorf("发现不存在: %w", err))
	}

	// 分析过程事件流：run_type=artifacts，事件带 finding_id + commit_id，
	// 与判定事件一起被分析结果页按提交回放。
	runID, runErr := store.CreateRun(runCtx, &repo.SentinelRun{
		RunType: "artifacts", Status: "running", Total: 1,
	})
	if runErr != nil {
		log.Printf("[Sentinel] 创建产物流水线批次失败 finding=%d: %v", job.Args.FindingID, runErr)
	} else {
		_ = store.UpdateRun(runCtx, runID, map[string]interface{}{"started_at": time.Now()})
	}
	emit := func(level, kind, message string, payload map[string]interface{}) {
		if runErr != nil {
			return
		}
		p := make(map[string]interface{}, len(payload)+2)
		for k, v := range payload {
			p[k] = v
		}
		p["finding_id"] = job.Args.FindingID
		p["commit_id"] = job.Args.CommitID
		data, _ := json.Marshal(p)
		if _, err := store.AppendRunEvent(runCtx, &repo.SentinelRunEvent{
			RunID: runID, Level: level, Kind: kind, Message: message, Payload: data,
		}); err != nil {
			log.Printf("[Sentinel] 写产物流水线事件失败 run=%d: %v", runID, err)
		}
	}
	finishRun := func(status, runErrMsg string) {
		if runErr != nil {
			return
		}
		fields := map[string]interface{}{"status": status, "processed": 1, "finished_at": time.Now()}
		if runErrMsg != "" {
			fields["error"] = runErrMsg
		}
		if err := store.UpdateRun(runCtx, runID, fields); err != nil {
			log.Printf("[Sentinel] 收尾产物流水线批次失败 run=%d: %v", runID, err)
		}
	}

	emit("info", "artifacts_start", fmt.Sprintf("高危产物流水线开始（发现 #%d %s 级）", f.ID, f.Grade), nil)
	err = runHighRiskArtifacts(runCtx, w.judge, job.Args.FindingID, job.Args.CommitID, f.VulnClass, emit)
	if err != nil {
		emit("error", "artifacts_failed", err.Error(), nil)
		finishRun("failed", err.Error())
		return err
	}
	emit("info", "artifacts_done", "产物流水线完成", nil)
	finishRun("completed", "")
	return nil
}

// EnqueueArtifacts 把产物流水线放进队列（幂等：同一发现排队中不会重复入队）。
func (q *SentinelQueue) EnqueueArtifacts(ctx context.Context, findingID, commitID int64) error {
	if q == nil || q.client == nil {
		return errors.New("提交哨兵队列未初始化")
	}
	_, err := q.client.Insert(ctx, SentinelArtifactsArgs{FindingID: findingID, CommitID: commitID}, &river.InsertOpts{
		Queue:       SentinelArtifactsQueueName,
		MaxAttempts: 3,
		UniqueOpts:  sentinelUniqueOpts(),
	})
	if err != nil {
		return fmt.Errorf("产物流水线入队失败: %w", err)
	}
	return nil
}

// EnqueueArtifactsOrDefault 判定 worker 侧的入队入口：队列未启用时返回错误
// （由调用方记日志），不再退化为 goroutine——产物流水线必须可持久、可重试。
func EnqueueArtifactsOrDefault(ctx context.Context, findingID, commitID int64) error {
	q := DefaultSentinelQueue()
	if q == nil {
		return errors.New("提交哨兵队列未初始化")
	}
	return q.EnqueueArtifacts(ctx, findingID, commitID)
}

// BackfillHighRiskArtifacts 把「高危且从未生成过深审产物」的发现批量入队产物流水线。
// 用于存量数据回填：产物流水线上线前的历史高危发现不会自动补跑，靠这个入口补。
// 入队幂等（river unique + deep-analysis 缺失判断），可重复调用。
func BackfillHighRiskArtifacts(ctx context.Context, limit int) (enqueued int, err error) {
	if limit <= 0 || limit > 200 {
		limit = 200
	}
	store := repo.Default().Sentinel()
	refs, err := store.ListHighRiskFindingsMissingArtifacts(ctx, limit)
	if err != nil {
		return 0, err
	}
	q := DefaultSentinelQueue()
	if q == nil {
		return 0, errors.New("提交哨兵未启用（sentinel.enabled=false）")
	}
	for _, r := range refs {
		if err := q.EnqueueArtifacts(ctx, r.FindingID, r.CommitID); err != nil {
			continue // 已在队列里（unique 冲突）不算错误
		}
		enqueued++
	}
	log.Printf("[Sentinel] 产物回填：候选 %d 条，新入队 %d 条", len(refs), enqueued)
	return enqueued, nil
}
