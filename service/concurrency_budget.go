package service

import (
	"fmt"

	"github.com/c1ayooo/4zreark/config"
)

// ConcurrencyBudget 汇总所有队列/执行器的并发上限，并与 pgxpool 连接预算对齐。
// 超出时按「先降 Gate，再降通用队列，最后降探测」夹紧；扫描队列不动。
type ConcurrencyBudget struct {
	Scan      int
	Gate      int
	Collect   int
	Judge     int
	Artifacts int
	Repro     int
	TaskQueue int
	Probe     int
	Total     int
	MaxConns  int
	Warnings  []string
}

func ComputeConcurrencyBudget(cfg *config.Config) ConcurrencyBudget {
	b := ConcurrencyBudget{}
	if cfg == nil {
		return b
	}
	b.Scan = cfg.Node.MaxTasks
	if b.Scan <= 0 {
		b.Scan = 5
	}
	if b.Scan > MaxNodeWorkers {
		b.Scan = MaxNodeWorkers
	}
	b.Gate = cfg.Collection.GateWorkers
	if b.Gate <= 0 {
		b.Gate = 4
	}
	// sentinel collect/judge 与队列 MaxWorkers 同源（config.yaml），改配置两边同步生效；
	// artifacts（LLM 产物流水线）固定串行；repro 由独立 pocsmith 进程消费。
	b.Collect = cfg.Sentinel.CollectWorkers
	if b.Collect <= 0 {
		b.Collect = 4
	}
	b.Judge = cfg.Sentinel.JudgeWorkers
	if b.Judge <= 0 {
		b.Judge = 8
	}
	b.Artifacts = 1
	b.Repro = 2
	b.TaskQueue = cfg.Scanner.WorkerCount
	if b.TaskQueue <= 0 {
		b.TaskQueue = 10
	}
	// 全局口径：同域最多 2 并发（可慢不可挂）。
	b.Probe = 2
	b.MaxConns = cfg.Postgres.MaxConns
	if b.MaxConns <= 0 {
		b.MaxConns = 50
	}

	b.Total = b.Scan + b.Gate + b.Collect + b.Judge + b.Artifacts + b.Repro + b.TaskQueue + b.Probe
	if b.Total <= b.MaxConns {
		return b
	}

	original := b.Total
	b.Warnings = append(b.Warnings, fmt.Sprintf(
		"并发预算 %d 超过 pgxpool.max_conns=%d，开始按 Gate→通用队列→探测 夹紧", b.Total, b.MaxConns))
	for b.Total > b.MaxConns {
		switch {
		case b.Gate > 1:
			b.Gate--
		case b.TaskQueue > 1:
			b.TaskQueue--
		case b.Probe > 1:
			b.Probe--
		default:
			b.Warnings = append(b.Warnings,
				"已无可夹紧的队列，剩余超出由 PG 连接排队吸收，请调大 max_conns 或降低扫描并发")
			b.Total = b.MaxConns
			return b
		}
		b.Total--
	}
	b.Warnings = append(b.Warnings, fmt.Sprintf(
		"并发预算已从 %d 夹紧到 %d（gate=%d task=%d probe=%d）",
		original, b.Total, b.Gate, b.TaskQueue, b.Probe))
	return b
}
