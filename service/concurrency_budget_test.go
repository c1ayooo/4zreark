package service

import (
	"testing"

	"github.com/c1ayooo/4zreark/config"
)

func TestConcurrencyBudgetNoClamp(t *testing.T) {
	cfg := &config.Config{}
	cfg.Node.MaxTasks = 5
	cfg.Collection.GateWorkers = 4
	cfg.Scanner.WorkerCount = 10
	cfg.Postgres.MaxConns = 50

	b := ComputeConcurrencyBudget(cfg)
	if b.Total > b.MaxConns {
		t.Fatalf("预算不应超出 max_conns: total=%d max=%d", b.Total, b.MaxConns)
	}
	if len(b.Warnings) != 0 {
		t.Fatalf("未超预算不应产生告警: %v", b.Warnings)
	}
	if b.Scan != 5 || b.Gate != 4 {
		t.Fatalf("基础预算被意外改动: scan=%d gate=%d", b.Scan, b.Gate)
	}
}

func TestConcurrencyBudgetClampsAuxQueues(t *testing.T) {
	cfg := &config.Config{}
	cfg.Node.MaxTasks = 5
	cfg.Collection.GateWorkers = 4
	cfg.Scanner.WorkerCount = 10
	cfg.Postgres.MaxConns = 25

	b := ComputeConcurrencyBudget(cfg)
	if b.Total > b.MaxConns {
		t.Fatalf("夹紧后仍超预算: total=%d max=%d", b.Total, b.MaxConns)
	}
	if b.Gate >= 4 || b.TaskQueue >= 10 || b.Probe >= 8 {
		t.Fatalf("应先夹紧 Gate/通用队列/探测: gate=%d task=%d probe=%d", b.Gate, b.TaskQueue, b.Probe)
	}
	if b.Scan != 5 {
		t.Fatalf("扫描队列不应被夹紧: scan=%d", b.Scan)
	}
	if len(b.Warnings) == 0 {
		t.Fatal("夹紧时必须给出告警")
	}
}
