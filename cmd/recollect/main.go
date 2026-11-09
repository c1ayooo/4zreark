// recollect 触发一次项目级信息收集任务，并轮询到终态或截止时间。
// 与已运行的 zreark 服务共用 DB/River，不重复启动服务。
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/oid"
	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
)

func main() {
	projectID := flag.Int64("project", 1, "项目 ID")
	target := flag.String("target", "meituan.com", "主域目标")
	mode := flag.String("mode", "full", "collection 模式：auto|full|staged")
	rate := flag.Int("rate", 5, "每秒请求数")
	delay := flag.Int("delay", 1000, "目标间隔毫秒")
	threads := flag.Int("threads", 4, "模块并发")
	deadline := flag.Duration("deadline", 8*time.Hour, "最长等待时间")
	dryRun := flag.Bool("dry-run", false, "只打印计划，不创建任务")
	cfgPath := flag.String("config", "config/config.yaml", "配置文件路径")
	flag.Parse()

	if *dryRun {
		fmt.Printf("project=%d target=%s mode=%s rate=%d delay=%d threads=%d deadline=%s\n",
			*projectID, *target, *mode, *rate, *delay, *threads, deadline.String())
		return
	}

	cfg := config.LoadConfig(*cfgPath)
	ctx := context.Background()
	r, err := repo.Open(ctx, &cfg.Postgres)
	if err != nil {
		log.Fatalf("连接 PostgreSQL 失败: %v", err)
	}
	defer r.Close()

	// 独立工具进程默认没有扫描队列；先创建 insert-only 客户端，
	// 让任务进入 River scan 队列，由已运行的 zreark 服务消费。
	scanQueue, err := service.NewScanQueue(ctx, r.Pool(), 1, nil, false)
	if err != nil {
		log.Fatalf("初始化扫描队列失败: %v", err)
	}
	service.SetDefaultScanQueue(scanQueue)
	defer func() { _ = scanQueue.Stop(context.Background()) }()

	// 幂等补种子：清空脚本已插入，这里兜底。
	if _, err := r.Pool().Exec(ctx, `
		insert into zre.seeds (project_id, kind, value, capability, enabled)
		values ($1, 'domain', $2, '{}'::jsonb, true)
		on conflict do nothing`, *projectID, *target); err != nil {
		log.Fatalf("写入种子失败: %v", err)
	}

	task := &models.Task{
		ID:         oid.NewObjectID(),
		ProjectID:  *projectID,
		Name:       fmt.Sprintf("美团src 重建信息收集 %s", time.Now().Format("20060102-1504")),
		Type:       models.TaskTypeCollection,
		Status:     models.TaskStatusPending,
		Targets:    []string{*target},
		TargetType: "domain",
		Config: models.TaskConfig{
			CollectionMode: *mode,
			RatePerSec:     *rate,
			TargetDelayMs:  *delay,
			Threads:        *threads,
		},
		Tags: []string{"recollect", "meituan", "rebuild"},
	}
	if err := service.NewTaskService().CreateTask(task); err != nil {
		log.Fatalf("创建任务失败: %v", err)
	}
	fmt.Printf("task_id=%s\n", task.ID.Hex())

	// 轮询到终态或截止时间；期间只读，不改任务状态。
	start := time.Now()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	limit := time.Now().Add(*deadline)
	for {
		t, err := r.Tasks().GetByID(ctx, task.ID.Hex())
		if err == nil && t != nil {
			fmt.Printf("[%s] status=%s progress=%d stage=%s elapsed=%s\n",
				time.Now().Format("15:04:05"), t.Status, t.Progress, t.Stage,
				time.Since(start).Round(time.Second))
			switch t.Status {
			case models.TaskStatusCompleted, models.TaskStatusFailed, models.TaskStatusCancelled:
				fmt.Printf("finished status=%s\n", t.Status)
				return
			}
		}
		if time.Now().After(limit) {
			fmt.Println("deadline reached; leaving task running")
			return
		}
		<-ticker.C
	}
}
