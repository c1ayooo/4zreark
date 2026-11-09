// pocsmith 是 CommitSentinel 的差分复现独立进程（v0.3 §7.6-7.9）。
//
// 为什么独立：docker build/run 吃满 CPU/磁盘，文档 §3.0 决策不让它和控制面
// 抢资源。它连同一个 PostgreSQL，只注册 sentinel_repro 队列的 worker，
// 与主进程的 SentinelQueue 共享 river_job 表、互不抢作业。
//
// 用法：
//
//	go build -o pocsmith ./cmd/pocsmith
//	CONFIG_PATH=config/config.yaml ZRE_PG_PASSWORD=... \
//	  pocsmith -workdir /var/lib/pocsmith -timeout 30
//
// 未启用 sentinel 时直接退出（提示而非报错）；docker 不可用时启动即失败。
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/internal/sentinelsandbox"
	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
)

func main() {
	workdir := flag.String("workdir", "data/pocsmith", "PoC 文件沙箱目录（挂载进容器 /poc）")
	timeout := flag.Int("timeout", 30, "单次 PoC 执行超时秒数")
	cfgPath := os.Getenv("CONFIG_PATH")
	if cfgPath == "" {
		cfgPath = "config/config.yaml"
	}
	flag.Parse()

	cfg := config.LoadConfig(cfgPath)
	if !cfg.Sentinel.Enabled {
		log.Fatal("[pocsmith] sentinel.enabled=false，无需启动复现进程")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := sentinelsandbox.Available(ctx); err != nil {
		log.Fatalf("[pocsmith] %v", err)
	}
	if err := os.MkdirAll(*workdir, 0o755); err != nil {
		log.Fatalf("[pocsmith] 创建沙箱目录失败: %v", err)
	}

	pool, err := repo.Open(ctx, &cfg.Postgres)
	if err != nil {
		log.Fatalf("[pocsmith] 连接 PostgreSQL 失败: %v", err)
	}
	defer pool.Close()

	repro := service.NewReproService(*workdir, *timeout)
	client, err := service.NewSentinelReproClient(ctx, pool.Pool(), repro)
	if err != nil {
		log.Fatalf("[pocsmith] %v", err)
	}
	if err := client.Start(ctx); err != nil {
		log.Fatalf("[pocsmith] 启动 worker 失败: %v", err)
	}
	log.Printf("[pocsmith] 已启动（queue=sentinel_repro workdir=%s timeout=%ds）——等待复现任务", *workdir, *timeout)

	<-ctx.Done()
	log.Println("[pocsmith] 收到退出信号，等待在跑任务收尾…")
	stopped := make(chan struct{})
	go func() {
		_ = client.Stop(context.Background())
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(2 * time.Minute):
		log.Println("[pocsmith] 收尾超时，强制退出")
	}
	log.Println("[pocsmith] 已退出")
}
