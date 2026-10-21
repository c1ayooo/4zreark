// 4zreark - 资产侦察与漏洞管理平台
// 作者: c1ayoo

package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/c1ayooo/4zreark/api"
	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/router"
	"github.com/c1ayooo/4zreark/service"

	"github.com/gin-gonic/gin"
)

func main() {
	// 分布式部署时用命令行覆盖节点身份；配置文件/service 环境变量同样生效。
	roleFlag := flag.String("role", "", "节点角色: all|master|worker（覆盖配置）")
	nameFlag := flag.String("node-name", "", "节点展示名（覆盖配置）")
	idFlag := flag.String("node-id", "", "节点唯一标识（覆盖配置）")
	maxTasksFlag := flag.Int("max-tasks", 0, "单节点并发任务数（覆盖配置）")
	platformURLFlag := flag.String("platform-url", "", "worker 连接的平台地址（覆盖配置）")
	tokenFlag := flag.String("node-token", "", "worker 节点密钥（覆盖配置）")
	flag.Parse()

	// Get executable directory for config path
	execPath, err := os.Executable()
	if err != nil {
		log.Fatalf("Failed to get executable path: %v", err)
	}
	execDir := filepath.Dir(execPath)

	// Windows 自更新接力：以 .new 启动的进程把正式名让给自己，下次仍从原路径启动。
	if strings.HasSuffix(execPath, ".new") {
		base := strings.TrimSuffix(execPath, ".new")
		_ = os.Remove(base)
		if rerr := os.Rename(execPath, base); rerr == nil {
			execPath = base
			execDir = filepath.Dir(execPath)
		}
	}

	// 自更新留下的旧二进制：新进程已经跑起来了，直接清掉，目标机不留垃圾。
	_ = os.Remove(execPath + ".old")

	// 配置原文留在内存：自更新 exec 重启要用同一份内容把 fd 0 重新灌满，
	// 目标机不允许落地配置文件。
	cfg, rawConfig := loadConfig(execDir)
	service.SetConfigSource(rawConfig)

	if *roleFlag != "" {
		cfg.Node.Role = *roleFlag
	}
	if *nameFlag != "" {
		cfg.Node.Name = *nameFlag
	}
	if *idFlag != "" {
		cfg.Node.ID = *idFlag
	}
	if *maxTasksFlag > 0 {
		cfg.Node.MaxTasks = *maxTasksFlag
	}
	if *platformURLFlag != "" {
		cfg.Node.PlatformURL = *platformURLFlag
	}
	if *tokenFlag != "" {
		cfg.Node.Token = *tokenFlag
	}
	if cfg.Node.Role != "" &&
		cfg.Node.Role != config.NodeRoleAll &&
		cfg.Node.Role != config.NodeRoleMaster &&
		cfg.Node.Role != config.NodeRoleWorker {
		log.Fatalf("无效的节点角色 %q（可选 all|master|worker）", cfg.Node.Role)
	}
	cfg.Node.Normalize()

	// 单节点并发：node.max_tasks > scanner.worker_count > 5
	workerCount := cfg.Node.MaxTasks
	if workerCount <= 0 {
		workerCount = cfg.Scanner.WorkerCount
	}
	if workerCount <= 0 {
		workerCount = 5
	}
	if workerCount > service.MaxNodeWorkers {
		workerCount = service.MaxNodeWorkers
	}
	cfg.Node.MaxTasks = workerCount

	// worker 不连接数据库：只拿 platform_url + 可吊销 token 连平台。
	if cfg.Node.Role == config.NodeRoleWorker {
		runRemoteWorker(cfg, workerCount)
		return
	}

	// Set Gin mode
	gin.SetMode(cfg.Server.Mode)

	// ---------------------------------------------------------------- PostgreSQL
	// 唯一存储。连接 + 启动自检（连接、迁移账本、必需表、当月/次月分区）任一项不过即以退出码 2 退出。
	initCtx, initCancel := context.WithTimeout(context.Background(), 15*time.Second)
	pg, pgErr := repo.Open(initCtx, &cfg.Postgres)
	if pgErr == nil {
		pgErr = pg.SelfCheck(initCtx)
	}
	initCancel()
	if pgErr != nil {
		log.Printf("[FATAL] PostgreSQL 启动自检失败: %v", pgErr)
		os.Exit(2)
	}
	defer pg.Close()
	log.Println("PostgreSQL 就绪，启动自检通过")

	// 恢复上次部署的 gost 反连隧道：进程还活着则跳过，死了就按记录重新拉起。
	api.RestoreGostTunnels()

	if cfg.Node.RunsControlPlane() {
		// Initialize default admin user
		userService := service.NewUserService()
		if err := userService.InitAdmin(); err != nil {
			log.Printf("Warning: Failed to initialize admin user: %v", err)
		}

		// Scan POC directory for auto-import
		log.Println("Scanning POC directory...")
		pocService := service.NewPOCService()
		pocDir := filepath.Join(execDir, "..", "pocs")
		if envPocDir := os.Getenv("POC_DIR"); envPocDir != "" {
			pocDir = envPocDir
		}
		// If pocs directory not found at execDir, try current directory
		if _, err := os.Stat(pocDir); os.IsNotExist(err) {
			pocDir = "pocs"
		}
		// Create pocs directory if it doesn't exist
		if _, err := os.Stat(pocDir); os.IsNotExist(err) {
			if mkErr := os.MkdirAll(pocDir, 0755); mkErr == nil {
				log.Printf("Created POC directory: %s", pocDir)
			}
		}
		pocService.ScanPOCDirectory(pocDir)
	} else {
		log.Printf("[Node] role=worker，跳过管理员初始化与 POC 目录导入（控制面负责）")
	}

	// 节点网关：worker 通过 WebSocket 连上来，master 通过它派单。
	nodeHub := api.NewNodeHub()

	// worker 二进制托管：节点心跳回包里比对版本，不一致就从这个地址拉新版自更新。
	workerBinaryPath := os.Getenv("ZRE_WORKER_BINARY")
	if workerBinaryPath == "" {
		workerBinaryPath = filepath.Join("data", "dist", "worker-linux-amd64.gz")
	}
	nodeBinaryHandler := api.NewNodeBinaryHandler(workerBinaryPath)
	nodeHub.SetBinaryVersionFn(nodeBinaryHandler.Version)

	// 节点专用 HTTPS 网关：独立端口 + TLS，只暴露 /api/node/*，不复用 Web 端口。
	if cfg.Node.GatewayPort == cfg.Server.Port {
		log.Fatalf("[FATAL] node.gateway_port(%d) 不能和 server.port(%d) 相同", cfg.Node.GatewayPort, cfg.Server.Port)
	}
	gatewayTLS, gerr := service.EnsureNodeGatewayTLS(&cfg.Node)
	if gerr != nil {
		log.Fatalf("[FATAL] 准备节点网关 TLS 失败: %v", gerr)
	}
	gatewayRouter := router.SetupNodeGatewayRouter(nodeHub, nodeBinaryHandler)
	go func() {
		addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Node.GatewayPort)
		log.Printf("[NodeGateway] HTTPS listening on %s", addr)
		if err := gatewayRouter.RunTLS(addr, gatewayTLS.CertFile, gatewayTLS.KeyFile); err != nil {
			log.Fatalf("[FATAL] 节点网关启动失败: %v", err)
		}
	}()

	// 扫描执行器：
	//   role=all    ：River Work 在本地跑流水线
	//   role=master ：River Work 只负责把任务推给已连接的 worker
	var taskExecutor *service.TaskExecutor
	taskExecutor = service.NewTaskExecutor(workerCount)
	taskExecutor.SetIdentity(cfg.Node.ID, cfg.Node.Name)
	if cfg.Node.Role == config.NodeRoleMaster {
		taskExecutor.SetDispatcher(nodeHub)
		log.Printf("[Node] role=master，%d 个调度 worker 等待远程节点连接", workerCount)
	} else {
		// all 模式：优先派给已连接的远程节点，没有节点时回退本机扫描。
		taskExecutor.SetDispatcher(nodeHub)
		taskExecutor.SetLocalFallback(true)
		log.Printf("[Node] role=all，%d 个本地扫描 worker（有远程节点时优先派发）", workerCount)
	}
	taskExecutor.Start()
	defer taskExecutor.Stop()

	// 节点离线看门狗：心跳超时置离线并推 IM，恢复后再推一条。
	service.StartNodeWatchdog(context.Background())

	// River 扫描队列：master/all 都运行 River Work（master 派单，all 本地执行）。
	queueCtx := context.Background()
	scanQueue, qErr := service.NewScanQueue(queueCtx, pg.Pool(), workerCount, taskExecutor, true)
	if qErr != nil {
		log.Printf("[FATAL] 初始化 River 扫描队列失败: %v", qErr)
		os.Exit(2)
	}
	service.SetDefaultScanQueue(scanQueue)
	if err := scanQueue.MigrateLegacy(queueCtx); err != nil {
		log.Printf("[Node] 旧 task_jobs 扫描作业迁移失败（可忽略，任务仍可在新队列重试）: %v", err)
	}
	if err := scanQueue.Start(queueCtx); err != nil {
		log.Printf("[FATAL] 启动 River 扫描队列失败: %v", err)
		os.Exit(2)
	}
	// 先停 River（不再拉新作业），再由 taskExecutor.Stop 取消本地流水线/派单。
	defer func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		defer cancel()
		if err := scanQueue.Stop(stopCtx); err != nil {
			log.Printf("[Node] 停止 River 队列失败: %v", err)
		}
	}()

	// 单机 all 模式把本进程也登记成扫描节点；master 只做调度，不写节点记录。
	if cfg.Node.Role == config.NodeRoleAll {
		nodeRuntime := service.NewNodeRuntime(&cfg.Node, cfg.Server.Port, taskExecutor)
		nodeRuntime.Start()
		defer nodeRuntime.Stop()
	}

	// Start cruise scheduler
	log.Println("Starting cruise scheduler...")
	cruiseService := service.NewCruiseService()
	if err := cruiseService.Start(); err != nil {
		log.Printf("Warning: Failed to start cruise scheduler: %v", err)
	}
	log.Println("Cruise scheduler started")
	defer cruiseService.Stop()

	// Start asset governance cycle scheduler（种子 → 计划 → 批次，每 60 秒推进一次）
	log.Println("Starting governance cycle scheduler...")
	cycleService := service.NewCycleService()
	cycleService.Start()
	log.Println("Governance cycle scheduler started")
	defer cycleService.Stop()

	// Start asset probe executor（批次执行单元 → 真实 HTTP 探测 → 写回站点连通性）
	log.Println("Starting asset probe executor...")
	probeExecutor := service.NewProbeExecutor(8)
	probeExecutor.Start()
	log.Println("Asset probe executor started")
	defer probeExecutor.Stop()

	// 自动存活验证：新扫描/导入的 pending 站点后台探测，不等人工点。
	if os.Getenv("ZRE_AUTOVERIFY_ENABLED") != "0" {
		autoVerify := service.NewAutoVerifyService()
		autoVerify.Start()
		log.Println("Auto verify scheduler started")
		defer autoVerify.Stop()
	}

	// Start retention scheduler（scan_results / raw_records / verifications / events）
	log.Println("Starting data retention scheduler...")
	retentionService := service.NewRetentionService()
	retentionService.Start()
	defer retentionService.Stop()
	log.Println("Data retention scheduler started")

	// Start fingerprint upstream sync（wappalyzergo / webanalyze / dddd，24h）
	log.Println("Starting fingerprint upstream sync...")
	fpUpstreamService := service.NewFingerprintUpstreamService()
	fpUpstreamService.Start()
	defer fpUpstreamService.Stop()
	log.Println("Fingerprint upstream sync started")

	// Start vuln intel poller（9 个公开漏洞源 → vuln_intel）
	// 设置里 vulnintel.enabled=false 时不轮询，但仍可手动触发。
	log.Println("Starting vuln intel poller...")
	intelService := service.NewIntelService()
	if err := intelService.Start(); err != nil {
		log.Printf("Warning: Failed to start vuln intel poller: %v", err)
	}
	log.Println("Vuln intel poller started")
	defer intelService.Stop()

	// 指纹命中后的自动 nuclei 验证（默认关闭；开启前确认项目种子即授权边界）
	vulnVerifyService := service.GetVulnVerifyService()
	vulnVerifyService.Start(context.Background())
	defer vulnVerifyService.Stop()

	// Initialize WebSocket hub for real-time data
	log.Println("Initializing WebSocket hub...")
	wsHub := api.NewHub()
	go wsHub.Run()
	go wsHub.StartMonitorTask()

	// Setup router with WebSocket hub
	r := router.SetupRouterWithWebSocket(wsHub, nodeHub)

	// Start server
	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	log.Printf("Server starting on %s", addr)

	// Graceful shutdown
	go func() {
		if err := r.Run(addr); err != nil {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	waitForShutdown("server")
}

// runRemoteWorker 启动不连接数据库的扫描节点：
// 只持有平台地址 + 可吊销密钥，通过 WebSocket 接单、通过 HTTP 回传结果。
func runRemoteWorker(cfg *config.Config, workerCount int) {
	if cfg.Node.PlatformURL == "" || cfg.Node.Token == "" {
		log.Fatalf("[FATAL] role=worker 需要 node.platform_url 和 node.token（平台签发的节点密钥）")
	}
	log.Printf("[Node] remote worker 启动：platform=%s name=%s max_tasks=%d",
		cfg.Node.PlatformURL, cfg.Node.Name, workerCount)

	client := service.NewRemoteClient(cfg.Node.PlatformURL, cfg.Node.Token, cfg.Node.Proxy, cfg.Node.PlatformCA)
	executor := service.NewRemoteTaskExecutor(workerCount, client)
	executor.SetIdentity(cfg.Node.ID, cfg.Node.Name)
	executor.Start()
	defer executor.Stop()

	// 漏洞扫描的 POC 从平台拉取，不读本地/远程数据库。
	client.InstallPOCLoader()

	// 密钥被吊销时 Agent 会自行返回，进程随之退出；SIGTERM 也会取消 ctx。
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	agent := service.NewRemoteAgent(&cfg.Node, client, executor)
	agent.Run(ctx)
	log.Println("[Node] remote worker 已停止")
}

// waitForShutdown 阻塞到 SIGINT/SIGTERM，defer 链负责停执行器、心跳与调度器。
func waitForShutdown(kind string) {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Printf("Shutting down %s...", kind)
}

// loadConfig 读配置并返回原文。
// 节点零配置部署时 CONFIG_PATH=/dev/stdin，配置只在管道里存在一次；
// 自更新 exec 重启要靠这份原文把 fd 0 重新灌满，所以两条路径都要留下字节。
func loadConfig(execDir string) (*config.Config, []byte) {
	// Windows 没有 /dev/stdin，自更新接力时配置走环境变量（base64）。
	if enc := os.Getenv("ZRE_CONFIG_BASE64"); enc != "" {
		if raw, derr := base64.StdEncoding.DecodeString(enc); derr == nil && len(raw) > 0 {
			return config.LoadConfigRaw(raw), raw
		}
	}

	configPath := filepath.Join(execDir, "..", "config", "config.yaml")
	if envPath := os.Getenv("CONFIG_PATH"); envPath != "" {
		configPath = envPath
	}
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		configPath = "config/config.yaml"
	}

	if configPath == "/dev/stdin" || configPath == "-" {
		raw, err := io.ReadAll(os.Stdin)
		if err != nil {
			log.Fatalf("Failed to read config from stdin: %v", err)
		}
		return config.LoadConfigRaw(raw), raw
	}

	raw, _ := os.ReadFile(configPath)
	return config.LoadConfig(configPath), raw
}
