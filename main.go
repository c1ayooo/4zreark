// 4zreark - 资产侦察与漏洞管理平台
// 作者: c1ayoo

package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	// 精简容器（scratch/alpine）常无系统 tzdata：cruise 的 CRON_TZ 调度依赖它。
	_ "time/tzdata"

	"github.com/c1ayooo/4zreark/api"
	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/internal/outbound"
	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/router"
	"github.com/c1ayooo/4zreark/service"

	"github.com/gin-gonic/gin"
)

// AppVersion 平台版本号；Release 构建经 ldflags 注入（-X .../service.AppVersion）。
// 本地/源码构建为 "dev"。
var AppVersion = "dev"

func init() {
	service.AppVersion = AppVersion
}

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

	// 出网代理解析的数据源：规则同步/工具下载/情报等出网点从这里取代理设置。
	outbound.SetStore(repo.Default().Settings())

	// 安全审计 M13：存量明文凭据（数据源会话 / Token 池 / 监控 / 通知）启动迁移。
	// 未配置 ZRE_SECRET_KEY 时跳过并告警；配置后重启自动完成。
	go service.MigratePlaintextSecrets(context.Background())

	// 恢复上次部署的 rem 反连隧道：进程还活着则跳过，死了就按记录重新拉起。
	api.RestoreRemTunnels()

	if cfg.Node.RunsControlPlane() {
		// JWT 签名密钥是随仓库入库的默认值时拒绝启动：任何知道该值的人都能
		// 伪造 role=admin 的 JWT 完全接管平台。确有内网隔离把握可用
		// ZRE_ALLOW_DEFAULT_SECRET=1 显式放行，但正确做法是配置随机密钥。
		if cfg.JWT.JWTSecretIsDefault() && os.Getenv("ZRE_ALLOW_DEFAULT_SECRET") != "1" {
			log.Fatalf("[FATAL] jwt.secret 仍是随仓库分发的默认值，拒绝启动控制面。" +
				"请设置随机密钥（环境变量 ZRE_JWT_SECRET 或配置文件 jwt.secret，" +
				"如 $(openssl rand -hex 32)）；确要带默认密钥运行请显式设置 ZRE_ALLOW_DEFAULT_SECRET=1")
		}

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

	// 引擎查询额度落账：worker 的 scan_done 上报与本地执行（all 角色）共用。
	engineBudget := service.GetEngineBudgetService()
	engineUsageReport := func(m map[string]int) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		engineBudget.ConsumeMany(ctx, m)
	}
	nodeHub.SetEngineUsageSink(engineUsageReport)
	service.SetEngineUsageSink(engineUsageReport)
	service.SetTaskCancelNotifier(func(taskID string) {
		nodeHub.CancelTask(taskID)
	})

	// worker 二进制托管：节点心跳回包里比对版本，不一致就从这个地址拉新版自更新。
	workerBinaryPath := os.Getenv("ZRE_WORKER_BINARY")
	if workerBinaryPath == "" {
		workerBinaryPath = filepath.Join("data", "dist", "worker-linux-amd64.gz")
	}
	nodeBinaryHandler := api.NewNodeBinaryHandler(workerBinaryPath)
	nodeHub.SetBinaryVersionFn(nodeBinaryHandler.Version)
	// 托管工具清单哈希：worker 心跳比对，不一致时拉清单同步工具。
	nodeToolsHandler := api.NewNodeToolsHandler()
	nodeHub.SetToolsHashFn(nodeToolsHandler.ManifestHash)

	// 节点专用 HTTPS 网关：独立端口 + TLS，只暴露 /api/node/*，不复用 Web 端口。
	if cfg.Node.GatewayPort == cfg.Server.Port {
		log.Fatalf("[FATAL] node.gateway_port(%d) 不能和 server.port(%d) 相同", cfg.Node.GatewayPort, cfg.Server.Port)
	}
	gatewayTLS, gerr := service.EnsureNodeGatewayTLS(&cfg.Node)
	if gerr != nil {
		log.Fatalf("[FATAL] 准备节点网关 TLS 失败: %v", gerr)
	}
	gatewayRouter := router.SetupNodeGatewayRouter(nodeHub, nodeBinaryHandler)
	// 网关挂了（起不来/监听器死亡）不能 log.Fatalf：那会绕过全部 defer 直接退进程，
	// 在跑的扫描收不了尾。把错误送回主 goroutine，走统一的优雅关停链。
	gatewayErr := make(chan error, 1)
	go func() {
		addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Node.GatewayPort)
		log.Printf("[NodeGateway] HTTPS listening on %s", addr)
		if err := gatewayRouter.RunTLS(addr, gatewayTLS.CertFile, gatewayTLS.KeyFile); err != nil {
			gatewayErr <- fmt.Errorf("节点网关停止/失败: %w", err)
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
	// 僵尸任务回收：节点离线或长时间无进展的 running 任务自动置失败并取消 River job。
	service.StartStaleTaskReaper(queueCtx)

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
	// 任务日志：每小时按留存时段自动清空（时段可在任务日志页调整）
	taskLogSvc := service.NewTaskLogService()
	taskLogSvc.StartRetention()
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

	// 工具运行时（gogo/spray/katana/rem）：定时检查上游版本，staged 安装+可回滚。
	// worker 不启动（无库，工具由节点网关按清单分发）。
	if cfg.Node.RunsControlPlane() {
		toolRuntimeService := service.GetToolRuntimeService()
		defer toolRuntimeService.Stop()
		log.Println("Tool runtime service started (gogo/spray/katana/rem)")

		// 资产巡航 v2：被动发现（新内容候选）+ 站点内容慢速巡检（hash 判变→慢爬）
		discoveryService := service.GetDiscoveryService()
		discoveryService.Start()
		defer discoveryService.Stop()
		siteWatchService := service.GetSiteWatchService()
		siteWatchService.Start()
		defer siteWatchService.Stop()
		log.Println("Asset cruise v2 started (discovery + site watch)")

		// 证书到期检测：每日扫 sites.cert_not_after，7 天内 critical / 30 天内 warning
		certExpiryService := service.NewCertExpiryService()
		certExpiryService.Start()
		defer certExpiryService.Stop()
		log.Println("Cert expiry monitor started")

		// 站点判死（down）通知钩子：reappear 的恢复通知在 VerifyService 内直调
		service.InstallSiteDownNotifyHook()

		// 内置词表自动同步（embed + 磁盘 config/dicts/txt → dictionaries 表）
		dictSyncService := service.GetDictSyncService()
		dictSyncService.Start()
		defer dictSyncService.Stop()
		log.Println("Dict sync service started (builtin dictionaries)")
	}

	// nuclei 运行时后台同步：每小时 Ensure(auto)，auto_update 开启且到期时
	// 自动拉上游模板快照与二进制（在 GetNucleiRuntimeService 单例里自启动）
	_ = service.GetNucleiRuntimeService()

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

	// GitHub 泄露监控（4zreco 迁移）：全局单例，规则按项目同步
	if gm, err := service.GetGitHubMonitor(); err != nil {
		log.Printf("[GitHubLeak] 监控初始化失败（不阻塞启动）: %v", err)
	} else {
		gm.Start(context.Background())
	}

	// Initialize WebSocket hub for real-time data
	log.Println("Initializing WebSocket hub...")
	wsHub := api.NewHub()
	go wsHub.Run()
	go wsHub.StartMonitorTask()

	// Setup router with WebSocket hub
	r := router.SetupRouterWithWebSocket(wsHub, nodeHub)

	// 通用队列 worker（/api/queue）随路由注册启动，关停时先于 HTTP 断开前收口。
	defer api.StopQueueHandler()

	// Start server
	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)

	// Graceful shutdown：http.Server 才有 Shutdown；r.Run 裸起做不到。
	// 超时配置（审计 M11/A）：防慢速连接占满 fd 与请求体无界读取。
	srv := &http.Server{
		Addr:              addr,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	// 原生 TLS（审计 M11）：证书/密钥成对配置时主 Web 直接 HTTPS；配一缺一拒绝启动。
	nativeTLS := cfg.Server.TLSCert != "" || cfg.Server.TLSKey != ""
	if nativeTLS && (cfg.Server.TLSCert == "" || cfg.Server.TLSKey == "") {
		log.Fatal("[FATAL] server.tls_cert 与 server.tls_key 必须成对配置")
	}
	if nativeTLS {
		log.Printf("Server starting on %s (TLS, 强制 HTTPS)", addr)
		go func() {
			if err := srv.ListenAndServeTLS(cfg.Server.TLSCert, cfg.Server.TLSKey); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("[FATAL] Failed to start TLS server: %v", err)
				os.Exit(1)
			}
		}()
	} else {
		if cfg.Server.ForceHTTPS {
			log.Printf("Server starting on %s (HTTP, force_https: 明文请求将 301 到 HTTPS)", addr)
		} else {
			log.Printf("Server starting on %s (HTTP)", addr)
		}
		go func() {
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("[FATAL] Failed to start server: %v", err)
				os.Exit(1)
			}
		}()
	}

	waitForShutdown("server", gatewayErr)

	// 先给在跑的 HTTP 请求（建任务/写结果）最多 30 秒收尾，再进 defer 链
	// 停队列/执行器/调度器/DB。
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("[Shutdown] HTTP server shutdown: %v", err)
	}
	log.Println("[Shutdown] HTTP server stopped")
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

// waitForShutdown 阻塞到 SIGINT/SIGTERM，或 extra 里的组件致命错误（如节点网关
// 监听器死亡）；返回后 defer 链负责停 HTTP、执行器、心跳与调度器。
func waitForShutdown(kind string, extra <-chan error) {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-quit:
		log.Printf("Shutting down %s...", kind)
	case err := <-extra:
		log.Printf("[FATAL] %v，触发优雅关停", err)
	}
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
