package router

import (
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/api"
	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/middleware"
	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/service/queue"

	"github.com/gin-gonic/gin"
)

func SetupRouter() *gin.Engine {
	return setupRouter(api.NewNodeHub())
}

func setupRouter(nodeHub *api.NodeHub) *gin.Engine {
	r := gin.Default()

	// Middleware
	r.Use(middleware.CORSMiddleware())
	r.Use(middleware.Gzip())
	r.Use(middleware.OperationLogMiddleware())

	// SPA 静态托管：有前端构建产物时，根路径直接出页面，不用另起 nginx。
	serveFrontend(r)

	// Health check
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	// API routes
	apiGroup := r.Group("/api")
	{
		// MCP 接入（外部平台只读访问）：用 API key 鉴权，不复用 JWT 登录态。
		// POST 走 JSON-RPC，GET/DELETE 只为协议探测与无状态会话收尾。
		mcpHandler := api.NewMCPHandler()
		apiGroup.POST("/mcp", middleware.APIKeyMiddleware(), mcpHandler.Serve)
		apiGroup.GET("/mcp", middleware.APIKeyMiddleware(), mcpHandler.Serve)
		apiGroup.DELETE("/mcp", middleware.APIKeyMiddleware(), mcpHandler.Serve)

		// Auth routes (no auth required)
		authHandler := api.NewAuthHandler()
		statusHandler := api.NewStatusHandler()
		apiGroup.GET("/status", statusHandler.Status)
		r.GET("/dns/status", statusHandler.DNSStatus)
		authGroup := apiGroup.Group("/auth")
		{
			authGroup.POST("/login", authHandler.Login)
			authGroup.POST("/register", authHandler.Register)
			authGroup.POST("/refresh", authHandler.RefreshToken)

			// 图标按内容哈希寻址，公开可取：<img> 标签带不了 Authorization
			assetHandlerPublic := api.NewAssetHandler()
			apiGroup.GET("/asset-icons/:sha256", assetHandlerPublic.IconImage)
		}

		// Protected routes
		protected := apiGroup.Group("")
		protected.Use(middleware.AuthMiddleware(), middleware.IdempotencyMiddleware())
		{
			// Auth routes (auth required)
			protected.POST("/auth/logout", authHandler.Logout)
			protected.GET("/auth/profile", authHandler.GetProfile)
			protected.PUT("/auth/profile", authHandler.UpdateProfile)
			protected.PUT("/auth/password", authHandler.ChangePassword)

			// 外部平台 / MCP 的 API key 管理（仅管理员）
			apiKeyHandler := api.NewAPIKeyHandler()
			apiKeyGroup := protected.Group("/api-keys")
			{
				apiKeyGroup.GET("", middleware.AdminMiddleware(), apiKeyHandler.ListAPIKeys)
				apiKeyGroup.POST("", middleware.AdminMiddleware(), apiKeyHandler.CreateAPIKey)
				apiKeyGroup.PUT("/:id", middleware.AdminMiddleware(), apiKeyHandler.UpdateAPIKey)
				apiKeyGroup.DELETE("/:id", middleware.AdminMiddleware(), apiKeyHandler.DeleteAPIKey)
			}

			// Asset governance routes（ScopesHub 复刻 P0）
			assetHandler := api.NewAssetHandler()
			verificationHandler := api.NewVerificationHandler()
			projectOpsHandler := api.NewProjectOpsHandler()
			seedRestartHandler := api.NewSeedRestartHandler()
			fpImportHandler := api.NewFingerprintImportHandler()
			fpUpstreamHandler := api.NewFingerprintUpstreamHandler()
			retentionHandler := api.NewRetentionHandler()
			compatHandler := api.NewCompatHandler()
			monitoringHandler := api.NewMonitoringHandler()
			enrichmentHandler := api.NewEnrichmentHandler()
			seedCatalogHandler := api.NewSeedCatalogHandler()
			{
				protected.GET("/overview", middleware.RequirePermission("project:read"), assetHandler.Overview)
				protected.GET("/projects", middleware.RequirePermission("project:read"), assetHandler.ListProjects)
				protected.GET("/projects/options", middleware.RequirePermission("project:read"), projectOpsHandler.Options)
				protected.GET("/projects/stats", middleware.RequirePermission("project:read"), projectOpsHandler.Stats)
				protected.GET("/project-cycle/status", projectOpsHandler.CycleStatus)
				protected.GET("/projects/:id", middleware.RequirePermission("project:read"), assetHandler.GetProject)
				protected.POST("/projects", middleware.RequirePermission("project:write"), assetHandler.CreateProject)
				protected.PUT("/projects/:id", middleware.RequirePermission("project:write"), assetHandler.UpdateProject)
				protected.PATCH("/projects/:id", middleware.RequirePermission("project:write"), assetHandler.UpdateProject)
				protected.POST("/projects/:id/pause", middleware.RequirePermission("project:write"), assetHandler.PauseProject)
				protected.POST("/projects/:id/resume", middleware.RequirePermission("project:write"), assetHandler.ResumeProject)
				protected.PUT("/projects/:id/icon", middleware.RequirePermission("project:write"), projectOpsHandler.UploadIcon)
				protected.DELETE("/projects/:id/icon", middleware.RequirePermission("project:write"), projectOpsHandler.DeleteIcon)
				protected.GET("/projects/:id/collection-state", middleware.RequirePermission("project:read"), projectOpsHandler.CollectionState)
				protected.DELETE("/projects/:id", middleware.RequirePermission("project:delete"), projectOpsHandler.DeleteProject)
				protected.GET("/assets", middleware.RequirePermission("asset:read"), assetHandler.ListAssets)
				protected.GET("/assets/graph", middleware.RequirePermission("asset:read"), assetHandler.AssetGraph)
				protected.GET("/assets/routes", middleware.RequirePermission("asset:read"), assetHandler.ListSiteRoutes)
				protected.GET("/assets/query-check", middleware.RequirePermission("asset:read"), assetHandler.CheckQuery)
				protected.GET("/assets/icons", middleware.RequirePermission("asset:read"), assetHandler.IconClusters)
				protected.GET("/assets/technologies", middleware.RequirePermission("asset:read"), assetHandler.TechClusters)
				protected.GET("/assets/fingerprint-scores", middleware.RequirePermission("asset:read"), assetHandler.ListFingerprintScores)
				protected.POST("/assets/import", middleware.RequirePermission("asset:write"), assetHandler.ImportAssets)
				protected.POST("/assets/import/preview", middleware.RequirePermission("asset:write"), assetHandler.PreviewImport)
				protected.POST("/assets/import/commit", middleware.RequirePermission("asset:write"), assetHandler.CommitImport)
				protected.POST("/assets/lost-delete", middleware.RequirePermission("asset:delete"), verificationHandler.DeleteLostAssets)
				protected.POST("/assets/verification-recheck", middleware.RequirePermission("verification:recheck"), verificationHandler.RecheckAssets)
				protected.GET("/verifications", middleware.RequirePermission("asset:read"), verificationHandler.ListVerifications)
				protected.GET("/verifications/stats", middleware.RequirePermission("asset:read"), verificationHandler.Stats)
				protected.POST("/verifications/batches/preview", middleware.RequirePermission("asset:write"), verificationHandler.PreviewBatch)
				protected.POST("/verifications/batches", middleware.RequirePermission("asset:write"), verificationHandler.ExecuteBatch)
				protected.GET("/assets/:id", middleware.RequirePermission("asset:read"), assetHandler.GetAsset)
				protected.GET("/assets/:id/records", middleware.RequirePermission("asset:read"), assetHandler.ListSiteRecords)
				protected.POST("/assets/:id/verify", assetHandler.VerifyAsset)
				protected.GET("/events", middleware.RequirePermission("asset:read"), assetHandler.ListEvents)
				protected.GET("/changes", compatHandler.Changes)
				protected.GET("/history-retention", middleware.RequirePermission("settings:write"), retentionHandler.Policy)
			}

			// Asset governance cycle routes（种子 → 计划 → 批次 → 执行单元）
			govHandler := api.NewGovernanceHandler()
			{
				protected.GET("/relations", middleware.RequirePermission("governance:read"), govHandler.ListRelations)
				protected.GET("/relations/index-status", middleware.RequirePermission("governance:read"), govHandler.RelationIndexStatus)
				protected.GET("/asset-relations", govHandler.ListRelations)
				protected.GET("/asset-relations/index-status", govHandler.RelationIndexStatus)
				protected.POST("/governance/relations/rebuild", middleware.RequirePermission("governance:write"), govHandler.RebuildRelations)
				protected.POST("/governance/replay-results", middleware.RequirePermission("governance:write"), govHandler.ReplayResults)
				protected.GET("/seeds", middleware.RequirePermission("governance:read"), govHandler.ListSeeds)
				protected.GET("/seeds/capabilities", middleware.RequirePermission("governance:read"), seedCatalogHandler.Capabilities)
				protected.GET("/seeds/domain-counts", middleware.RequirePermission("governance:read"), seedCatalogHandler.DomainCounts)
				protected.POST("/seeds/preview", middleware.RequirePermission("seed:write"), govHandler.PreviewSeed)
				protected.POST("/seeds/batch", middleware.RequirePermission("seed:write"), seedCatalogHandler.CreateBatch)
				protected.POST("/seeds", middleware.RequirePermission("seed:write"), govHandler.CreateSeed)
				protected.DELETE("/seeds/:id", middleware.RequirePermission("seed:write"), govHandler.DeleteSeed)
				protected.POST("/seeds/:id/restart-preview", middleware.RequirePermission("seed:write"), seedRestartHandler.PreviewRestart)
				protected.POST("/seeds/:id/restart", middleware.RequirePermission("seed:write"), seedRestartHandler.Restart)
				protected.GET("/monitoring-presets", middleware.RequirePermission("governance:read"), monitoringHandler.ListPresets)
				protected.POST("/monitoring-presets", middleware.AdminMiddleware(), monitoringHandler.CreatePreset)
				protected.PUT("/monitoring-presets/:id", middleware.AdminMiddleware(), monitoringHandler.UpdatePreset)
				protected.DELETE("/monitoring-presets/:id", middleware.AdminMiddleware(), monitoringHandler.DeletePreset)
				protected.GET("/monitoring-defaults", middleware.RequirePermission("governance:read"), monitoringHandler.DefaultPreset)
				protected.POST("/monitoring-bulk/preview", middleware.AdminMiddleware(), monitoringHandler.PreviewBulk)
				protected.POST("/monitoring-bulk", middleware.AdminMiddleware(), monitoringHandler.ApplyBulk)
				protected.GET("/enrichment/status", enrichmentHandler.Status)
				protected.GET("/plans", middleware.RequirePermission("governance:read"), govHandler.ListPlans)
				protected.POST("/plans", middleware.RequirePermission("plan:write"), govHandler.CreatePlan)
				protected.PUT("/plans/:id", middleware.RequirePermission("plan:write"), govHandler.UpdatePlan)
				protected.PATCH("/plans/:id", middleware.RequirePermission("plan:write"), govHandler.UpdatePlan)
				protected.DELETE("/plans/:id", middleware.RequirePermission("plan:write"), govHandler.DeletePlan)
				protected.POST("/plans/:id/trigger", middleware.RequirePermission("run:execute"), govHandler.TriggerPlan)
				protected.GET("/runs", middleware.RequirePermission("governance:read"), govHandler.ListRuns)
				protected.GET("/runs/:id", middleware.RequirePermission("governance:read"), govHandler.GetRun)
				protected.GET("/runs/:id/targets", middleware.RequirePermission("governance:read"), govHandler.ListTargets)
				protected.POST("/governance/tick", middleware.RequirePermission("governance:write"), govHandler.Tick)
				protected.POST("/assets/:id/probe", middleware.RequirePermission("asset:write"), govHandler.ProbeAsset)
				protected.POST("/runs/:id/execute", middleware.RequirePermission("run:execute"), govHandler.ExecuteRun)
				protected.POST("/governance/archive", middleware.RequirePermission("asset:write"), govHandler.ArchiveLost)
				protected.GET("/governance/retention", middleware.RequirePermission("settings:write"), retentionHandler.Policy)
				protected.POST("/governance/retention/run", middleware.RequirePermission("settings:write"), retentionHandler.Run)
				protected.POST("/assets/:id/protect", middleware.RequirePermission("asset:write"), govHandler.ProtectAsset)
				protected.GET("/assets/:id/fingerprints", middleware.RequirePermission("fingerprint:read"), govHandler.SiteFingerprints)
				protected.GET("/governance/fingerprints", middleware.RequirePermission("fingerprint:read"), govHandler.ListFingerprints)
				protected.GET("/governance/fingerprints/sources", middleware.RequirePermission("fingerprint:read"), govHandler.FingerprintSources)
				protected.POST("/governance/fingerprints/sync", middleware.RequirePermission("fingerprint:write"), govHandler.SyncFingerprints)
				protected.POST("/governance/fingerprints/sync-upstream", middleware.RequirePermission("fingerprint:write"), fpUpstreamHandler.Sync)
				protected.POST("/governance/fingerprints", middleware.RequirePermission("fingerprint:write"), govHandler.UpsertFingerprint)
				protected.POST("/governance/fingerprints/preview", govHandler.PreviewFingerprint)
				protected.POST("/governance/fingerprints/import", middleware.RequirePermission("fingerprint:write"), fpImportHandler.PreviewImport)
				protected.POST("/governance/fingerprints/import/commit", middleware.RequirePermission("fingerprint:write"), fpImportHandler.CommitImport)
				protected.POST("/governance/fingerprints/bulk", middleware.RequirePermission("fingerprint:write"), fpImportHandler.BulkToggle)
				protected.DELETE("/governance/fingerprints/:name", middleware.RequirePermission("fingerprint:write"), govHandler.DeleteFingerprint)
				protected.POST("/governance/fingerprints/:name/toggle", middleware.RequirePermission("fingerprint:write"), govHandler.ToggleFingerprint)
			}

			// User routes
			userHandler := api.NewUserHandler()
			userGroup := protected.Group("/users")
			{
				userGroup.GET("", middleware.AdminMiddleware(), userHandler.ListUsers)
				userGroup.GET("/:id", userHandler.GetUser)
				userGroup.POST("", middleware.RequirePermission("user:manage"), userHandler.CreateUser)
				userGroup.PUT("/:id", middleware.RequirePermission("user:manage"), userHandler.UpdateUser)
				userGroup.PATCH("/:id", middleware.RequirePermission("user:manage"), userHandler.UpdateUser)
				userGroup.DELETE("/:id", middleware.RequirePermission("user:manage"), userHandler.DeleteUser)
				userGroup.PUT("/:id/status", middleware.RequirePermission("user:manage"), userHandler.SetUserStatus)
				userGroup.PUT("/:id/password", middleware.RequirePermission("user:manage"), userHandler.ResetPassword)
			}

			// 注册码（管理员）
			registrationHandler := api.NewRegistrationHandler()
			protected.GET("/registration-codes", middleware.RequirePermission("user:manage"), registrationHandler.List)
			protected.POST("/registration-codes", middleware.RequirePermission("user:manage"), registrationHandler.Generate)
			protected.POST("/registration-codes/batch-delete", middleware.RequirePermission("user:manage"), registrationHandler.BatchDelete)
			protected.DELETE("/registration-codes/:code", middleware.RequirePermission("user:manage"), registrationHandler.Delete)

			// Task routes
			taskHandler := api.NewTaskHandler()
			resultHandler := api.NewResultHandler()
			taskGroup := protected.Group("/tasks")
			{
				taskGroup.GET("", middleware.RequirePermission("task:read"), taskHandler.ListTasks)
				taskGroup.GET("/stats", middleware.RequirePermission("task:read"), taskHandler.GetTaskStats)
				taskGroup.GET("/templates", middleware.RequirePermission("task:read"), taskHandler.ListTaskTemplates)
				taskGroup.GET("/templates/:id", middleware.RequirePermission("task:read"), taskHandler.GetTaskTemplate)
				taskGroup.POST("/templates", middleware.RequirePermission("task:write"), taskHandler.CreateTaskTemplate)
				taskGroup.PUT("/templates/:id", middleware.RequirePermission("task:write"), taskHandler.UpdateTaskTemplate)
				taskGroup.DELETE("/templates/:id", middleware.RequirePermission("task:write"), taskHandler.DeleteTaskTemplate)
				taskGroup.POST("/from-template", middleware.RequirePermission("task:write"), taskHandler.CreateTaskFromTemplate)
				taskGroup.GET("/:id", middleware.RequirePermission("task:read"), taskHandler.GetTask)
				taskGroup.POST("", middleware.RequirePermission("task:write"), taskHandler.CreateTask)
				taskGroup.PUT("/:id", middleware.RequirePermission("task:write"), taskHandler.UpdateTask)
				taskGroup.DELETE("/:id", middleware.RequirePermission("task:write"), taskHandler.DeleteTask)
				taskGroup.POST("/:id/start", middleware.RequirePermission("task:write"), taskHandler.StartTask)
				taskGroup.POST("/:id/pause", middleware.RequirePermission("task:write"), taskHandler.PauseTask)
				taskGroup.POST("/:id/resume", middleware.RequirePermission("task:write"), taskHandler.ResumeTask)
				taskGroup.POST("/:id/cancel", middleware.RequirePermission("task:write"), taskHandler.CancelTask)
				taskGroup.POST("/:id/retry", middleware.RequirePermission("task:write"), taskHandler.RetryTask)
				taskGroup.POST("/:id/rescan", middleware.RequirePermission("task:write"), taskHandler.RescanTask)
				taskGroup.GET("/:id/logs", middleware.RequirePermission("task:read"), taskHandler.GetTaskLogs)
				// Task Results routes
				taskGroup.GET("/:id/results", middleware.RequirePermission("task:read"), resultHandler.GetTaskResults)
				taskGroup.GET("/:id/results/stats", middleware.RequirePermission("task:read"), resultHandler.GetTaskResultStats)
				taskGroup.GET("/:id/assets", middleware.RequirePermission("task:read"), assetHandler.ListTaskAssets)
				taskGroup.GET("/:id/results/subdomains", middleware.RequirePermission("task:read"), resultHandler.GetSubdomainResults)
				taskGroup.GET("/:id/results/ports", middleware.RequirePermission("task:read"), resultHandler.GetPortResults)
				taskGroup.GET("/:id/results/export", middleware.RequirePermission("task:read"), resultHandler.ExportResults)
			}

			// Results routes (for tag management and batch operations)
			resultGroup := protected.Group("/results")
			{
				resultGroup.PUT("/:id/tags", resultHandler.UpdateResultTags)
				resultGroup.POST("/:id/tags", resultHandler.AddResultTag)
				resultGroup.DELETE("/:id/tags", resultHandler.RemoveResultTag)
				resultGroup.POST("/batch-delete", resultHandler.BatchDeleteResults)
			}

			// Vulnerability routes
			vulnHandler := api.NewVulnHandler()
			reportHandler := api.NewReportHandler()
			vulnGroup := protected.Group("/vulnerabilities")
			{
				vulnGroup.GET("", vulnHandler.ListVulnerabilities)
				vulnGroup.GET("/stats", vulnHandler.GetVulnStats)
				vulnGroup.GET("/review-stats", vulnHandler.ReviewStats)            // 复核分布
				vulnGroup.GET("/statistics", vulnHandler.GetVulnStatistics)        // 详细统计
				vulnGroup.POST("/batch-update", vulnHandler.BatchUpdateVulnStatus) // 批量更新
				vulnGroup.GET("/:id", vulnHandler.GetVulnerability)
				vulnGroup.POST("", vulnHandler.CreateVulnerability)
				vulnGroup.PUT("/:id", vulnHandler.UpdateVulnerability)
				vulnGroup.DELETE("/:id", vulnHandler.DeleteVulnerability)
				vulnGroup.POST("/:id/review", vulnHandler.ReviewVuln)      // 复核（流转 + 记录）
				vulnGroup.GET("/:id/reviews", vulnHandler.ListVulnReviews) // 复核历史
				vulnGroup.PUT("/:id/fixed", vulnHandler.MarkVulnAsFixed)
				vulnGroup.PUT("/:id/ignore", vulnHandler.MarkVulnAsIgnored)
				vulnGroup.PUT("/:id/false-positive", vulnHandler.MarkVulnAsFalsePositive)
				vulnGroup.POST("/:id/verify", vulnHandler.VerifyVulnerability) // 验证漏洞
			}

			// POC routes
			pocHandler := api.NewPOCHandler()
			pocGroup := protected.Group("/pocs")
			{
				pocGroup.GET("", pocHandler.ListPOCs)
				pocGroup.GET("/statistics", pocHandler.GetPOCStatistics)
				pocGroup.POST("/import", pocHandler.ImportPOCsFromZip)
				pocGroup.POST("/batch-delete", pocHandler.BatchDeletePOCs)
				pocGroup.DELETE("/clear-all", pocHandler.ClearAllPOCs)
				pocGroup.GET("/:id", pocHandler.GetPOC)
				pocGroup.POST("", pocHandler.CreatePOC)
				pocGroup.PUT("/:id", pocHandler.UpdatePOC)
				pocGroup.DELETE("/:id", pocHandler.DeletePOC)
				pocGroup.POST("/:id/toggle", pocHandler.TogglePOCEnabled)
			}

			// 组件档案与证据质量
			componentHandler := api.NewComponentHandler()
			componentGroup := protected.Group("/components")
			{
				componentGroup.GET("/cves", componentHandler.CVEs)
				componentGroup.GET("/evidence-quality", componentHandler.EvidenceQuality)
			}

			// 手工验证工具（OOB / 凭据只读验证 / 差分 / JS 侦察），均要求管理员
			toolkitHandler := api.NewToolkitHandler()
			toolkitGroup := protected.Group("/tools", middleware.AdminMiddleware())
			{
				toolkitGroup.POST("/oob/domain", toolkitHandler.OOBDomain)
				toolkitGroup.POST("/oob/records", toolkitHandler.OOBRecords)
				toolkitGroup.POST("/creds/cloud", toolkitHandler.VerifyCloudCredential)
				toolkitGroup.POST("/creds/db", toolkitHandler.VerifyDB)
				toolkitGroup.POST("/creds/ssh", toolkitHandler.VerifySSH)
				toolkitGroup.POST("/diffprobe", toolkitHandler.DiffProbe)
				toolkitGroup.POST("/webrecon", toolkitHandler.WebRecon)
				toolkitGroup.POST("/quote-check", toolkitHandler.QuoteCheck)
				toolkitGroup.GET("/playbooks", toolkitHandler.Playbooks)
				toolkitGroup.POST("/playbooks/run", toolkitHandler.RunPlaybook)
				toolkitGroup.GET("/github-leak/dorks", toolkitHandler.GithubLeakDorks)
				toolkitGroup.POST("/github-leak/scan", toolkitHandler.GithubLeakScan)
				toolkitGroup.GET("/enterprise/providers", toolkitHandler.EnterpriseProviders)
				toolkitGroup.POST("/enterprise/search", toolkitHandler.EnterpriseSearch)
				toolkitGroup.POST("/extract", toolkitHandler.Extract)
			}

			// 自动 nuclei 验证（默认关闭）
			vulnVerifyHandler := api.NewVulnVerifyHandler()
			vulnVerifyGroup := protected.Group("/vuln-verify")
			{
				vulnVerifyGroup.GET("/stats", vulnVerifyHandler.Stats)
				vulnVerifyGroup.POST("/enqueue", middleware.AdminMiddleware(), vulnVerifyHandler.Enqueue)
			}

			// Report routes
			reportGroup := protected.Group("/reports")
			{
				reportGroup.GET("", vulnHandler.ListReports)
				reportGroup.GET("/templates", reportHandler.ListTemplates)
				reportGroup.POST("/generate", reportHandler.GenerateReport)
				reportGroup.GET("/:id/download", reportHandler.DownloadReport)
				reportGroup.GET("/:id", vulnHandler.GetReport)
				reportGroup.POST("", vulnHandler.CreateReport)
				reportGroup.DELETE("/:id", vulnHandler.DeleteReport)
			}

			// Vuln intel routes（9 个公开漏洞源的轮询结果）
			intelHandler := api.NewIntelHandler()
			intelGroup := protected.Group("/vuln-intel")
			{
				intelGroup.GET("", intelHandler.ListIntel)
				intelGroup.GET("/stats", intelHandler.Stats)
				// 轮询触发与设置写要走管理员：轮询会真实访问外部源，
				// 高频触发等于替别人扛爬取压力。
				intelGroup.POST("/poll", middleware.AdminMiddleware(), intelHandler.Poll)
				intelGroup.GET("/settings", intelHandler.GetSettings)
				intelGroup.PUT("/settings", middleware.AdminMiddleware(), intelHandler.UpdateSettings)
				// 富化会真实访问 GitHub API 并消耗配额，只给管理员。
				intelGroup.POST("/:unique_key/enrich", middleware.AdminMiddleware(), intelHandler.Enrich)
				intelGroup.GET("/:unique_key/enrich", intelHandler.EnrichStatus)
			}

			// Node routes
			nodeHandler := api.NewNodeHandler(nodeHub)
			nodeGroup := protected.Group("/nodes")
			{
				nodeGroup.GET("", nodeHandler.ListNodes)
				nodeGroup.GET("/stats", nodeHandler.GetNodeStats)
				nodeGroup.POST("/enroll", middleware.AdminMiddleware(), nodeHandler.EnrollNode)
				nodeGroup.POST("/deploy", middleware.AdminMiddleware(), nodeHandler.DeployNode)
				nodeGroup.POST("/register", nodeHandler.RegisterNode)
				nodeGroup.GET("/:id", nodeHandler.GetNode)
				nodeGroup.PUT("/:id", nodeHandler.UpdateNode)
				nodeGroup.DELETE("/:id", nodeHandler.DeleteNode)
				nodeGroup.POST("/:id/heartbeat", nodeHandler.Heartbeat)
				nodeGroup.PUT("/:id/status", nodeHandler.SetNodeStatus)
				nodeGroup.POST("/:id/token", middleware.AdminMiddleware(), nodeHandler.RotateNodeToken)
				nodeGroup.DELETE("/:id/token", middleware.AdminMiddleware(), nodeHandler.RevokeNodeToken)
				// 默认扫描节点：任务没显式指定节点时用它；空 = 任意在线节点。
				protected.GET("/nodes/default", nodeHandler.GetDefaultScanNode)
				protected.PUT("/nodes/default", middleware.AdminMiddleware(), nodeHandler.SetDefaultScanNode)
			}

			// Plugin routes
			pluginHandler := api.NewPluginHandler()
			pluginGroup := protected.Group("/plugins")
			{
				pluginGroup.GET("", pluginHandler.ListPlugins)
				pluginGroup.GET("/:id", pluginHandler.GetPlugin)
				pluginGroup.POST("", middleware.RequirePermission("settings:write"), pluginHandler.CreatePlugin)
				pluginGroup.PUT("/:id", middleware.RequirePermission("settings:write"), pluginHandler.UpdatePlugin)
				pluginGroup.DELETE("/:id", middleware.RequirePermission("settings:write"), pluginHandler.DeletePlugin)
				pluginGroup.PUT("/:id/toggle", middleware.RequirePermission("settings:write"), pluginHandler.TogglePlugin)
				pluginGroup.POST("/:id/install", middleware.RequirePermission("settings:write"), pluginHandler.InstallPlugin)
				pluginGroup.POST("/:id/uninstall", middleware.RequirePermission("settings:write"), pluginHandler.UninstallPlugin)
			}

			// Fingerprint routes
			fingerprintGroup := protected.Group("/fingerprints")
			{
				fingerprintGroup.GET("", pluginHandler.ListFingerprintRules)
				fingerprintGroup.POST("", middleware.RequirePermission("fingerprint:write"), pluginHandler.CreateFingerprintRule)
				fingerprintGroup.POST("/import", middleware.RequirePermission("fingerprint:write"), fpImportHandler.PreviewImport)
				fingerprintGroup.POST("/import/commit", middleware.RequirePermission("fingerprint:write"), fpImportHandler.CommitImport)
				fingerprintGroup.POST("/bulk", middleware.RequirePermission("fingerprint:write"), fpImportHandler.BulkToggle)
				fingerprintGroup.DELETE("/:id", middleware.RequirePermission("fingerprint:write"), pluginHandler.DeleteFingerprintRule)
			}

			// Dictionary routes
			dictionaryGroup := protected.Group("/dictionaries")
			{
				dictionaryGroup.GET("", middleware.RequirePermission("dictionary:read"), pluginHandler.ListDictionaries)
				dictionaryGroup.POST("", middleware.RequirePermission("dictionary:write"), pluginHandler.CreateDictionary)
				dictionaryGroup.POST("/preview", middleware.RequirePermission("dictionary:write"), pluginHandler.PreviewDictionary)
				dictionaryGroup.POST("/import", middleware.RequirePermission("dictionary:write"), pluginHandler.ImportDictionary)
				dictionaryGroup.GET("/:id/entries", middleware.RequirePermission("dictionary:read"), pluginHandler.ListDictionaryEntries)
				dictionaryGroup.DELETE("/:id", middleware.RequirePermission("dictionary:write"), pluginHandler.DeleteDictionary)
			}

			// Dashboard routes
			dashboardHandler := api.NewDashboardHandler()
			dashboardGroup := protected.Group("/dashboard")
			{
				dashboardGroup.GET("/stats", dashboardHandler.GetDashboardStats)
				dashboardGroup.GET("/trends", dashboardHandler.GetTrends)
				dashboardGroup.GET("/activities", dashboardHandler.GetRecentActivities)
				dashboardGroup.GET("/recent-tasks", dashboardHandler.GetRecentTasks)
				dashboardGroup.GET("/recent-vulns", dashboardHandler.GetRecentVulnerabilities)
				dashboardGroup.GET("/recent-assets", dashboardHandler.GetRecentAssets)
			}

			// Scan routes (实时扫描)
			scanHandler := api.NewScanHandler()
			scanGroup := protected.Group("/scan")
			scanGroup.Use(middleware.RequirePermission("run:execute"))
			{
				// 端口扫描
				scanGroup.POST("/port/quick", scanHandler.QuickPortScan)
				scanGroup.POST("/port/custom", scanHandler.CustomPortScan)
				scanGroup.GET("/port/single", scanHandler.SinglePortScan)

				// C段扫描
				scanGroup.POST("/csegment", scanHandler.CSegmentScan)
				scanGroup.POST("/csegment/quick", scanHandler.QuickCSegmentScan)
				scanGroup.POST("/csegment/full", scanHandler.FullCSegmentScan)

				// 域名扫描
				scanGroup.GET("/domain/info", scanHandler.DomainInfo)
				scanGroup.POST("/subdomain/quick", scanHandler.QuickSubdomainScan)
				scanGroup.POST("/subdomain/full", scanHandler.FullSubdomainScan)
				scanGroup.POST("/subdomain/custom", scanHandler.CustomSubdomainScan)

				// CDN检测
				scanGroup.POST("/cdn/detect", scanHandler.CDNDetect)
				scanGroup.POST("/cdn/batch", scanHandler.CDNBatchDetect)

				// 指纹识别
				scanGroup.POST("/fingerprint", scanHandler.FingerprintScan)
				scanGroup.POST("/fingerprint/batch", scanHandler.FingerprintBatchScan)

				// 漏洞扫描
				scanGroup.POST("/vuln", scanHandler.VulnScan)
				scanGroup.POST("/vuln/quick", scanHandler.VulnQuickScan)
				scanGroup.GET("/vuln/pocs", scanHandler.GetPOCList)

				// 目录扫描
				scanGroup.POST("/dir", scanHandler.DirScan)
				scanGroup.POST("/dir/quick", scanHandler.QuickDirScan)

				// 敏感信息扫描
				scanGroup.POST("/sensitive", scanHandler.SensitiveScan)
				scanGroup.POST("/sensitive/batch", scanHandler.SensitiveBatchScan)

				// 爬虫
				scanGroup.POST("/crawler", scanHandler.CrawlerScan)

				// 弱口令扫描
				scanGroup.POST("/weakpwd", scanHandler.WeakPwdScan)

				// 子域名接管检测
				scanGroup.POST("/takeover", scanHandler.TakeoverScan)
				scanGroup.POST("/takeover/batch", scanHandler.TakeoverBatchScan)
				scanGroup.GET("/takeover/fingerprints", scanHandler.GetTakeoverFingerprints)
			}

			// 数据源与凭据（G4）：凭据只写不读
			sourceHandler := api.NewSourceHandler()
			sourceGroup := protected.Group("/sources")
			{
				sourceGroup.GET("", middleware.RequirePermission("source:read"), sourceHandler.ListSources)
				sourceGroup.GET("/:id", middleware.RequirePermission("source:read"), sourceHandler.GetSource)
				sourceGroup.POST("", middleware.RequirePermission("source:write"), sourceHandler.CreateSource)
				sourceGroup.PUT("/:id", middleware.RequirePermission("source:write"), sourceHandler.UpdateSource)
				sourceGroup.DELETE("/:id", middleware.RequirePermission("source:write"), sourceHandler.DeleteSource)
				sourceGroup.POST("/:id/test", middleware.RequirePermission("source:write"), sourceHandler.TestSource)
			}

			// 兼容旧设置页：第三方 API 配置。
			// 底层已改为 sources 表（AES-GCM 密文），不再挂旧 thirdparty 客户端。
			protected.GET("/thirdparty/config", sourceHandler.GetLegacyConfig)
			protected.PUT("/thirdparty/config", middleware.RequirePermission("source:write"), sourceHandler.UpdateLegacyConfig)
			protected.GET("/thirdparty/sources", sourceHandler.GetLegacySources)

			// 审计日志（只读，管理员）
			auditHandler := api.NewAuditHandler()
			protected.GET("/audit", middleware.RequirePermission("audit:read"), auditHandler.ListAudit)

			// 数字资产名单与本地文档导入（v4 §14）：名单与站点库解耦
			digitalHandler := api.NewDigitalHandler()
			protected.GET("/digital-assets", middleware.RequirePermission("digital:read"), digitalHandler.ListDigitalAssets)
			protected.POST("/digital-assets/preview", middleware.RequirePermission("digital:write"), digitalHandler.PreviewDigitalAssets)
			protected.POST("/digital-assets/commit", middleware.RequirePermission("digital:write"), digitalHandler.CommitDigitalImport)
			protected.DELETE("/digital-assets/:id", middleware.RequirePermission("digital:write"), digitalHandler.DeleteDigitalAsset)
			protected.GET("/digital-imports", middleware.RequirePermission("digital:read"), digitalHandler.ListImportBatches)
			protected.POST("/digital-imports/preview", middleware.RequirePermission("digital:write"), digitalHandler.PreviewDigitalAssets)
			protected.POST("/digital-imports/commit", middleware.RequirePermission("digital:write"), digitalHandler.CommitDigitalImport)
			protected.POST("/digital-imports/undo", middleware.RequirePermission("digital:write"), digitalHandler.UndoImportBatch)
			protected.POST("/digital-imports/cancel", middleware.RequirePermission("digital:write"), digitalHandler.CancelPreview)
			protected.POST("/local-documents/preview", middleware.RequirePermission("digital:write"), digitalHandler.PreviewLocalDocument)
			protected.POST("/local-documents/import", middleware.RequirePermission("digital:write"), digitalHandler.ImportLocalDocument)

			// 企业身份线索（v4 功能域 15）：手工维护 + 数据源采集 + 与 APP 名单对齐
			enterpriseHandler := api.NewEnterpriseHandler()
			protected.GET("/enterprise-entities", middleware.RequirePermission("digital:read"), enterpriseHandler.List)
			protected.GET("/enterprise-entities/providers", middleware.RequirePermission("digital:read"), enterpriseHandler.Providers)
			protected.POST("/enterprise-entities", middleware.RequirePermission("digital:write"), enterpriseHandler.Upsert)
			protected.POST("/enterprise-entities/import", middleware.RequirePermission("digital:write"), enterpriseHandler.Import)
			protected.POST("/enterprise-entities/collect", middleware.RequirePermission("digital:write"), enterpriseHandler.Collect)
			protected.POST("/enterprise-entities/search", middleware.RequirePermission("digital:write"), enterpriseHandler.SearchProvider)
			protected.POST("/enterprise-entities/discover", middleware.RequirePermission("digital:write"), enterpriseHandler.Discover)
			protected.GET("/enterprise-entities/jobs", middleware.RequirePermission("digital:read"), enterpriseHandler.Jobs)
			protected.GET("/enterprise-entities/jobs/:id", middleware.RequirePermission("digital:read"), enterpriseHandler.GetJob)
			protected.POST("/enterprise-entities/jobs/:id/cancel", middleware.RequirePermission("digital:write"), enterpriseHandler.CancelJob)
			protected.GET("/enterprise-entities/candidates", middleware.RequirePermission("digital:read"), enterpriseHandler.Candidates)
			protected.DELETE("/enterprise-entities/:id", middleware.RequirePermission("digital:write"), enterpriseHandler.Delete)
			protected.GET("/enterprise-entities/:id/assets", middleware.RequirePermission("digital:read"), enterpriseHandler.AlignedAssets)

			// 工信部 ICP 官方查询（异步单 worker + 全局限速，独立队列）
			icpHandler := api.NewICPHandler()
			protected.POST("/icp/queries", middleware.RequirePermission("run:execute"), icpHandler.Enqueue)
			protected.GET("/icp/queries", middleware.RequirePermission("digital:read"), icpHandler.List)
			protected.GET("/icp/queries/:id", middleware.RequirePermission("digital:read"), icpHandler.Get)
			protected.POST("/icp/queries/:id/cancel", middleware.RequirePermission("run:execute"), icpHandler.Cancel)

			// 通知管理
			notifyHandler := api.NewNotifyHandler()
			notifyGroup := protected.Group("/notify")
			{
				// 配置管理
				notifyGroup.GET("/types", notifyHandler.GetSupportedTypes)
				notifyGroup.GET("/configs", notifyHandler.GetConfigs)
				notifyGroup.POST("/configs", notifyHandler.AddConfig)
				notifyGroup.PUT("/configs", notifyHandler.UpdateConfig)
				notifyGroup.DELETE("/configs", notifyHandler.DeleteConfig)
				notifyGroup.POST("/configs/enable", notifyHandler.EnableConfig)

				// 测试和发送
				notifyGroup.POST("/test", notifyHandler.TestConfig)
				notifyGroup.POST("/send", notifyHandler.SendNotification)

				// 历史记录
				notifyGroup.GET("/history", notifyHandler.GetHistory)

				// 站内通知（铃铛）
				notifyGroup.GET("/notifications", notifyHandler.ListNotifications)
				notifyGroup.GET("/notifications/unread-count", notifyHandler.UnreadCount)
				notifyGroup.POST("/notifications/read-all", notifyHandler.MarkAllNotificationsRead)
				notifyGroup.POST("/notifications/:id/read", notifyHandler.MarkNotificationRead)
			}

			// Nuclei POC 扫描
			nucleiHandler := api.NewNucleiHandler()
			nucleiRuntimeHandler := api.NewNucleiRuntimeHandler()
			nucleiGroup := protected.Group("/nuclei")
			{
				// 模板管理
				nucleiGroup.GET("/templates", nucleiHandler.GetTemplates)
				nucleiGroup.GET("/templates/:id", nucleiHandler.GetTemplate)
				nucleiGroup.POST("/templates", nucleiHandler.UploadTemplate)
				nucleiGroup.DELETE("/templates/:id", nucleiHandler.DeleteTemplate)

				// 统计和管理
				nucleiGroup.GET("/tags", nucleiHandler.GetTags)
				nucleiGroup.GET("/statistics", nucleiHandler.GetStatistics)
				nucleiGroup.POST("/reload", nucleiHandler.ReloadTemplates)
				nucleiGroup.POST("/validate", nucleiHandler.ValidateTemplate)

				// 扫描
				nucleiGroup.POST("/scan", nucleiHandler.ScanTarget)
				nucleiGroup.GET("/runtime/status", nucleiRuntimeHandler.Status)
				nucleiGroup.POST("/runtime/ensure", middleware.AdminMiddleware(), nucleiRuntimeHandler.Ensure)
				nucleiGroup.POST("/runtime/update", middleware.AdminMiddleware(), nucleiRuntimeHandler.Update)
				nucleiGroup.PUT("/runtime/settings", middleware.AdminMiddleware(), nucleiRuntimeHandler.UpdateSettings)
			}

			// 页面变化监控
			monitorHandler := api.NewMonitorHandler(notifyHandler.GetManager())
			monitorGroup := protected.Group("/monitor")
			{
				// 监控类型
				monitorGroup.GET("/types", monitorHandler.GetMonitorTypes)

				// 页面管理
				monitorGroup.GET("/pages", monitorHandler.ListMonitoredPages)
				monitorGroup.GET("/pages/:id", monitorHandler.GetMonitoredPage)
				monitorGroup.POST("/pages", monitorHandler.AddMonitoredPage)
				monitorGroup.DELETE("/pages/:id", monitorHandler.RemoveMonitoredPage)
				monitorGroup.PUT("/pages/:id/enable", monitorHandler.EnableMonitoredPage)
				monitorGroup.POST("/pages/:id/check", monitorHandler.CheckPageNow)

				// 变化历史
				monitorGroup.GET("/changes", monitorHandler.GetChanges)
			}

			// 自动化巡航任务
			cruiseHandler := api.NewCruiseHandler()
			cruiseGroup := protected.Group("/cruises")
			{
				// 基本 CRUD
				cruiseGroup.GET("", cruiseHandler.ListCruises)
				cruiseGroup.GET("/stats", cruiseHandler.GetCruiseStats)
				cruiseGroup.GET("/preview-targets", cruiseHandler.PreviewProjectTargets)
				cruiseGroup.POST("", cruiseHandler.CreateCruise)
				cruiseGroup.GET("/:id", cruiseHandler.GetCruise)
				cruiseGroup.PUT("/:id", cruiseHandler.UpdateCruise)
				cruiseGroup.DELETE("/:id", cruiseHandler.DeleteCruise)

				// 控制操作
				cruiseGroup.POST("/:id/enable", cruiseHandler.EnableCruise)
				cruiseGroup.POST("/:id/disable", cruiseHandler.DisableCruise)
				cruiseGroup.POST("/:id/run", cruiseHandler.RunNow)

				// 执行日志
				cruiseGroup.GET("/:id/logs", cruiseHandler.GetCruiseLogs)
			}

			// 分布式任务队列（存储为 PostgreSQL 的 task_jobs，无外部依赖）
			cfg := config.GetConfig()
			queueConfig := &queue.QueueConfig{
				QueueName:   "moon-gazing-tower",
				Workers:     cfg.Scanner.WorkerCount,
				TaskTimeout: time.Duration(cfg.Scanner.Timeout) * time.Second,
				MaxRetries:  cfg.Scanner.RetryCount,
			}

			log.Printf("[Router] Initializing queue on PostgreSQL")
			queueHandler, err := api.NewQueueHandler(queueConfig)
			if err == nil {
				log.Printf("[Router] Queue handler initialized successfully")
				queueGroup := protected.Group("/queue")
				{
					queueGroup.GET("/stats", queueHandler.GetStats)
					queueGroup.GET("/types", queueHandler.GetTaskTypes)
					queueGroup.GET("/workers", queueHandler.GetWorkerStatus)
					queueGroup.POST("/tasks", queueHandler.EnqueueTask)
					queueGroup.GET("/tasks/:id/result", middleware.RequirePermission("task:read"), queueHandler.GetTaskResult)
					queueGroup.GET("/tasks/pending", middleware.RequirePermission("task:read"), queueHandler.GetPendingTasks)
					queueGroup.GET("/tasks/processing", middleware.RequirePermission("task:read"), queueHandler.GetProcessingTasks)
					queueGroup.GET("/tasks/deadletter", middleware.RequirePermission("task:read"), queueHandler.GetDeadLetterTasks)
					queueGroup.POST("/tasks/deadletter/:id/retry", queueHandler.RetryDeadLetterTask)
					queueGroup.DELETE("/tasks/deadletter", queueHandler.ClearDeadLetter)
				}
			} else {
				log.Printf("[Router] Queue handler not available: %v", err)
			}
		}
	}

	return r
}

func SetupRouterWithWebSocket(hub *api.Hub, nodeHub *api.NodeHub) *gin.Engine {
	r := setupRouter(nodeHub)

	// Register WebSocket routes
	RegisterWebSocketRoutes(r, hub)

	return r
}

// SetupNodeGatewayRouter 是节点专用 HTTPS 监听：只暴露 /api/node/*，
// 不包含 Web UI、用户 API 或管理接口。由 main 用独立端口 + TLS 启动。
func SetupNodeGatewayRouter(nodeHub *api.NodeHub, binaryHandler *api.NodeBinaryHandler) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "scope": "node-gateway"})
	})

	nodeGateway := api.NewNodeGatewayHandler(nodeHub)
	nodeAPI := r.Group("/api/node")
	nodeAPI.Use(api.NodeAuthMiddleware(service.NewNodeService()))
	{
		nodeAPI.GET("/ws", nodeGateway.WS)
		nodeAPI.GET("/binary", binaryHandler.Download)
		nodeAPI.GET("/tasks/:id", nodeGateway.GetTask)
		nodeAPI.PUT("/tasks/:id", nodeGateway.UpdateTask)
		nodeAPI.POST("/tasks/:id/results", nodeGateway.PostResults)
		nodeAPI.POST("/tasks/:id/assets", nodeGateway.PostAssets)
		nodeAPI.POST("/tasks/:id/cdn", nodeGateway.PostCDN)
		nodeAPI.GET("/pocs", nodeGateway.ListPOCs)
	}
	return r
}

func RegisterWebSocketRoutes(router *gin.Engine, hub *api.Hub) {
	// WebSocket endpoint for real-time data
	router.GET("/api/ws", hub.WebSocketHandler)
}

// serveFrontend 托管前端构建产物，并为 SPA 路由做 index.html 回退。
//
// 查找顺序：ZRE_FRONTEND_DIST → ../frontend/dist → ./frontend/dist → ./dist。
// 一个都找不到时静默跳过——本地开发通常用 vite dev server（5173 代理 /api），
// 生产一般交给 nginx；这里托管只是为了单进程也能直接打开。
func serveFrontend(r *gin.Engine) {
	dir := frontendDist()
	if dir == "" {
		return
	}
	index := filepath.Join(dir, "index.html")

	// 静态产物挂 /static：/assets 让给前端的资产页路由，否则直接访问资产页会被静态目录劫持成白屏。
	// 挂 dist 根目录而不是 dist/assets —— 构建产物引用的是 /static/assets/xxx.js，
	// 挂子目录会变成 /static/assets/assets/xxx.js，全部落到 SPA 兜底返回 index.html。
	r.Static("/static", dir)

	serveFile := func(c *gin.Context, rel string) bool {
		// 只接受挂在 dir 下的路径，避免 ../ 穿越。
		clean := filepath.Clean("/" + rel)
		full := filepath.Join(dir, clean)
		absDir, err1 := filepath.Abs(dir)
		absFull, err2 := filepath.Abs(full)
		if err1 != nil || err2 != nil || !strings.HasPrefix(absFull, absDir) {
			return false
		}
		st, err := os.Stat(full)
		if err != nil || st.IsDir() {
			return false
		}
		if clean == "/index.html" {
			// 构建后 assets 文件名会变，index.html 不能缓存，否则旧 chunk 会 404。
			c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
		}
		c.File(full)
		return true
	}

	r.NoRoute(func(c *gin.Context) {
		path := c.Request.URL.Path
		// /api 下的未知路径仍然按 API 404 返回，不要被 SPA 回退吞掉。
		if strings.HasPrefix(path, "/api/") {
			c.JSON(http.StatusNotFound, gin.H{"code": 404, "message": "not found"})
			return
		}
		if serveFile(c, path) {
			return
		}
		c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
		c.File(index)
	})

	log.Printf("[Router] 前端静态资源: %s", dir)
}

func frontendDist() string {
	candidates := []string{os.Getenv("ZRE_FRONTEND_DIST")}
	candidates = append(candidates,
		"../frontend/dist", "./frontend/dist", "./dist")
	for _, dir := range candidates {
		if dir == "" {
			continue
		}
		if st, err := os.Stat(filepath.Join(dir, "index.html")); err == nil && !st.IsDir() {
			return dir
		}
	}
	return ""
}
