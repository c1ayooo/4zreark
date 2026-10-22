package service

import (
	"context"
	"log"
	"os"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/scanner/fingerprint"
	"github.com/c1ayooo/4zreark/scanner/vulnscan"
	"github.com/c1ayooo/4zreark/scanner/webscan"
)

// executeFingerprintScan 执行指纹扫描
func (e *TaskExecutor) executeFingerprintScan(task *models.Task, jobID int64) {
	log.Printf("[TaskExecutor] Executing fingerprint scan for task: %s", task.ID.Hex())

	targets := task.Targets
	if len(targets) == 0 {
		e.failTask(task, jobID, "没有目标")
		return
	}

	results := make([]models.ScanResult, 0)
	fpScanner := fingerprint.NewFingerprintScanner(20)

	for i, target := range targets {
		progress := int((float64(i) / float64(len(targets))) * 100)
		e.updateProgress(task, progress)

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		fpResult := fpScanner.ScanFingerprint(ctx, target)
		cancel()

		for _, fp := range fpResult.Fingerprints {
			result := models.ScanResult{
				TaskID:      task.ID,
				WorkspaceID: task.WorkspaceID,
				Type:        models.ResultTypeService,
				Source:      "主动扫描",
				Data: map[string]interface{}{
					"target":     target,
					"name":       fp.Name,
					"version":    fp.Version,
					"category":   fp.Category,
					"confidence": fp.Confidence,
				},
				CreatedAt: time.Now(),
			}
			results = append(results, result)
		}
	}

	e.saveResults(task, results)
	e.completeTask(task, jobID, len(results))
}

// executeVulnScan 执行漏洞扫描
func (e *TaskExecutor) executeVulnScan(task *models.Task, jobID int64) {
	log.Printf("[TaskExecutor] Executing vuln scan for task: %s", task.ID.Hex())

	targets := task.Targets
	if len(targets) == 0 {
		e.failTask(task, jobID, "没有目标")
		return
	}

	results := make([]models.ScanResult, 0)

	// 模板来源：POC 库（pocs 表）里启用的 nuclei 模板。
	// 用 nuclei CLI 执行：进程内执行器的 DSL 求值器是简化实现，会大面积误报。
	dir, err := os.MkdirTemp("", "zre-nuclei-*")
	if err != nil {
		e.failTask(task, jobID, "创建模板临时目录失败: "+err.Error())
		return
	}
	defer os.RemoveAll(dir)

	count, err := NewNucleiService().MaterializeTemplates(dir, []string{"critical", "high", "medium"}, nil, nil)
	if err != nil || count == 0 {
		log.Printf("[TaskExecutor] POC 库无可用模板，回退内置 POC（err=%v）", err)
		fallback := vulnscan.NewVulnScanner(10)
		for _, target := range targets {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			vulnResult := fallback.ScanVuln(ctx, target, nil)
			cancel()
			for _, vuln := range vulnResult.Vulns {
				results = append(results, models.ScanResult{
					TaskID:      task.ID,
					WorkspaceID: task.WorkspaceID,
					Type:        models.ResultTypeVuln,
					Source:      "主动扫描",
					Data: map[string]interface{}{
						"target":      target,
						"name":        vuln.Name,
						"severity":    vuln.Severity,
						"description": vuln.Description,
						"vuln_id":     vuln.VulnID,
						"evidence":    vuln.Evidence,
						"matched_at":  vuln.MatchedAt,
					},
					CreatedAt: time.Now(),
				})
			}
		}
		e.saveResults(task, results)
		e.completeTask(task, jobID, len(results))
		return
	}

	scanner := vulnscan.NewNucleiCLIScanner(dir)
	if !scanner.IsAvailable() {
		e.failTask(task, jobID, "nuclei CLI 不可用")
		return
	}

	timeout := time.Duration(len(targets))*5*time.Minute + 10*time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	scanResults, err := scanner.Scan(ctx, targets, &vulnscan.NucleiScanConfig{
		Concurrency: 25,
		RateLimit:   50, // 与自动链路 nucleiruntime 的 50 硬顶对齐：150rps 对小目标是 DoS 级
		Timeout:     timeout,
	})
	if err != nil {
		e.failTask(task, jobID, "nuclei 扫描失败: "+err.Error())
		return
	}

	for _, r := range scanResults {
		if r == nil {
			continue
		}
		results = append(results, models.ScanResult{
			TaskID:      task.ID,
			WorkspaceID: task.WorkspaceID,
			Type:        models.ResultTypeVuln,
			Source:      "主动扫描",
			Data: map[string]interface{}{
				"target":      r.Host,
				"name":        r.TemplateName,
				"severity":    strings.ToLower(r.Severity),
				"description": r.Description,
				"vuln_id":     r.TemplateID,
				"template_id": r.TemplateID,
				"cve_id":      r.CVEID,
				"evidence":    r.URL,
				"matched_at":  r.URL,
			},
			CreatedAt: time.Now(),
		})
	}

	log.Printf("[TaskExecutor] vuln scan completed: %d templates, %d matched", count, len(results))
	e.saveResults(task, results)
	e.completeTask(task, jobID, len(results))
}

// executeContentScan 执行目录扫描 (使用 Spray)
func (e *TaskExecutor) executeContentScan(task *models.Task, jobID int64) {
	log.Printf("[TaskExecutor] Executing content scan with Spray for task: %s", task.ID.Hex())

	targets := task.Targets
	if len(targets) == 0 {
		e.failTask(task, jobID, "没有目标")
		return
	}

	sprayScanner := webscan.NewSprayScanner()
	if sprayScanner == nil || !sprayScanner.IsAvailable() {
		e.failTask(task, jobID, "Spray 扫描器不可用")
		return
	}

	results := make([]models.ScanResult, 0)

	for i, target := range targets {
		progress := int((float64(i) / float64(len(targets))) * 100)
		e.updateProgress(task, progress)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		sprayResult, err := sprayScanner.Scan(ctx, target)
		cancel()

		if err != nil {
			log.Printf("[TaskExecutor] Spray scan error for %s: %v", target, err)
			continue
		}

		if sprayResult == nil {
			continue
		}

		for _, entry := range sprayResult.Results {
			result := models.ScanResult{
				TaskID:      task.ID,
				WorkspaceID: task.WorkspaceID,
				Type:        models.ResultTypeDirScan,
				Source:      "spray",
				Data: map[string]interface{}{
					"target":       target,
					"url":          entry.URL,
					"path":         entry.Path,
					"status":       entry.StatusCode,
					"size":         entry.BodyLength,
					"content_type": entry.ContentType,
					"title":        entry.Title,
				},
				CreatedAt: time.Now(),
			}
			results = append(results, result)
		}
	}

	e.saveResults(task, results)
	e.completeTask(task, jobID, len(results))
}

// executeSensitiveScan 执行敏感信息扫描
func (e *TaskExecutor) executeSensitiveScan(task *models.Task, jobID int64) {
	log.Printf("[TaskExecutor] Executing sensitive scan for task: %s", task.ID.Hex())

	targets := task.Targets
	if len(targets) == 0 {
		e.failTask(task, jobID, "没有目标")
		return
	}

	results := make([]models.ScanResult, 0)
	contentScanner := webscan.NewContentScanner(20)

	for i, target := range targets {
		progress := int((float64(i) / float64(len(targets))) * 100)
		e.updateProgress(task, progress)

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		sensitiveResult := contentScanner.ScanSensitiveInfo(ctx, target)
		cancel()

		for _, finding := range sensitiveResult.Findings {
			result := models.ScanResult{
				TaskID:      task.ID,
				WorkspaceID: task.WorkspaceID,
				Type:        models.ResultTypeSensitive,
				Source:      "主动扫描",
				Data: map[string]interface{}{
					"target":   target,
					"type":     finding.Type,
					"pattern":  finding.Pattern,
					"matches":  finding.Matches,
					"location": finding.Location,
					"severity": finding.Severity,
				},
				CreatedAt: time.Now(),
			}
			results = append(results, result)
		}
	}

	e.saveResults(task, results)
	e.completeTask(task, jobID, len(results))
}

// executeCrawlerScan 执行爬虫扫描 (Katana + Rad)
func (e *TaskExecutor) executeCrawlerScan(task *models.Task, jobID int64) {
	log.Printf("[TaskExecutor] Executing crawler scan for task: %s", task.ID.Hex())

	targets := task.Targets
	if len(targets) == 0 {
		e.failTask(task, jobID, "没有目标")
		return
	}

	results := make([]models.ScanResult, 0)
	assetSvc := NewAssetService()

	katanaScanner := webscan.NewKatanaScanner()
	radScanner := webscan.NewRadScanner()

	useKatana := katanaScanner.IsAvailable()
	useRad := radScanner.IsAvailable()

	if useKatana {
		log.Printf("[TaskExecutor] Using Katana for web crawling")
	}
	if useRad {
		log.Printf("[TaskExecutor] Using Rad for web crawling")
	}

	for i, target := range targets {
		progress := int((float64(i) / float64(len(targets))) * 100)
		e.updateProgress(task, progress)

		// 本次 target 采到的全部 URL：既写 scan_results，也归到站点路由。
		collected := make([]CrawledEndpoint, 0, 128)

		// Katana 爬取
		if useKatana {
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(katanaScanner.ExecutionTimeout)*time.Minute)
			katanaResult, err := katanaScanner.Crawl(ctx, target)
			cancel()

			if err == nil {
				for _, url := range katanaResult.URLs {
					collected = append(collected, CrawledEndpoint{URL: url.URL, Method: url.Method, StatusCode: url.StatusCode})
					result := models.ScanResult{
						TaskID:      task.ID,
						WorkspaceID: task.WorkspaceID,
						Type:        models.ResultTypeCrawler,
						Source:      "katana",
						Data: map[string]interface{}{
							"target":      target,
							"url":         url.URL,
							"method":      url.Method,
							"status_code": url.StatusCode,
							"crawler":     "katana",
						},
						CreatedAt: time.Now(),
					}
					results = append(results, result)
				}
			} else {
				log.Printf("[TaskExecutor] Katana failed for %s: %v", target, err)
			}
		}

		// Rad 爬取
		if useRad {
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(radScanner.ExecutionTimeout)*time.Minute)
			radResult, err := radScanner.Crawl(ctx, target)
			cancel()

			if err == nil {
				for _, url := range radResult.URLs {
					collected = append(collected, CrawledEndpoint{URL: url.URL, Method: url.Method})
					result := models.ScanResult{
						TaskID:      task.ID,
						WorkspaceID: task.WorkspaceID,
						Type:        models.ResultTypeCrawler,
						Source:      "rad",
						Data: map[string]interface{}{
							"target":  target,
							"url":     url.URL,
							"method":  url.Method,
							"crawler": "rad",
						},
						CreatedAt: time.Now(),
					}
					results = append(results, result)
				}
			} else {
				log.Printf("[TaskExecutor] Rad failed for %s: %v", target, err)
			}
		}

		// 两个外部爬虫都不可用时用原生爬虫兜底，保证路由采集不被环境卡死。
		if !useKatana && !useRad {
			crawler := webscan.NewWebCrawler(3, 500, 10)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			nativeResult := crawler.Crawl(ctx, target)
			cancel()
			if nativeResult != nil {
				for _, url := range nativeResult.URLs {
					collected = append(collected, CrawledEndpoint{URL: url.URL, Method: url.Method, StatusCode: url.StatusCode})
					results = append(results, models.ScanResult{
						TaskID:      task.ID,
						WorkspaceID: task.WorkspaceID,
						Type:        models.ResultTypeCrawler,
						Source:      "native",
						Data: map[string]interface{}{
							"target":      target,
							"url":         url.URL,
							"method":      url.Method,
							"status_code": url.StatusCode,
							"crawler":     "native",
						},
						CreatedAt: time.Now(),
					})
				}
			}
		}

		// 按 host 归到站点：匹配不到站点的 URL 会被跳过。
		if sites, saved, err := assetSvc.SaveCrawledRoutes("crawler", collected); err != nil {
			log.Printf("[TaskExecutor] 保存路由失败 %s: %v", target, err)
		} else if saved > 0 {
			log.Printf("[TaskExecutor] 路由入库 %s: 站点 %d 个，路由 %d 条", target, sites, saved)
		}
	}

	e.saveResults(task, results)
	e.completeTask(task, jobID, len(results))
}
