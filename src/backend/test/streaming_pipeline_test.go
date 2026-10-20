package test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/service/pipeline"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// ========== StreamingPipeline 集成测试 ==========

// TestStreamingPipelineFullFlow 完整流程测试
// 测试: 子域名 → CDN检测 → 端口扫描 → 指纹识别 → URL爬虫
// 注意：子域名爆破需要 sudo 权限（ksubdomain需要raw socket）
func TestStreamingPipelineFullFlow(t *testing.T) {
	printSeparator("StreamingPipeline 完整流程测试")
	fmt.Println("流程: 子域名 → 端口扫描 → 指纹识别 → URL爬虫")

	// 创建测试任务
	task := &models.Task{
		ID:        primitive.NewObjectID(),
		Name:      "Full Pipeline Test",
		Type:      models.TaskTypeFull,
		Targets:   []string{"swirecocacola.com"},
		Status:    models.TaskStatusRunning,
		CreatedAt: time.Now(),
	}

	// 创建流水线配置（完整扫描）
	config := &pipeline.PipelineConfig{
		SubdomainScan:          true, // 启用子域名扫描
		SubdomainMaxEnumTime:   5,    // 5分钟限制
		SubdomainResolveIP:     true,
		SubdomainCheckTakeover: false,
		PortScan:               true,
		PortScanMode:           "top1000", // Top1000端口
		SkipCDN:                false,     // 不跳过CDN，继续扫描
		Fingerprint:            true,
		WebCrawler:             true,
		DirScan:                false,
		SensitiveScan:          false,
	}

	// 创建流水线
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	pipe := pipeline.NewStreamingPipeline(ctx, task, config)

	// 启动流水线
	err := pipe.Start(task.Targets)
	if err != nil {
		t.Fatalf("Failed to start pipeline: %v", err)
	}

	// 收集结果
	fmt.Println("\n[收集结果]")
	var subdomainCount, portCount, assetCount, urlCount int
	startTime := time.Now()

	for result := range pipe.Results() {
		switch r := result.(type) {
		case pipeline.SubdomainResult:
			subdomainCount++
			fmt.Printf("  [子域名] %s -> %v\n", r.Host, r.IPs)

		case pipeline.PortAlive:
			portCount++
			fmt.Printf("  [端口] %s:%s - %s\n", r.Host, r.Port, r.Service)

		case pipeline.AssetHttp:
			assetCount++
			title := r.Title
			if len(title) > 30 {
				title = title[:30] + "..."
			}
			fmt.Printf("  [资产] %s (状态: %d, 标题: %s)\n", r.URL, r.StatusCode, title)

		case pipeline.UrlResult:
			urlCount++
			if urlCount <= 10 { // 只显示前10个URL
				fmt.Printf("  [URL] %s -> %s\n", r.Source, r.Output)
			}
		}
	}

	duration := time.Since(startTime)

	// 结果统计
	printSeparator("测试完成")
	fmt.Printf("总耗时: %v\n", duration)
	fmt.Printf("子域名: %d 个\n", subdomainCount)
	fmt.Printf("开放端口: %d 个\n", portCount)
	fmt.Printf("Web资产: %d 个\n", assetCount)
	fmt.Printf("发现URL: %d 个\n", urlCount)

	// 验证
	if portCount == 0 && assetCount == 0 {
		t.Log("Warning: No ports or assets found (target may be down or blocked)")
	}

	t.Logf("Pipeline completed successfully: %d subdomains, %d ports, %d assets, %d urls",
		subdomainCount, portCount, assetCount, urlCount)
}

// TestStreamingPipelineSubdomainOnly 仅子域名扫描测试
func TestStreamingPipelineSubdomainOnly(t *testing.T) {
	printSeparator("StreamingPipeline 子域名扫描测试")
	fmt.Println("仅测试子域名发现，不进行后续端口/指纹扫描")

	task := &models.Task{
		ID:        primitive.NewObjectID(),
		Name:      "Subdomain Only Test",
		Type:      models.TaskTypeSubdomain,
		Targets:   []string{"swirecocacola.com"},
		Status:    models.TaskStatusRunning,
		CreatedAt: time.Now(),
	}

	// 仅启用子域名扫描
	config := &pipeline.PipelineConfig{
		SubdomainScan:          true,
		SubdomainMaxEnumTime:   10, // 10分钟限制
		SubdomainResolveIP:     true,
		SubdomainCheckTakeover: false,
		PortScan:               false, // 不进行端口扫描
		Fingerprint:            false,
		WebCrawler:             false,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	pipe := pipeline.NewStreamingPipeline(ctx, task, config)

	err := pipe.Start(task.Targets)
	if err != nil {
		t.Fatalf("Failed to start pipeline: %v", err)
	}

	fmt.Println("\n[发现的子域名]")
	var subdomainCount int
	subdomains := make([]string, 0)

	for result := range pipe.Results() {
		switch r := result.(type) {
		case pipeline.SubdomainResult:
			subdomainCount++
			subdomains = append(subdomains, r.Host)
			fmt.Printf("  [%d] %s -> %v\n", subdomainCount, r.Host, r.IPs)
		}
	}

	printSeparator("结果统计")
	fmt.Printf("发现子域名: %d 个\n", subdomainCount)
	fmt.Println("\n子域名列表:")
	for i, sub := range subdomains {
		fmt.Printf("  %d. %s\n", i+1, sub)
	}

	if subdomainCount == 0 {
		t.Log("Warning: No subdomains found")
	}

	t.Logf("Subdomain scan completed: %d subdomains found", subdomainCount)
}

// TestStreamingPipelinePortScanOnly 仅端口扫描测试
func TestStreamingPipelinePortScanOnly(t *testing.T) {
	printSeparator("StreamingPipeline 端口扫描测试")

	task := &models.Task{
		ID:        primitive.NewObjectID(),
		Name:      "Port Scan Test",
		Type:      models.TaskTypePortScan,
		Targets:   []string{"example.com"}, // 使用 example.com 因为更快
		Status:    models.TaskStatusRunning,
		CreatedAt: time.Now(),
	}

	config := &pipeline.PipelineConfig{
		SubdomainScan: false,
		PortScan:      true,
		PortScanMode:  "quick",
		SkipCDN:       false, // example.com 是 CDN，但我们仍然测试
		Fingerprint:   true,
		WebCrawler:    true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	pipe := pipeline.NewStreamingPipeline(ctx, task, config)

	err := pipe.Start(task.Targets)
	if err != nil {
		t.Fatalf("Failed to start pipeline: %v", err)
	}

	fmt.Println("\n[收集结果]")
	var portCount, assetCount, urlCount int

	for result := range pipe.Results() {
		switch r := result.(type) {
		case pipeline.PortAlive:
			portCount++
			fmt.Printf("  [端口] %s:%s - %s\n", r.Host, r.Port, r.Service)

		case pipeline.AssetHttp:
			assetCount++
			fmt.Printf("  [资产] %s (状态: %d)\n", r.URL, r.StatusCode)

		case pipeline.UrlResult:
			urlCount++
			if urlCount <= 5 {
				fmt.Printf("  [URL] %s\n", r.Output)
			}
		}
	}

	printSeparator("结果")
	fmt.Printf("开放端口: %d 个\n", portCount)
	fmt.Printf("Web资产: %d 个\n", assetCount)
	fmt.Printf("发现URL: %d 个\n", urlCount)

	if portCount == 0 {
		t.Log("Warning: No open ports found (target may be down)")
	}

	t.Logf("Port scan completed: %d ports, %d assets, %d urls", portCount, assetCount, urlCount)
}

// TestStreamingPipelineCrawlerBatch 测试爬虫批量模式
func TestStreamingPipelineCrawlerBatch(t *testing.T) {
	printSeparator("StreamingPipeline 爬虫批量模式测试")

	task := &models.Task{
		ID:        primitive.NewObjectID(),
		Name:      "Crawler Batch Test",
		Type:      models.TaskTypeCrawler,
		Targets:   []string{"example.com"}, // 使用单个目标简化测试
		Status:    models.TaskStatusRunning,
		CreatedAt: time.Now(),
	}

	// 需要启用端口扫描来发现HTTP服务
	config := &pipeline.PipelineConfig{
		SubdomainScan: false,
		PortScan:      true,
		PortScanMode:  "quick",
		SkipCDN:       false,
		Fingerprint:   true,
		WebCrawler:    true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	pipe := pipeline.NewStreamingPipeline(ctx, task, config)

	err := pipe.Start(task.Targets)
	if err != nil {
		t.Fatalf("Failed to start pipeline: %v", err)
	}

	fmt.Println("\n[收集结果]")
	var assetCount, urlCount int
	urlSources := make(map[string]int)

	for result := range pipe.Results() {
		switch r := result.(type) {
		case pipeline.AssetHttp:
			assetCount++
			fmt.Printf("  [资产] %s\n", r.URL)

		case pipeline.UrlResult:
			urlCount++
			urlSources[r.Source]++
			if urlCount <= 10 {
				fmt.Printf("  [URL][%s] %s\n", r.Source, r.Output)
			}
		}
	}

	printSeparator("结果")
	fmt.Printf("Web资产: %d 个\n", assetCount)
	fmt.Printf("发现URL: %d 个\n", urlCount)
	fmt.Printf("URL来源: %v\n", urlSources)

	if urlCount == 0 {
		t.Error("Expected to find URLs from crawler")
	}

	t.Logf("Crawler batch test completed: %d assets, %d urls", assetCount, urlCount)
}

// TestStreamingPipelineIPTarget IP目标测试
func TestStreamingPipelineIPTarget(t *testing.T) {
	printSeparator("StreamingPipeline IP目标测试")

	task := &models.Task{
		ID:        primitive.NewObjectID(),
		Name:      "IP Target Test",
		Type:      models.TaskTypePortScan,
		Targets:   []string{"45.33.32.156"}, // scanme.nmap.org 的 IP
		Status:    models.TaskStatusRunning,
		CreatedAt: time.Now(),
	}

	config := &pipeline.PipelineConfig{
		SubdomainScan: false,
		PortScan:      true,
		PortScanMode:  "quick",
		SkipCDN:       false, // IP不需要CDN检测
		Fingerprint:   true,
		WebCrawler:    true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	pipe := pipeline.NewStreamingPipeline(ctx, task, config)

	err := pipe.Start(task.Targets)
	if err != nil {
		t.Fatalf("Failed to start pipeline: %v", err)
	}

	fmt.Println("\n[收集结果]")
	var portCount, assetCount, urlCount int

	for result := range pipe.Results() {
		switch r := result.(type) {
		case pipeline.PortAlive:
			portCount++
			fmt.Printf("  [端口] %s:%s - %s\n", r.Host, r.Port, r.Service)

		case pipeline.AssetHttp:
			assetCount++
			fmt.Printf("  [资产] %s (状态: %d)\n", r.URL, r.StatusCode)

		case pipeline.UrlResult:
			urlCount++
			if urlCount <= 5 {
				fmt.Printf("  [URL] %s\n", r.Output)
			}
		}
	}

	printSeparator("结果")
	fmt.Printf("开放端口: %d 个\n", portCount)
	fmt.Printf("Web资产: %d 个\n", assetCount)
	fmt.Printf("发现URL: %d 个\n", urlCount)

	t.Logf("IP target test completed: %d ports, %d assets, %d urls", portCount, assetCount, urlCount)
}

// TestStreamingPipelineMultipleTargets 多目标测试
func TestStreamingPipelineMultipleTargets(t *testing.T) {
	printSeparator("StreamingPipeline 多目标测试")

	task := &models.Task{
		ID:        primitive.NewObjectID(),
		Name:      "Multiple Targets Test",
		Type:      models.TaskTypePortScan,
		Targets:   []string{"scanme.nmap.org", "example.com"},
		Status:    models.TaskStatusRunning,
		CreatedAt: time.Now(),
	}

	config := &pipeline.PipelineConfig{
		SubdomainScan: false,
		PortScan:      true,
		PortScanMode:  "quick",
		SkipCDN:       true,
		Fingerprint:   true,
		WebCrawler:    true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	pipe := pipeline.NewStreamingPipeline(ctx, task, config)

	err := pipe.Start(task.Targets)
	if err != nil {
		t.Fatalf("Failed to start pipeline: %v", err)
	}

	fmt.Println("\n[收集结果]")
	hostResults := make(map[string]struct {
		ports  int
		assets int
		urls   int
	})

	for result := range pipe.Results() {
		switch r := result.(type) {
		case pipeline.PortAlive:
			data := hostResults[r.Host]
			data.ports++
			hostResults[r.Host] = data
			fmt.Printf("  [端口] %s:%s\n", r.Host, r.Port)

		case pipeline.AssetHttp:
			// 提取主机名
			host := r.Host
			if host == "" && r.URL != "" {
				// 从URL提取
				parts := strings.Split(r.URL, "/")
				if len(parts) >= 3 {
					host = strings.TrimPrefix(parts[2], "www.")
				}
			}
			data := hostResults[host]
			data.assets++
			hostResults[host] = data
			fmt.Printf("  [资产] %s\n", r.URL)

		case pipeline.UrlResult:
			// 从Input提取主机
			host := ""
			if r.Input != "" {
				parts := strings.Split(r.Input, "/")
				if len(parts) >= 3 {
					host = strings.TrimPrefix(parts[2], "www.")
				}
			}
			data := hostResults[host]
			data.urls++
			hostResults[host] = data
		}
	}

	printSeparator("结果汇总")
	for host, data := range hostResults {
		fmt.Printf("  %s: 端口=%d, 资产=%d, URL=%d\n", host, data.ports, data.assets, data.urls)
	}

	if len(hostResults) == 0 {
		t.Log("Warning: No results collected")
	}

	t.Logf("Multiple targets test completed for %d hosts", len(hostResults))
}
