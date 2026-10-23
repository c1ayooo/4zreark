package test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/scanner/subdomain"
	"github.com/c1ayooo/4zreark/scanner/webscan"
)

// getProjectRoot 获取项目根目录
func getProjectRootPath() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Dir(filepath.Dir(filename))
}

// setupScanners 设置扫描器
func setupScanners() (*webscan.HttpxScanner, *webscan.KatanaScanner) {
	projectRoot := getProjectRootPath()

	httpxScanner := webscan.NewHttpxScanner(10)
	katanaScanner := webscan.NewKatanaScanner()

	// 设置 katana 路径
	katanaPath := filepath.Join(projectRoot, "tools", "darwin", "katana")
	if _, err := os.Stat(katanaPath); err == nil {
		katanaScanner.BinPath = katanaPath
	}

	return httpxScanner, katanaScanner
}

// TestSubdomainToKatanaPipeline 测试完整流程：子域名扫描 → URL收集 → Katana爬虫
func TestSubdomainToKatanaPipeline(t *testing.T) {
	requireLiveNetwork(t)
	fmt.Println("=" + strings.Repeat("=", 59))
	fmt.Println("  完整流程测试: 子域名扫描 → URL收集 → Katana批量爬虫")
	fmt.Println("=" + strings.Repeat("=", 59))

	httpxScanner, katanaScanner := setupScanners()

	if !katanaScanner.IsAvailable() {
		t.Skipf("Katana not available, skipping test")
	}

	// 测试目标域名
	targetDomain := "example.com"
	fmt.Printf("\n[目标域名] %s\n", targetDomain)

	// ========== 阶段1: 子域名扫描 ==========
	fmt.Println("\n" + strings.Repeat("-", 50))
	fmt.Println("[阶段1] 子域名扫描 (原生 DNS)")
	fmt.Println(strings.Repeat("-", 50))

	domainScanner := subdomain.NewDomainScanner(10)

	ctx1, cancel1 := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel1()

	// 快速子域名扫描
	scanResult := domainScanner.QuickSubdomainScan(ctx1, targetDomain)

	// 收集发现的子域名
	discoveredSubdomains := []string{targetDomain} // 先加入主域名
	if scanResult != nil {
		for _, sub := range scanResult.Subdomains {
			discoveredSubdomains = append(discoveredSubdomains, sub.FullDomain)
		}
	}

	fmt.Printf("发现子域名数量: %d\n", len(discoveredSubdomains))
	for i, sub := range discoveredSubdomains {
		if i >= 10 {
			fmt.Printf("  ... 还有 %d 个子域名\n", len(discoveredSubdomains)-10)
			break
		}
		fmt.Printf("  [%d] %s\n", i+1, sub)
	}

	// ========== 阶段2: HTTP探测 (httpx) ==========
	fmt.Println("\n" + strings.Repeat("-", 50))
	fmt.Println("[阶段2] HTTP探测 (使用 httpx)")
	fmt.Println(strings.Repeat("-", 50))

	ctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel2()

	// 使用 httpx 探测存活的 HTTP 服务
	httpResults := httpxScanner.EnrichSubdomains(ctx2, discoveredSubdomains)

	// 收集存活的 URL
	aliveURLs := make([]string, 0)
	for _, result := range httpResults {
		if result.URL != "" && result.StatusCode > 0 {
			aliveURLs = append(aliveURLs, result.URL)
		}
	}

	fmt.Printf("存活HTTP服务数量: %d\n", len(aliveURLs))
	for i, url := range aliveURLs {
		if i >= 10 {
			fmt.Printf("  ... 还有 %d 个URL\n", len(aliveURLs)-10)
			break
		}
		fmt.Printf("  [%d] %s\n", i+1, url)
	}

	if len(aliveURLs) == 0 {
		fmt.Println("没有发现存活的HTTP服务，跳过爬虫阶段")
		return
	}

	// ========== 阶段3: Katana批量爬虫 ==========
	fmt.Println("\n" + strings.Repeat("-", 50))
	fmt.Println("[阶段3] URL爬虫 (使用 Katana 批量模式)")
	fmt.Println(strings.Repeat("-", 50))

	ctx3, cancel3 := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel3()

	// 设置爬取参数
	katanaScanner.Depth = 3
	katanaScanner.Concurrency = 10
	katanaScanner.RateLimit = 100

	fmt.Printf("爬取参数: depth=%d, concurrency=%d, rate_limit=%d\n",
		katanaScanner.Depth, katanaScanner.Concurrency, katanaScanner.RateLimit)
	fmt.Printf("待爬取URL数量: %d\n", len(aliveURLs))

	startTime := time.Now()
	crawlResult, err := katanaScanner.CrawlList(ctx3, aliveURLs)
	duration := time.Since(startTime)

	if err != nil {
		t.Fatalf("Katana爬取失败: %v", err)
	}

	fmt.Printf("\n爬取完成!\n")
	fmt.Printf("耗时: %s\n", duration)
	fmt.Printf("发现URL总数: %d\n", crawlResult.Total)

	// 统计信息
	statusCount := make(map[int]int)
	methodCount := make(map[string]int)
	for _, url := range crawlResult.URLs {
		statusCount[url.StatusCode]++
		if url.Method != "" {
			methodCount[url.Method]++
		}
	}

	fmt.Println("\n状态码分布:")
	for status, count := range statusCount {
		fmt.Printf("  %d: %d URLs\n", status, count)
	}

	fmt.Println("\n请求方法分布:")
	for method, count := range methodCount {
		fmt.Printf("  %s: %d URLs\n", method, count)
	}

	// 打印部分URL示例
	fmt.Println("\n发现的URL示例:")
	for i, url := range crawlResult.URLs {
		if i >= 20 {
			fmt.Printf("  ... 还有 %d 个URL\n", len(crawlResult.URLs)-20)
			break
		}
		fmt.Printf("  [%d] %s %s\n", i+1, url.Method, url.URL)
	}

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("  测试完成!")
	fmt.Println(strings.Repeat("=", 60))
}

// TestSubdomainToKatanaWithRealDomain 使用真实域名测试
func TestSubdomainToKatanaWithRealDomain(t *testing.T) {
	requireLiveNetwork(t)
	fmt.Println("=" + strings.Repeat("=", 59))
	fmt.Println("  真实域名测试: httpbin.org")
	fmt.Println("=" + strings.Repeat("=", 59))

	httpxScanner, katanaScanner := setupScanners()

	if !katanaScanner.IsAvailable() {
		t.Skipf("Katana not available, skipping test")
	}

	// 使用 httpbin.org 作为测试目标（有丰富的页面结构）
	targetDomain := "httpbin.org"
	fmt.Printf("\n[目标域名] %s\n", targetDomain)

	// ========== 阶段1: 直接HTTP探测 ==========
	fmt.Println("\n" + strings.Repeat("-", 50))
	fmt.Println("[阶段1] HTTP探测")
	fmt.Println(strings.Repeat("-", 50))

	ctx1, cancel1 := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel1()

	// 直接探测主域名
	httpResults := httpxScanner.EnrichSubdomains(ctx1, []string{targetDomain})

	aliveURLs := make([]string, 0)
	for _, result := range httpResults {
		if result.URL != "" {
			aliveURLs = append(aliveURLs, result.URL)
			fmt.Printf("发现: %s (状态码: %d, 标题: %s)\n",
				result.URL, result.StatusCode, result.Title)
		}
	}

	if len(aliveURLs) == 0 {
		// 如果 httpx 探测失败，直接使用 https://
		aliveURLs = append(aliveURLs, "https://"+targetDomain)
		fmt.Printf("回退使用: https://%s\n", targetDomain)
	}

	// ========== 阶段2: Katana批量爬虫 ==========
	fmt.Println("\n" + strings.Repeat("-", 50))
	fmt.Println("[阶段2] URL爬虫 (Katana)")
	fmt.Println(strings.Repeat("-", 50))

	ctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel2()

	katanaScanner.Depth = 3
	katanaScanner.Concurrency = 10
	katanaScanner.RateLimit = 50

	fmt.Printf("爬取参数: depth=%d, concurrency=%d, rate_limit=%d\n",
		katanaScanner.Depth, katanaScanner.Concurrency, katanaScanner.RateLimit)

	startTime := time.Now()
	crawlResult, err := katanaScanner.CrawlList(ctx2, aliveURLs)
	duration := time.Since(startTime)

	if err != nil {
		t.Fatalf("Katana爬取失败: %v", err)
	}

	fmt.Printf("\n爬取完成!\n")
	fmt.Printf("耗时: %s\n", duration)
	fmt.Printf("发现URL总数: %d\n", crawlResult.Total)

	// 打印所有URL
	fmt.Println("\n发现的URL:")
	for i, url := range crawlResult.URLs {
		fmt.Printf("  [%d] %s %s (status: %d)\n", i+1, url.Method, url.URL, url.StatusCode)
	}

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("  测试完成!")
	fmt.Println(strings.Repeat("=", 60))
}
