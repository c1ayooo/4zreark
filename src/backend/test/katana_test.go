package test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/scanner/webscan"
)

// getProjectRoot 获取项目根目录
func getProjectRoot() string {
	// 获取当前文件的目录
	_, filename, _, _ := runtime.Caller(0)
	// test 目录的父目录就是 backend 根目录
	return filepath.Dir(filepath.Dir(filename))
}

// setupKatanaScanner 创建并设置 Katana 扫描器路径
func setupKatanaScanner() *webscan.KatanaScanner {
	scanner := webscan.NewKatanaScanner()

	// 如果默认路径不可用，尝试项目相对路径
	if !scanner.IsAvailable() {
		projectRoot := getProjectRoot()
		katanaPath := filepath.Join(projectRoot, "tools", "darwin", "katana")
		if _, err := os.Stat(katanaPath); err == nil {
			scanner.BinPath = katanaPath
		}
	}

	return scanner
}

// TestKatanaSingleCrawl 测试单个URL爬取
func TestKatanaSingleCrawl(t *testing.T) {
	requireLiveNetwork(t)
	scanner := setupKatanaScanner()

	if !scanner.IsAvailable() {
		t.Skipf("Katana not available at %s, skipping test", scanner.BinPath)
	}

	fmt.Println("=== Katana Single URL Crawl Test ===")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	target := "https://example.com"
	fmt.Printf("Target: %s\n", target)

	result, err := scanner.QuickCrawl(ctx, target)
	if err != nil {
		t.Fatalf("Crawl failed: %v", err)
	}

	fmt.Printf("Duration: %s\n", result.Duration)
	fmt.Printf("Total URLs found: %d\n", result.Total)

	// 打印前10个URL
	for i, url := range result.URLs {
		if i >= 10 {
			fmt.Printf("  ... and %d more URLs\n", len(result.URLs)-10)
			break
		}
		fmt.Printf("  [%d] %s %s (status: %d)\n", i+1, url.Method, url.URL, url.StatusCode)
	}
}

// TestKatanaListCrawl 测试批量URL爬取
func TestKatanaListCrawl(t *testing.T) {
	requireLiveNetwork(t)
	scanner := setupKatanaScanner()

	if !scanner.IsAvailable() {
		t.Skipf("Katana not available at %s, skipping test", scanner.BinPath)
	}

	fmt.Println("=== Katana List Crawl Test ===")

	// 测试URL列表
	urls := []string{
		"https://example.com",
		"https://httpbin.org",
	}

	fmt.Printf("URLs to crawl: %d\n", len(urls))
	for i, url := range urls {
		fmt.Printf("  [%d] %s\n", i+1, url)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// 设置爬取参数
	scanner.Depth = 2
	scanner.Concurrency = 5
	scanner.RateLimit = 100

	result, err := scanner.CrawlList(ctx, urls)
	if err != nil {
		t.Fatalf("CrawlList failed: %v", err)
	}

	fmt.Printf("\nDuration: %s\n", result.Duration)
	fmt.Printf("Total URLs found: %d\n", result.Total)

	// 打印前20个URL
	for i, url := range result.URLs {
		if i >= 20 {
			fmt.Printf("  ... and %d more URLs\n", len(result.URLs)-20)
			break
		}
		fmt.Printf("  [%d] %s %s (status: %d)\n", i+1, url.Method, url.URL, url.StatusCode)
	}
}

// TestKatanaDeepCrawl 测试深度爬取
func TestKatanaDeepCrawl(t *testing.T) {
	requireLiveNetwork(t)
	scanner := setupKatanaScanner()

	if !scanner.IsAvailable() {
		t.Skipf("Katana not available at %s, skipping test", scanner.BinPath)
	}

	fmt.Println("=== Katana Deep Crawl Test ===")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	target := "https://httpbin.org"
	fmt.Printf("Target: %s\n", target)
	fmt.Printf("Depth: 5\n")

	result, err := scanner.DeepCrawl(ctx, target)
	if err != nil {
		t.Fatalf("DeepCrawl failed: %v", err)
	}

	fmt.Printf("Duration: %s\n", result.Duration)
	fmt.Printf("Total URLs found: %d\n", result.Total)

	// 按状态码统计
	statusCount := make(map[int]int)
	for _, url := range result.URLs {
		statusCount[url.StatusCode]++
	}

	fmt.Println("\nStatus code distribution:")
	for status, count := range statusCount {
		fmt.Printf("  %d: %d URLs\n", status, count)
	}

	// 打印前15个URL
	fmt.Println("\nSample URLs:")
	for i, url := range result.URLs {
		if i >= 15 {
			break
		}
		fmt.Printf("  [%d] %s %s\n", i+1, url.Method, url.URL)
	}
}

// TestKatanaEmptyList 测试空列表
func TestKatanaEmptyList(t *testing.T) {
	scanner := setupKatanaScanner()

	if !scanner.IsAvailable() {
		t.Skipf("Katana not available at %s, skipping test", scanner.BinPath)
	}

	fmt.Println("=== Katana Empty List Test ===")

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	result, err := scanner.CrawlList(ctx, []string{})
	if err != nil {
		t.Fatalf("CrawlList failed: %v", err)
	}

	fmt.Printf("Total URLs found: %d (expected: 0)\n", result.Total)

	if result.Total != 0 {
		t.Errorf("Expected 0 URLs for empty list, got %d", result.Total)
	}
}
