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

	"github.com/c1ayooo/4zreark/scanner/fingerprint"
	"github.com/c1ayooo/4zreark/scanner/portscan"
	"github.com/c1ayooo/4zreark/scanner/subdomain"
	"github.com/c1ayooo/4zreark/scanner/webscan"
)

// ========== 测试数据结构 ==========

// DiscoveredAsset 发现的资产
type DiscoveredAsset struct {
	Host        string
	IP          string
	Port        int
	Protocol    string
	URL         string
	Title       string
	StatusCode  int
	Server      string
	IsCDN       bool
	CDNName     string
	Fingerprint []string
}

// ========== 辅助函数 ==========

func getTestProjectRoot() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Dir(filepath.Dir(filename))
}

func setupAllScanners() (*subdomain.DomainScanner, *portscan.GoGoScanner, *webscan.HttpxScanner, *webscan.KatanaScanner, *fingerprint.FingerprintScanner) {
	projectRoot := getTestProjectRoot()

	domainScanner := subdomain.NewDomainScanner(10)
	gogoScanner := portscan.NewGoGoScanner()
	httpxScanner := webscan.NewHttpxScanner(10)
	katanaScanner := webscan.NewKatanaScanner()
	fpScanner := fingerprint.NewFingerprintScanner(10)

	// 设置工具路径（GoGo会自动查找路径）
	katanaPath := filepath.Join(projectRoot, "tools", "darwin", "katana")
	if _, err := os.Stat(katanaPath); err == nil {
		katanaScanner.BinPath = katanaPath
	}

	return domainScanner, gogoScanner, httpxScanner, katanaScanner, fpScanner
}

func printSeparator(title string) {
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Printf("  %s\n", title)
	fmt.Println(strings.Repeat("=", 60))
}

func printSubSeparator(title string) {
	fmt.Println("\n" + strings.Repeat("-", 50))
	fmt.Printf("[%s]\n", title)
	fmt.Println(strings.Repeat("-", 50))
}

// ========== 完整流程测试 ==========

// TestFullScanPipeline 完整扫描流程测试
// 子域名扫描 → CDN检测 → 端口扫描 → HTTP探测 → 指纹识别 → URL爬虫
func TestFullScanPipeline(t *testing.T) {
	printSeparator("完整扫描流程测试")
	fmt.Println("流程: 子域名 → CDN检测 → 端口扫描 → HTTP探测 → 指纹识别 → URL爬虫")

	// 初始化扫描器
	domainScanner, gogoScanner, httpxScanner, katanaScanner, fpScanner := setupAllScanners()

	// 检查工具可用性
	fmt.Println("\n[工具检查]")
	fmt.Printf("  GoGo: %v\n", gogoScanner.IsAvailable())
	fmt.Printf("  Katana: %v\n", katanaScanner.IsAvailable())

	// 测试目标
	targetDomain := "example.com"
	fmt.Printf("\n[目标] %s\n", targetDomain)

	// 收集的资产
	var discoveredAssets []DiscoveredAsset
	var aliveHosts []string
	var httpURLs []string

	startTime := time.Now()

	// ========== 阶段1: 子域名扫描 ==========
	printSubSeparator("阶段1: 子域名扫描 (ksubdomain)")

	ctx1, cancel1 := context.WithTimeout(context.Background(), 2*time.Minute)
	scanResult := domainScanner.QuickSubdomainScan(ctx1, targetDomain)
	cancel1()

	// 收集子域名
	subdomains := []string{targetDomain}
	if scanResult != nil {
		for _, sub := range scanResult.Subdomains {
			subdomains = append(subdomains, sub.FullDomain)
		}
		fmt.Printf("发现子域名: %d 个\n", scanResult.Found)
	}

	for i, sub := range subdomains {
		fmt.Printf("  [%d] %s\n", i+1, sub)
	}

	// ========== 阶段2: CDN检测 & HTTP探测 ==========
	printSubSeparator("阶段2: CDN检测 & HTTP探测 (httpx)")

	ctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Minute)
	httpResults := httpxScanner.EnrichSubdomains(ctx2, subdomains)
	cancel2()

	cdnHosts := make(map[string]string)
	nonCDNHosts := []string{}

	for _, result := range httpResults {
		asset := DiscoveredAsset{
			Host:       result.Host,
			URL:        result.URL,
			Title:      result.Title,
			StatusCode: result.StatusCode,
			Server:     result.WebServer,
			IsCDN:      result.CDN,
			CDNName:    result.CDNName,
		}

		if len(result.IPs) > 0 {
			asset.IP = result.IPs[0]
		}

		discoveredAssets = append(discoveredAssets, asset)

		if result.CDN {
			cdnHosts[result.Host] = result.CDNName
		} else if result.StatusCode > 0 {
			nonCDNHosts = append(nonCDNHosts, result.Host)
			if result.URL != "" {
				httpURLs = append(httpURLs, result.URL)
			}
		}

		if result.StatusCode > 0 {
			aliveHosts = append(aliveHosts, result.Host)
		}
	}

	fmt.Printf("存活主机: %d 个\n", len(aliveHosts))
	fmt.Printf("CDN主机: %d 个\n", len(cdnHosts))
	fmt.Printf("非CDN主机: %d 个\n", len(nonCDNHosts))

	for _, asset := range discoveredAssets {
		cdnTag := ""
		if asset.IsCDN {
			cdnTag = fmt.Sprintf(" [CDN: %s]", asset.CDNName)
		}
		fmt.Printf("  %s -> %s (状态码: %d, 标题: %s)%s\n",
			asset.Host, asset.IP, asset.StatusCode, truncate(asset.Title, 30), cdnTag)
	}

	// ========== 阶段3: 端口扫描 ==========
	printSubSeparator("阶段3: 端口扫描 (GoGo)")

	if !gogoScanner.IsAvailable() {
		fmt.Println("GoGo 不可用，跳过端口扫描")
	} else if len(nonCDNHosts) == 0 {
		fmt.Println("没有非CDN主机，跳过端口扫描")
	} else {
		ctx3, cancel3 := context.WithTimeout(context.Background(), 5*time.Minute)

		// 对非CDN主机进行端口扫描
		for _, host := range nonCDNHosts {
			fmt.Printf("\n扫描目标: %s\n", host)

			portResults, err := gogoScanner.QuickScan(ctx3, host)
			if err != nil {
				fmt.Printf("  扫描失败: %v\n", err)
				continue
			}

			fmt.Printf("  发现开放端口: %d 个\n", len(portResults.Ports))
			for _, pr := range portResults.Ports {
				fmt.Printf("    %s:%d - %s %s\n", portResults.IP, pr.Port, pr.State, pr.Service)

				// 更新资产信息
				for i := range discoveredAssets {
					if discoveredAssets[i].Host == host || discoveredAssets[i].IP == portResults.IP {
						// 添加端口相关信息
						if pr.Port > 0 {
							newAsset := DiscoveredAsset{
								Host:     host,
								IP:       portResults.IP,
								Port:     pr.Port,
								Protocol: pr.State,
								Server:   pr.Service,
							}
							if len(pr.Fingerprint) > 0 {
								newAsset.Fingerprint = pr.Fingerprint
							}
							discoveredAssets = append(discoveredAssets, newAsset)
						}
						break
					}
				}
			}
		}
		cancel3()
	}

	// ========== 阶段4: Web指纹识别 ==========
	printSubSeparator("阶段4: Web指纹识别")

	if len(httpURLs) == 0 {
		fmt.Println("没有HTTP服务，跳过指纹识别")
	} else {
		ctx4, cancel4 := context.WithTimeout(context.Background(), 3*time.Minute)

		for _, url := range httpURLs {
			fmt.Printf("\n识别目标: %s\n", url)

			fpResult := fpScanner.ScanFingerprint(ctx4, url)

			if fpResult != nil {
				fmt.Printf("  状态码: %d\n", fpResult.StatusCode)
				fmt.Printf("  标题: %s\n", fpResult.Title)
				fmt.Printf("  服务器: %s\n", fpResult.Server)
				if fpResult.CMS != "" {
					fmt.Printf("  CMS: %s\n", fpResult.CMS)
				}
				if fpResult.Framework != "" {
					fmt.Printf("  框架: %s\n", fpResult.Framework)
				}
				if len(fpResult.Technologies) > 0 {
					fmt.Printf("  技术栈: %v\n", fpResult.Technologies)
				}
				if len(fpResult.JSLibraries) > 0 {
					fmt.Printf("  JS库: %v\n", fpResult.JSLibraries)
				}

				// 更新资产指纹信息
				for i := range discoveredAssets {
					if discoveredAssets[i].URL == url {
						discoveredAssets[i].Fingerprint = fpResult.Technologies
						break
					}
				}
			}
		}
		cancel4()
	}

	// ========== 阶段5: URL爬虫 ==========
	printSubSeparator("阶段5: URL爬虫 (Katana)")

	if !katanaScanner.IsAvailable() {
		fmt.Println("Katana 不可用，跳过URL爬虫")
	} else if len(httpURLs) == 0 {
		fmt.Println("没有HTTP URL，跳过URL爬虫")
	} else {
		ctx5, cancel5 := context.WithTimeout(context.Background(), 5*time.Minute)

		katanaScanner.Depth = 3
		katanaScanner.Concurrency = 10
		katanaScanner.RateLimit = 100

		fmt.Printf("待爬取URL: %d 个\n", len(httpURLs))
		fmt.Printf("爬取参数: depth=%d, concurrency=%d, rate_limit=%d\n",
			katanaScanner.Depth, katanaScanner.Concurrency, katanaScanner.RateLimit)

		crawlResult, err := katanaScanner.CrawlList(ctx5, httpURLs)
		cancel5()

		if err != nil {
			fmt.Printf("爬取失败: %v\n", err)
		} else {
			fmt.Printf("\n发现URL: %d 个\n", crawlResult.Total)

			// 统计
			statusCount := make(map[int]int)
			for _, u := range crawlResult.URLs {
				statusCount[u.StatusCode]++
			}

			fmt.Println("状态码分布:")
			for status, count := range statusCount {
				fmt.Printf("  %d: %d URLs\n", status, count)
			}

			// 显示部分URL
			fmt.Println("\nURL示例:")
			for i, u := range crawlResult.URLs {
				if i >= 15 {
					fmt.Printf("  ... 还有 %d 个URL\n", len(crawlResult.URLs)-15)
					break
				}
				fmt.Printf("  [%d] %s %s\n", i+1, u.Method, u.URL)
			}
		}
	}

	// ========== 扫描完成 ==========
	totalDuration := time.Since(startTime)

	printSeparator("扫描完成")
	fmt.Printf("总耗时: %s\n", totalDuration)
	fmt.Printf("发现资产: %d 个\n", len(discoveredAssets))
	fmt.Printf("存活主机: %d 个\n", len(aliveHosts))
	fmt.Printf("HTTP服务: %d 个\n", len(httpURLs))

	fmt.Println("\n资产汇总:")
	for i, asset := range discoveredAssets {
		if i >= 20 {
			fmt.Printf("  ... 还有 %d 个资产\n", len(discoveredAssets)-20)
			break
		}
		info := asset.Host
		if asset.Port > 0 {
			info = fmt.Sprintf("%s:%d", asset.Host, asset.Port)
		}
		if asset.URL != "" {
			info = asset.URL
		}
		cdnTag := ""
		if asset.IsCDN {
			cdnTag = " [CDN]"
		}
		fmt.Printf("  [%d] %s%s\n", i+1, info, cdnTag)
	}
}

// TestFullScanWithHackerTarget 使用实际目标测试完整流程
func TestFullScanWithHackerTarget(t *testing.T) {
	printSeparator("实际目标完整扫描测试")

	// 初始化扫描器
	_, gogoScanner, httpxScanner, katanaScanner, fpScanner := setupAllScanners()

	// 使用 scanme.nmap.org 作为测试目标（专门用于测试的网站）
	targets := []string{"scanme.nmap.org"}
	fmt.Printf("\n[目标] %v\n", targets)

	startTime := time.Now()

	// ========== 阶段1: HTTP探测 & CDN检测 ==========
	printSubSeparator("阶段1: HTTP探测 & CDN检测")

	ctx1, cancel1 := context.WithTimeout(context.Background(), 2*time.Minute)
	httpResults := httpxScanner.EnrichSubdomains(ctx1, targets)
	cancel1()

	var httpURLs []string
	var nonCDNTargets []string

	for _, result := range httpResults {
		cdnTag := ""
		if result.CDN {
			cdnTag = fmt.Sprintf(" [CDN: %s]", result.CDNName)
		} else {
			nonCDNTargets = append(nonCDNTargets, result.Host)
		}

		if result.URL != "" {
			httpURLs = append(httpURLs, result.URL)
		}

		ip := ""
		if len(result.IPs) > 0 {
			ip = result.IPs[0]
		}

		fmt.Printf("  %s -> %s (状态码: %d)%s\n", result.Host, ip, result.StatusCode, cdnTag)
	}

	// ========== 阶段2: 端口扫描 ==========
	printSubSeparator("阶段2: 端口扫描 (GoGo Top100)")

	if !gogoScanner.IsAvailable() {
		fmt.Println("GoGo 不可用，跳过")
	} else if len(nonCDNTargets) == 0 {
		fmt.Println("没有非CDN目标，跳过")
	} else {
		ctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Minute)

		for _, target := range nonCDNTargets {
			fmt.Printf("\n扫描: %s\n", target)

			results, err := gogoScanner.QuickScan(ctx2, target)
			if err != nil {
				fmt.Printf("  失败: %v\n", err)
				continue
			}

			fmt.Printf("  开放端口: %d 个\n", len(results.Ports))
			for _, r := range results.Ports {
				fp := ""
				if len(r.Fingerprint) > 0 {
					fp = fmt.Sprintf(" [%s]", strings.Join(r.Fingerprint, ", "))
				}
				fmt.Printf("    %s:%d - %s%s\n", results.IP, r.Port, r.Service, fp)
			}
		}
		cancel2()
	}

	// ========== 阶段3: Web指纹识别 ==========
	printSubSeparator("阶段3: Web指纹识别")

	if len(httpURLs) == 0 {
		fmt.Println("没有HTTP服务，跳过")
	} else {
		ctx3, cancel3 := context.WithTimeout(context.Background(), 2*time.Minute)

		for _, url := range httpURLs {
			fmt.Printf("\n识别: %s\n", url)

			result := fpScanner.ScanFingerprint(ctx3, url)

			if result != nil {
				fmt.Printf("  标题: %s\n", result.Title)
				fmt.Printf("  服务器: %s\n", result.Server)
				if len(result.Technologies) > 0 {
					fmt.Printf("  技术: %v\n", result.Technologies)
				}
			}
		}
		cancel3()
	}

	// ========== 阶段4: URL爬虫 ==========
	printSubSeparator("阶段4: URL爬虫")

	if !katanaScanner.IsAvailable() {
		fmt.Println("Katana 不可用，跳过")
	} else if len(httpURLs) == 0 {
		fmt.Println("没有HTTP URL，跳过")
	} else {
		ctx4, cancel4 := context.WithTimeout(context.Background(), 3*time.Minute)

		katanaScanner.Depth = 2
		katanaScanner.Concurrency = 5

		result, err := katanaScanner.CrawlList(ctx4, httpURLs)
		cancel4()

		if err != nil {
			fmt.Printf("失败: %v\n", err)
		} else {
			fmt.Printf("发现URL: %d 个\n", result.Total)
			for i, u := range result.URLs {
				if i >= 10 {
					fmt.Printf("  ... 还有 %d 个\n", len(result.URLs)-10)
					break
				}
				fmt.Printf("  [%d] %s\n", i+1, u.URL)
			}
		}
	}

	// ========== 完成 ==========
	printSeparator("扫描完成")
	fmt.Printf("总耗时: %s\n", time.Since(startTime))
}

// truncate 截断字符串
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
