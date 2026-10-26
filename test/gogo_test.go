package test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/scanner/portscan"
)

func TestGoGoScanner(t *testing.T) {
	requireLiveNetwork(t)
	fmt.Println("=== GoGo 端口扫描测试 ===")

	// 创建扫描器
	scanner := portscan.NewGoGoScanner()

	// 检查是否可用
	available := scanner.IsAvailable()
	fmt.Printf("GoGo 可用: %v\n", available)

	if !available {
		t.Skip("GoGo SDK 不可用，跳过测试")
	}

	// 测试扫描 scanme.nmap.org (这是一个公开的测试目标)
	target := "scanme.nmap.org"
	fmt.Printf("\n测试目标: %s\n", target)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	fmt.Println("开始快速扫描...")
	result, err := scanner.QuickScan(ctx, target)
	if err != nil {
		t.Fatalf("扫描错误: %v", err)
	}

	if result == nil {
		t.Fatal("结果为空")
	}

	fmt.Printf("\n扫描结果:\n")
	fmt.Printf("  目标: %s\n", result.Target)
	fmt.Printf("  开放端口数: %d\n", len(result.Ports))

	for _, port := range result.Ports {
		fmt.Printf("  - 端口 %d (%s) - %s\n", port.Port, port.Service, port.State)
	}

	if len(result.Ports) == 0 {
		t.Log("警告: 未发现开放端口，可能是网络问题或目标不可达")
	}

	fmt.Println("\n=== 测试完成 ===")
}

func TestGoGoScannerScanOne(t *testing.T) {
	requireLiveNetwork(t)
	fmt.Println("=== GoGo ScanOne 测试 ===")

	scanner := portscan.NewGoGoScanner()

	if !scanner.IsAvailable() {
		t.Skip("GoGo SDK 不可用，跳过测试")
	}

	// 测试单个端口扫描
	target := "scanme.nmap.org"
	port := "80"

	fmt.Printf("扫描 %s:%s\n", target, port)
	result := scanner.ScanOne(target, port)

	if result != nil {
		fmt.Printf("结果: Port=%d, Service=%s, State=%s\n",
			result.Port, result.Service, result.State)
	} else {
		fmt.Println("端口关闭或无响应")
	}

	fmt.Println("=== ScanOne 测试完成 ===")
}

func TestGoGoScannerTop1000(t *testing.T) {
	requireLiveNetwork(t)
	fmt.Println("=== GoGo Top1000 端口扫描测试 ===")

	scanner := portscan.NewGoGoScanner()

	if !scanner.IsAvailable() {
		t.Skip("GoGo 不可用，跳过测试")
	}

	target := "scanme.nmap.org"
	fmt.Printf("测试目标: %s\n", target)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	fmt.Println("开始 Top1000 扫描...")
	result, err := scanner.Top1000Scan(ctx, target)
	if err != nil {
		t.Fatalf("Top1000 扫描错误: %v", err)
	}

	if result == nil {
		t.Fatal("结果为空")
	}

	fmt.Printf("发现 %d 个开放端口\n", len(result.Ports))
	for _, port := range result.Ports {
		fmt.Printf("  - 端口 %d (%s) - %s\n", port.Port, port.Service, port.State)
	}

	fmt.Println("=== Top1000 测试完成 ===")
}

func TestGoGoScannerCustomPorts(t *testing.T) {
	requireLiveNetwork(t)
	fmt.Println("=== GoGo 自定义端口扫描测试 ===")

	scanner := portscan.NewGoGoScanner()

	if !scanner.IsAvailable() {
		t.Skip("GoGo 不可用，跳过测试")
	}

	target := "scanme.nmap.org"
	customPorts := "22,80,443,8080,8443"
	fmt.Printf("测试目标: %s\n", target)
	fmt.Printf("自定义端口: %s\n", customPorts)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	fmt.Println("开始自定义端口扫描...")
	result, err := scanner.ScanPorts(ctx, target, customPorts)
	if err != nil {
		t.Fatalf("自定义端口扫描错误: %v", err)
	}

	if result == nil {
		t.Fatal("结果为空")
	}

	fmt.Printf("发现 %d 个开放端口\n", len(result.Ports))
	for _, port := range result.Ports {
		fmt.Printf("  - 端口 %d (%s) - %s", port.Port, port.Service, port.State)
		if port.Banner != "" {
			fmt.Printf(" [%s]", port.Banner)
		}
		if len(port.Fingerprint) > 0 {
			fmt.Printf(" 指纹: %v", port.Fingerprint)
		}
		fmt.Println()
	}

	fmt.Println("=== 自定义端口扫描测试完成 ===")
}

func TestGoGoScannerPortRange(t *testing.T) {
	requireLiveNetwork(t)
	fmt.Println("=== GoGo 端口范围扫描测试 ===")

	scanner := portscan.NewGoGoScanner()

	if !scanner.IsAvailable() {
		t.Skip("GoGo 不可用，跳过测试")
	}

	target := "scanme.nmap.org"
	portRange := "20-100"
	fmt.Printf("测试目标: %s\n", target)
	fmt.Printf("端口范围: %s\n", portRange)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	fmt.Println("开始端口范围扫描...")
	result, err := scanner.ScanRange(ctx, target, portRange)
	if err != nil {
		t.Fatalf("端口范围扫描错误: %v", err)
	}

	if result == nil {
		t.Fatal("结果为空")
	}

	fmt.Printf("发现 %d 个开放端口\n", len(result.Ports))
	for _, port := range result.Ports {
		fmt.Printf("  - 端口 %d (%s) - %s\n", port.Port, port.Service, port.State)
	}

	fmt.Printf("扫描耗时: %v\n", result.EndTime.Sub(result.StartTime))
	fmt.Println("=== 端口范围扫描测试完成 ===")
}

func TestGoGoScannerFullScan(t *testing.T) {
	requireLiveNetwork(t)
	fmt.Println("=== GoGo 全端口扫描测试 (仅扫描小范围模拟) ===")

	scanner := portscan.NewGoGoScanner()

	if !scanner.IsAvailable() {
		t.Skip("GoGo 不可用，跳过测试")
	}

	// 为了测试速度，使用 localhost 或小范围
	target := "127.0.0.1"
	portRange := "1-1000" // 模拟全端口，实际只扫前1000
	fmt.Printf("测试目标: %s\n", target)
	fmt.Printf("端口范围: %s (模拟全端口扫描)\n", portRange)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	fmt.Println("开始扫描...")
	result, err := scanner.ScanPorts(ctx, target, portRange)
	if err != nil {
		t.Fatalf("扫描错误: %v", err)
	}

	if result == nil {
		t.Fatal("结果为空")
	}

	fmt.Printf("发现 %d 个开放端口\n", len(result.Ports))
	for _, port := range result.Ports {
		fmt.Printf("  - 端口 %d (%s) - %s\n", port.Port, port.Service, port.State)
	}

	fmt.Printf("扫描耗时: %v\n", result.EndTime.Sub(result.StartTime))
	fmt.Println("=== 全端口扫描测试完成 ===")
}

func TestGoGoScannerRealFullScan(t *testing.T) {
	requireLiveNetwork(t)
	fmt.Println("=== GoGo 真实全端口扫描测试 (1-65535) ===")

	scanner := portscan.NewGoGoScanner()

	if !scanner.IsAvailable() {
		t.Skip("GoGo 不可用，跳过测试")
	}

	target := "scanme.nmap.org"
	fmt.Printf("测试目标: %s\n", target)
	fmt.Println("端口范围: 1-65535 (全端口)")
	fmt.Println("预计耗时较长，请耐心等待...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	startTime := time.Now()
	fmt.Printf("开始时间: %s\n", startTime.Format("15:04:05"))

	result, err := scanner.FullScan(ctx, target)
	if err != nil {
		t.Fatalf("全端口扫描错误: %v", err)
	}

	if result == nil {
		t.Fatal("结果为空")
	}

	fmt.Printf("\n========== 扫描结果 ==========\n")
	fmt.Printf("发现 %d 个开放端口\n", len(result.Ports))
	for _, port := range result.Ports {
		fmt.Printf("  - 端口 %d (%s) - %s", port.Port, port.Service, port.State)
		if port.Banner != "" {
			fmt.Printf(" [%s]", port.Banner)
		}
		if port.Version != "" {
			fmt.Printf(" 版本: %s", port.Version)
		}
		if len(port.Fingerprint) > 0 {
			fmt.Printf(" 指纹: %v", port.Fingerprint)
		}
		fmt.Println()
	}

	duration := result.EndTime.Sub(result.StartTime)
	fmt.Printf("\n扫描耗时: %v\n", duration)
	fmt.Printf("扫描速率: %.0f 端口/秒\n", 65535.0/duration.Seconds())
	fmt.Println("=== 真实全端口扫描测试完成 ===")
}
