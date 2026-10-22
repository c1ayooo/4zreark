package portscan

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"github.com/c1ayooo/4zreark/scanner/core"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// GoGoScanner 使用 GoGo 进行高速端口扫描
type GoGoScanner struct {
	toolPath string
	mu       sync.Mutex
	Threads  int // 并发数
	Timeout  int // 超时时间(秒)
}

// GoGoConfig GoGo 扫描配置
type GoGoConfig struct {
	Timeout   int // 超时时间(秒)
	Threads   int // 并发数/线程数
	RateLimit int // 速率限制（暂不使用）
}

// GoGoResult GoGo JSON 输出结构
type GoGoResult struct {
	IP         string                 `json:"ip"`
	Port       string                 `json:"port"`
	Protocol   string                 `json:"protocol"`
	Status     string                 `json:"status"`
	Title      string                 `json:"title"`
	Midware    string                 `json:"midware"`
	Frameworks map[string]interface{} `json:"frameworks"`
}

var (
	globalGoGoScanner *GoGoScanner
	gogoOnce          sync.Once
)

// GetGoGoScanner 获取全局 GoGo 扫描器实例（单例模式）
func GetGoGoScanner() *GoGoScanner {
	gogoOnce.Do(func() {
		globalGoGoScanner = &GoGoScanner{
			Threads: 1000, // 默认 1000 并发
			Timeout: 10,   // 默认 10 秒超时
		}
		globalGoGoScanner.findToolPath()
	})
	return globalGoGoScanner
}

// NewGoGoScanner 创建 GoGo 扫描器
func NewGoGoScanner() *GoGoScanner {
	return GetGoGoScanner()
}

// NewGoGoScannerWithConfig 使用配置创建 GoGo 扫描器
func NewGoGoScannerWithConfig(config *GoGoConfig) *GoGoScanner {
	scanner := GetGoGoScanner()
	if config != nil {
		scanner.SetConfig(config)
	}
	return scanner
}

// SetConfig 更新扫描器配置
func (g *GoGoScanner) SetConfig(config *GoGoConfig) {
	if config == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	if config.Timeout > 0 {
		g.Timeout = config.Timeout
	}
	if config.Threads > 0 {
		g.Threads = config.Threads
	}
}

// SetThreads 更新并发线程数。gogo 是进程级单例，多个任务会并发改/读线程数，
// 必须走锁；直接写字段是 data race。
func (g *GoGoScanner) SetThreads(n int) {
	if n <= 0 {
		return
	}
	g.mu.Lock()
	g.Threads = n
	g.mu.Unlock()
}

func (g *GoGoScanner) snapshot() (threads, timeout int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.Threads, g.Timeout
}

// findToolPath 查找 GoGo 工具路径
func (g *GoGoScanner) findToolPath() {
	// 根据操作系统选择工具目录
	var osDir string
	switch runtime.GOOS {
	case "darwin":
		osDir = "darwin"
	case "linux":
		osDir = "linux"
	case "windows":
		osDir = "win"
	default:
		osDir = "linux"
	}

	// 获取可执行文件目录
	execPath, err := os.Executable()
	if err != nil {
		log.Printf("[GoGoScanner] Failed to get executable path: %v", err)
		return
	}
	execDir := filepath.Dir(execPath)

	// 可能的工具路径
	possiblePaths := []string{
		filepath.Join(execDir, "tools", osDir, "gogo"),
		filepath.Join("tools", osDir, "gogo"),
		filepath.Join("..", "tools", osDir, "gogo"),
		"gogo", // 系统 PATH
	}

	for _, path := range possiblePaths {
		if _, err := os.Stat(path); err == nil {
			g.toolPath = path
			log.Printf("[GoGoScanner] Found gogo at: %s", path)
			return
		}
		// 检查带扩展名的版本（Windows）
		if runtime.GOOS == "windows" {
			pathWithExt := path + ".exe"
			if _, err := os.Stat(pathWithExt); err == nil {
				g.toolPath = pathWithExt
				log.Printf("[GoGoScanner] Found gogo at: %s", pathWithExt)
				return
			}
		}
	}

	// 尝试从 PATH 查找
	if path, err := exec.LookPath("gogo"); err == nil {
		g.toolPath = path
		log.Printf("[GoGoScanner] Found gogo in PATH: %s", path)
		return
	}

	log.Printf("[GoGoScanner] gogo not found in any expected location")
}

// IsAvailable 检查是否可用
func (g *GoGoScanner) IsAvailable() bool {
	if g.toolPath == "" {
		g.findToolPath()
	}
	return g.toolPath != ""
}

// ScanPorts 扫描端口
// target: 目标 IP 或域名
// ports: 端口配置，如 "80,443,8080" 或 "1-1000" 或 "top1000"
func (g *GoGoScanner) ScanPorts(ctx context.Context, target string, ports string) (*core.ScanResult, error) {
	if !g.IsAvailable() {
		return nil, fmt.Errorf("gogo tool not found")
	}

	result := &core.ScanResult{
		Target:    target,
		StartTime: time.Now(),
		Ports:     make([]core.PortResult, 0),
	}

	log.Printf("[GoGoScanner] Scanning %s with ports: %s", target, ports)

	// 构建命令参数
	threads, timeout := g.snapshot()
	args := []string{
		"-i", target,
		"-p", ports,
		"-o", "jl", // jsonlines 输出
		"-t", strconv.Itoa(threads),
		"-d", strconv.Itoa(timeout), // 超时时间
	}

	// 创建命令
	cmd := exec.CommandContext(ctx, g.toolPath, args...)

	// 获取输出管道
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %v", err)
	}

	// 启动命令
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start gogo: %v", err)
	}

	// 使用 map 去重
	portMap := make(map[string]bool)

	// 逐行读取输出
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// 跳过日志行（以 [*] 或 [-] 开头）
		if strings.HasPrefix(line, "[") || line == "" {
			continue
		}

		// 尝试解析 JSON
		var gogoResult GoGoResult
		if err := json.Unmarshal([]byte(line), &gogoResult); err != nil {
			continue
		}

		portResult := g.convertResult(&gogoResult)
		if portResult != nil {
			key := fmt.Sprintf("%s:%d", gogoResult.IP, portResult.Port)
			if !portMap[key] {
				portMap[key] = true
				result.Ports = append(result.Ports, *portResult)
			}
		}
	}

	// 等待命令完成
	if err := cmd.Wait(); err != nil {
		// 如果是上下文取消，不视为错误
		if ctx.Err() != nil {
			log.Printf("[GoGoScanner] Scan cancelled")
			result.EndTime = time.Now()
			return result, nil
		}
		// 其他错误记录但不返回，可能已经有结果
		log.Printf("[GoGoScanner] Command finished with error: %v", err)
	}

	result.EndTime = time.Now()
	log.Printf("[GoGoScanner] Found %d open ports on %s", len(result.Ports), target)

	return result, nil
}

// convertResult 将 GoGo 结果转换为通用格式
func (g *GoGoScanner) convertResult(gogoResult *GoGoResult) *core.PortResult {
	if gogoResult == nil {
		return nil
	}

	// 跳过关闭的端口
	if gogoResult.Status == "" || gogoResult.Status == "closed" {
		return nil
	}

	port, err := strconv.Atoi(gogoResult.Port)
	if err != nil || port <= 0 {
		return nil
	}

	// 提取服务信息
	service := gogoResult.Protocol
	if service == "" || service == "tcp" {
		service = guessService(port)
	}

	// 提取版本信息
	version := gogoResult.Midware

	// 提取指纹信息
	var fingerprints []string
	for name := range gogoResult.Frameworks {
		fingerprints = append(fingerprints, name)
	}

	// 提取 Banner（使用 Title）
	banner := gogoResult.Title

	return &core.PortResult{
		Port:        port,
		State:       "open",
		Service:     service,
		Version:     version,
		Banner:      banner,
		Fingerprint: fingerprints,
	}
}

// ScanRange 扫描端口范围
func (g *GoGoScanner) ScanRange(ctx context.Context, target string, portRange string) (*core.ScanResult, error) {
	return g.ScanPorts(ctx, target, portRange)
}

// Top1000Scan 扫描 Top 1000 常用端口
func (g *GoGoScanner) Top1000Scan(ctx context.Context, target string) (*core.ScanResult, error) {
	// GoGo 使用 top2 代表 top1000
	return g.ScanPorts(ctx, target, "top2")
}

// QuickScan 快速扫描常用端口
func (g *GoGoScanner) QuickScan(ctx context.Context, target string) (*core.ScanResult, error) {
	// GoGo 使用 top1 代表 top100
	return g.ScanPorts(ctx, target, "top1")
}

// FullScan 全端口扫描
func (g *GoGoScanner) FullScan(ctx context.Context, target string) (*core.ScanResult, error) {
	return g.ScanPorts(ctx, target, "1-65535")
}

// ScanOne 扫描单个端口（快速检测）
func (g *GoGoScanner) ScanOne(target string, port string) *core.PortResult {
	_, timeout := g.snapshot()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	result, err := g.ScanPorts(ctx, target, port)
	if err != nil || result == nil || len(result.Ports) == 0 {
		return nil
	}

	return &result.Ports[0]
}

// guessService 根据端口猜测服务
func guessService(port int) string {
	// 从配置加载端口服务映射
	services := core.GetPortServiceMap()

	if service, ok := services[port]; ok {
		return service
	}
	return "unknown"
}
