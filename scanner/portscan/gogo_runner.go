package portscan

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"github.com/c1ayooo/4zreark/internal/toolruntime"
	"github.com/c1ayooo/4zreark/scanner/core"
	"log"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// GoGoScanner 使用 GoGo 进行高速端口扫描
type GoGoScanner struct {
	mu      sync.Mutex
	Threads int // 并发数
	Timeout int // 超时时间(秒)
}

// GoGoConfig GoGo 扫描配置
type GoGoConfig struct {
	Timeout   int // 超时时间(秒)
	Threads   int // 并发数/线程数
	RateLimit int // 速率限制（暂不使用）
}

// GoGoResult GoGo JSON 输出结构（字段表对照 gogo v2.15.0 实测输出）。
// frameworks 的版本藏在 attributes.version；vul 是 name → Vuln 的对象。
type GoGoResult struct {
	IP         string                   `json:"ip"`
	Port       string                   `json:"port"`
	Protocol   string                   `json:"protocol"`
	Status     string                   `json:"status"`
	Title      string                   `json:"title"`
	Midware    string                   `json:"midware"`
	Host       string                   `json:"host"`
	Uri        string                   `json:"uri"`
	Frameworks map[string]GoGoFramework `json:"frameworks"`
	Vul        map[string]GoGoVul       `json:"vul"`
}

// GoGoFramework gogo 指纹条目（tags 含 language 的即语言识别）。
type GoGoFramework struct {
	Name       string            `json:"name"`
	Tags       []string          `json:"tags"`
	Attributes GoGoFrameworkAttr `json:"attributes"`
}

type GoGoFrameworkAttr struct {
	Version string `json:"version"`
}

// GoGoVul gogo 内置 poc 命中（fingers/common.Vuln 的 JSON 形态）。
type GoGoVul struct {
	Name          string                 `json:"name"`
	Tags          []string               `json:"tags"`
	SeverityLevel int                    `json:"severity"`
	Payload       map[string]interface{} `json:"payload"`
	Detail        map[string][]string    `json:"detail"`
}

// parseStats 记录一次 gogo 输出的解析健康度：上游改 schema 时在这里先暴露，
// 而不是静默丢数据。成功率过低应对照 tool_runtime 的 needs_review 状态排查。
type parseStats struct {
	lines      int
	parsed     int
	parseErrs  int
	missingKey int
}

func (s parseStats) summary() string {
	return fmt.Sprintf("%d lines, %d parsed, %d parse-errors, %d missing-critical-field", s.lines, s.parsed, s.parseErrs, s.missingKey)
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

// resolveTool 每次扫描时解析 gogo 路径：托管目录更新或 vendored 变化即时生效。
func (g *GoGoScanner) resolveTool() string {
	return toolruntime.Default().ResolveToolPath("gogo")
}

// IsAvailable 检查是否可用
func (g *GoGoScanner) IsAvailable() bool {
	return g.resolveTool() != ""
}

// ScanPorts 扫描端口
// target: 目标 IP 或域名
// ports: 端口配置，如 "80,443,8080" 或 "1-1000" 或 "top1000"
func (g *GoGoScanner) ScanPorts(ctx context.Context, target string, ports string) (*core.ScanResult, error) {
	toolPath := g.resolveTool()
	if toolPath == "" {
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
	cmd := exec.CommandContext(ctx, toolPath, args...)

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
	var stats parseStats

	// 逐行读取输出
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// 跳过日志行（以 [*] 或 [-] 开头）
		if strings.HasPrefix(line, "[") || line == "" {
			continue
		}
		stats.lines++

		// 尝试解析 JSON
		var gogoResult GoGoResult
		if err := json.Unmarshal([]byte(line), &gogoResult); err != nil {
			stats.parseErrs++
			continue
		}
		if gogoResult.IP == "" || gogoResult.Port == "" {
			// 关键字段缺失通常是上游改了 schema，单独计数
			stats.missingKey++
			continue
		}
		stats.parsed++

		portResult := g.convertResult(&gogoResult)
		if portResult != nil {
			key := fmt.Sprintf("%s:%d", gogoResult.IP, portResult.Port)
			if !portMap[key] {
				portMap[key] = true
				result.Ports = append(result.Ports, *portResult)
			}
		}
		// gogo 内置 poc 命中：作为漏洞发现单独收集，由端口模块下发
		for _, v := range gogoResult.Vul {
			if v.Name == "" {
				continue
			}
			result.Vulns = append(result.Vulns, core.VulFinding{
				Target:        net.JoinHostPort(gogoResult.IP, gogoResult.Port),
				Name:          v.Name,
				SeverityLevel: v.SeverityLevel,
				Tags:          v.Tags,
				Payload:       v.Payload,
			})
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
	log.Printf("[GoGoScanner] Found %d open ports, %d vul hits on %s (gogo %s; parse: %s)",
		len(result.Ports), len(result.Vulns), target, gogoVersion(), stats.summary())
	if stats.lines > 0 && float64(stats.parsed)/float64(stats.lines) < 0.8 {
		log.Printf("[GoGoScanner] 警告: gogo 输出解析成功率低于 80%%（%s），疑似上游版本不兼容，请在工具运行时面板检查", stats.summary())
	}

	return result, nil
}

// gogoVersion 返回 toolruntime 记录的 gogo 版本（可能为空），用于结果归因。
func gogoVersion() string {
	return toolruntime.Default().ToolVersion("gogo")
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

	// 提取指纹：带版本的写 name/version（gogo 把版本放 attributes.version）
	var fingerprints []string
	for _, fw := range gogoResult.Frameworks {
		name := fw.Name
		if name == "" {
			continue
		}
		if v := strings.TrimSpace(fw.Attributes.Version); v != "" {
			name = name + "/" + v
		}
		fingerprints = append(fingerprints, name)
	}

	// Banner：标题为主，host/uri 可用时补在后面（vhost 与入口线索）
	banner := gogoResult.Title
	if gogoResult.Host != "" && gogoResult.Host != gogoResult.IP {
		if banner == "" {
			banner = "host: " + gogoResult.Host
		} else {
			banner = banner + " | host: " + gogoResult.Host
		}
	}
	if gogoResult.Uri != "" {
		banner = banner + " | " + gogoResult.Uri
	}

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
