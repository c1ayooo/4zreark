package webscan

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"github.com/c1ayooo/4zreark/scanner/core"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// SprayScanner 使用 Spray 进行目录爆破
// spray 是 chainreactors 开发的高性能目录爆破工具
type SprayScanner struct {
	BinPath           string
	Concurrency       int // 并发数
	Timeout           int // 超时时间(秒)
	RateLimit         int // 每秒请求数
	TempDir           string
	ExecutionTimeout  int  // 执行超时时间（分钟）
	Depth             int  // 递归深度
	EnableFingerprint bool // 是否启用指纹识别
	EnableCrawl       bool // 是否启用爬虫
	EnableBackup      bool // 是否扫描备份文件
	EnableCommon      bool // 是否扫描通用文件
}

// SprayResult Spray 扫描结果
type SprayResult struct {
	Target    string       `json:"target"`
	Results   []SprayEntry `json:"results"`
	StartTime time.Time    `json:"start_time"`
	EndTime   time.Time    `json:"end_time"`
	Duration  string       `json:"duration"`
	Total     int          `json:"total"`
}

// SprayEntry Spray 单条结果
type SprayEntry struct {
	URL          string                 `json:"url"`
	Path         string                 `json:"path"`
	StatusCode   int                    `json:"status"`
	BodyLength   int64                  `json:"body_length"`
	HeaderLength int64                  `json:"header_length"`
	ContentType  string                 `json:"content_type"`
	Title        string                 `json:"title"`
	Host         string                 `json:"host"`
	Frameworks   map[string]interface{} `json:"frameworks"`
	Extracts     []string               `json:"extracts"`
	Hashes       map[string]string      `json:"hashes"`
}

// SprayJSONOutput Spray JSON 输出格式 (根据实际输出调整)
type SprayJSONOutput struct {
	Number       int                    `json:"number"`
	Parent       int                    `json:"parent"`
	Valid        bool                   `json:"valid"`
	Fuzzy        bool                   `json:"fuzzy"`
	URL          string                 `json:"url"`
	Path         string                 `json:"path"`
	Host         string                 `json:"host"`
	BodyLength   int64                  `json:"body_length"`
	HeaderLength int64                  `json:"header_length"`
	Status       int                    `json:"status"`
	Spend        int64                  `json:"spend"` // 耗时(毫秒)
	ContentType  string                 `json:"content_type"`
	Title        string                 `json:"title"`
	Frameworks   map[string]interface{} `json:"frameworks"`
	Extracts     []string               `json:"extracts"`
	Error        string                 `json:"error"`
	Reason       string                 `json:"reason"`
	Source       int                    `json:"source"`
	From         int                    `json:"From"`
	Depth        int                    `json:"depth"`
	Distance     int                    `json:"distance"`
	Unique       int                    `json:"unique"`
	Hashes       map[string]string      `json:"hashes"`
}

// NewSprayScanner 创建 Spray 扫描器
func NewSprayScanner() *SprayScanner {
	tm := core.NewToolsManager()
	binPath := tm.GetToolPath("spray")

	return &SprayScanner{
		BinPath:           binPath,
		Concurrency:       50, // 并发数
		Timeout:           10, // 每个请求超时（秒）
		RateLimit:         0,  // 速率限制，0 表示不限制
		TempDir:           os.TempDir(),
		ExecutionTimeout:  30,   // 执行超时（分钟）
		Depth:             0,    // 递归深度，0 表示不递归
		EnableFingerprint: true, // 启用指纹识别
		EnableCrawl:       false,
		EnableBackup:      true, // 扫描备份文件
		EnableCommon:      true, // 扫描通用文件
	}
}

// IsAvailable 检查是否可用
func (s *SprayScanner) IsAvailable() bool {
	return s.BinPath != "" && core.FileExists(s.BinPath)
}

// Scan 对单个目标进行目录扫描
func (s *SprayScanner) Scan(ctx context.Context, target string) (*SprayResult, error) {
	return s.ScanWithWordlist(ctx, target, nil)
}

// ScanWithWordlist 使用指定字典进行目录扫描
func (s *SprayScanner) ScanWithWordlist(ctx context.Context, target string, wordlists []string) (*SprayResult, error) {
	if !s.IsAvailable() {
		return nil, fmt.Errorf("spray not available at %s", s.BinPath)
	}

	result := &SprayResult{
		Target:    target,
		StartTime: time.Now(),
		Results:   make([]SprayEntry, 0),
	}

	// 确保目标有协议
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	// 创建临时输出文件
	outputFile, err := os.CreateTemp(s.TempDir, "spray_output_*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %v", err)
	}
	outputPath := outputFile.Name()
	outputFile.Close()
	defer os.Remove(outputPath)

	// 构建命令参数
	args := s.buildArgs(target, outputPath, wordlists)

	// 创建带超时的上下文
	execCtx, cancel := context.WithTimeout(ctx, time.Duration(s.ExecutionTimeout)*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(execCtx, s.BinPath, args...)

	fmt.Printf("[*] Running Spray: %s %s\n", s.BinPath, strings.Join(args, " "))

	// 执行命令
	output, err := cmd.CombinedOutput()
	if err != nil {
		if execCtx.Err() == context.DeadlineExceeded {
			return result, fmt.Errorf("spray execution timeout after %d minutes", s.ExecutionTimeout)
		}
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		fmt.Printf("[!] Spray error: %v, output: %s\n", err, string(output))
	}

	// 解析输出文件
	entries, err := s.parseOutput(outputPath)
	if err != nil {
		fmt.Printf("[!] Failed to parse spray output: %v\n", err)
	}
	result.Results = entries
	result.Total = len(entries)

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime).String()

	fmt.Printf("[*] Spray completed for %s: found %d entries\n", target, result.Total)

	return result, nil
}

// ScanBatch 批量扫描多个目标
func (s *SprayScanner) ScanBatch(ctx context.Context, targets []string) (*SprayResult, error) {
	return s.ScanBatchWithWordlist(ctx, targets, nil)
}

// ScanBatchWithWordlist 使用指定字典批量扫描多个目标
func (s *SprayScanner) ScanBatchWithWordlist(ctx context.Context, targets []string, wordlists []string) (*SprayResult, error) {
	if !s.IsAvailable() {
		return nil, fmt.Errorf("spray not available")
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets provided")
	}

	result := &SprayResult{
		Target:    fmt.Sprintf("batch_%d_targets", len(targets)),
		StartTime: time.Now(),
		Results:   make([]SprayEntry, 0),
	}

	// 创建目标列表文件
	targetFile, err := os.CreateTemp(s.TempDir, "spray_targets_*.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to create target file: %v", err)
	}
	targetPath := targetFile.Name()
	defer os.Remove(targetPath)

	// 写入目标
	for _, t := range targets {
		// 确保目标有协议
		if !strings.HasPrefix(t, "http://") && !strings.HasPrefix(t, "https://") {
			t = "https://" + t
		}
		targetFile.WriteString(t + "\n")
	}
	targetFile.Close()

	// 创建输出文件
	outputFile, err := os.CreateTemp(s.TempDir, "spray_output_*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create output file: %v", err)
	}
	outputPath := outputFile.Name()
	outputFile.Close()
	defer os.Remove(outputPath)

	// 构建命令参数（批量模式使用 -l）
	args := s.buildBatchArgs(targetPath, outputPath, wordlists)

	// 创建带超时的上下文
	execCtx, cancel := context.WithTimeout(ctx, time.Duration(s.ExecutionTimeout)*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(execCtx, s.BinPath, args...)

	fmt.Printf("[*] Running Spray batch: %s %s\n", s.BinPath, strings.Join(args, " "))

	output, err := cmd.CombinedOutput()
	if err != nil {
		if execCtx.Err() == context.DeadlineExceeded {
			fmt.Printf("[!] Spray batch execution timeout\n")
		} else if ctx.Err() != nil {
			return result, ctx.Err()
		} else {
			fmt.Printf("[!] Spray batch error: %v, output: %s\n", err, string(output))
		}
	}

	// 解析输出
	entries, err := s.parseOutput(outputPath)
	if err != nil {
		fmt.Printf("[!] Failed to parse spray batch output: %v\n", err)
	}
	result.Results = entries
	result.Total = len(entries)

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime).String()

	fmt.Printf("[*] Spray batch completed: found %d entries from %d targets\n", result.Total, len(targets))

	return result, nil
}

// CheckOnly 仅进行指纹识别（类似 httpx）
func (s *SprayScanner) CheckOnly(ctx context.Context, targets []string) (*SprayResult, error) {
	if !s.IsAvailable() {
		return nil, fmt.Errorf("spray not available")
	}

	result := &SprayResult{
		Target:    fmt.Sprintf("check_%d_targets", len(targets)),
		StartTime: time.Now(),
		Results:   make([]SprayEntry, 0),
	}

	// 创建目标列表文件
	targetFile, err := os.CreateTemp(s.TempDir, "spray_check_*.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to create target file: %v", err)
	}
	targetPath := targetFile.Name()
	defer os.Remove(targetPath)

	for _, t := range targets {
		if !strings.HasPrefix(t, "http://") && !strings.HasPrefix(t, "https://") {
			t = "https://" + t
		}
		targetFile.WriteString(t + "\n")
	}
	targetFile.Close()

	// 创建输出文件
	outputFile, err := os.CreateTemp(s.TempDir, "spray_check_output_*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create output file: %v", err)
	}
	outputPath := outputFile.Name()
	outputFile.Close()
	defer os.Remove(outputPath)

	// check-only 模式参数
	args := []string{
		"-l", targetPath,
		"--check-only",
		"-t", fmt.Sprintf("%d", s.Concurrency),
		"-j",             // JSON 输出
		"-f", outputPath, // 输出文件
		"--no-color",
		"--no-bar",
	}

	if s.EnableFingerprint {
		args = append(args, "--finger")
	}

	execCtx, cancel := context.WithTimeout(ctx, time.Duration(s.ExecutionTimeout)*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(execCtx, s.BinPath, args...)

	fmt.Printf("[*] Running Spray check-only: %s %s\n", s.BinPath, strings.Join(args, " "))

	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("[!] Spray check error: %v, output: %s\n", err, string(output))
	}

	entries, err := s.parseOutput(outputPath)
	if err != nil {
		fmt.Printf("[!] Failed to parse spray check output: %v\n", err)
	}
	result.Results = entries
	result.Total = len(entries)

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime).String()

	return result, nil
}

// buildArgs 构建单目标扫描参数
func (s *SprayScanner) buildArgs(target, outputPath string, wordlists []string) []string {
	args := []string{
		"-u", target,
		"-t", fmt.Sprintf("%d", s.Concurrency),
		"-j",             // JSON 输出格式
		"-f", outputPath, // 输出文件
		"--no-color",
		"--no-bar", // 禁用进度条
	}

	// 添加字典
	if len(wordlists) > 0 {
		for _, wl := range wordlists {
			args = append(args, "-d", wl)
		}
	} else {
		// 使用默认字典
		args = append(args, "-D")
	}

	// 速率限制
	if s.RateLimit > 0 {
		args = append(args, "--rate-limit", fmt.Sprintf("%d", s.RateLimit))
	}

	// 递归深度
	if s.Depth > 0 {
		args = append(args, "--depth", fmt.Sprintf("%d", s.Depth))
	}

	// 指纹识别
	if s.EnableFingerprint {
		args = append(args, "--finger")
	}

	// 爬虫
	if s.EnableCrawl {
		args = append(args, "--crawl")
	}

	// 备份文件扫描
	if s.EnableBackup {
		args = append(args, "--bak")
	}

	// 通用文件扫描
	if s.EnableCommon {
		args = append(args, "--common")
	}

	return args
}

// buildBatchArgs 构建批量扫描参数
func (s *SprayScanner) buildBatchArgs(targetPath, outputPath string, wordlists []string) []string {
	args := []string{
		"-l", targetPath,
		"-t", fmt.Sprintf("%d", s.Concurrency),
		"-j",             // JSON 输出格式
		"-f", outputPath, // 输出文件
		"--no-color",
		"--no-bar", // 禁用进度条
	}

	// 添加字典
	if len(wordlists) > 0 {
		for _, wl := range wordlists {
			args = append(args, "-d", wl)
		}
	} else {
		// 使用默认字典
		args = append(args, "-D")
	}

	// 速率限制
	if s.RateLimit > 0 {
		args = append(args, "--rate-limit", fmt.Sprintf("%d", s.RateLimit))
	}

	// 递归深度
	if s.Depth > 0 {
		args = append(args, "--depth", fmt.Sprintf("%d", s.Depth))
	}

	// 指纹识别
	if s.EnableFingerprint {
		args = append(args, "--finger")
	}

	// 备份文件扫描
	if s.EnableBackup {
		args = append(args, "--bak")
	}

	// 通用文件扫描
	if s.EnableCommon {
		args = append(args, "--common")
	}

	return args
}

// parseOutput 解析 Spray 输出文件
func (s *SprayScanner) parseOutput(outputPath string) ([]SprayEntry, error) {
	var entries []SprayEntry

	file, err := os.Open(outputPath)
	if err != nil {
		return entries, fmt.Errorf("failed to open output file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// 增加缓冲区大小以处理长行
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	seen := make(map[string]bool)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// 尝试解析 JSON
		var jsonOutput SprayJSONOutput
		if err := json.Unmarshal([]byte(line), &jsonOutput); err != nil {
			// 可能是普通文本输出，跳过
			continue
		}

		// 去重 - 使用 URL 或 URL+Path 作为唯一键
		uniqueKey := jsonOutput.URL
		if jsonOutput.Path != "" {
			uniqueKey = jsonOutput.URL + jsonOutput.Path
		}

		if uniqueKey != "" && !seen[uniqueKey] {
			seen[uniqueKey] = true

			entry := SprayEntry{
				URL:          jsonOutput.URL,
				Path:         jsonOutput.Path,
				StatusCode:   jsonOutput.Status,
				BodyLength:   jsonOutput.BodyLength,
				HeaderLength: jsonOutput.HeaderLength,
				ContentType:  jsonOutput.ContentType,
				Title:        jsonOutput.Title,
				Host:         jsonOutput.Host,
				Frameworks:   jsonOutput.Frameworks,
				Extracts:     jsonOutput.Extracts,
				Hashes:       jsonOutput.Hashes,
			}

			entries = append(entries, entry)
		}
	}

	if err := scanner.Err(); err != nil {
		return entries, fmt.Errorf("error reading output: %v", err)
	}

	return entries, nil
}

// GetDefaultWordlistPath 获取默认字典路径
func (s *SprayScanner) GetDefaultWordlistPath() string {
	// spray 自带字典，通常不需要额外指定
	// 如果需要自定义字典，可以在这里返回路径
	if s.BinPath == "" {
		return ""
	}

	// 检查是否存在默认字典目录
	sprayDir := filepath.Dir(s.BinPath)
	defaultDict := filepath.Join(sprayDir, "dict", "default.txt")
	if core.FileExists(defaultDict) {
		return defaultDict
	}

	return ""
}

// SetOptions 设置扫描选项
func (s *SprayScanner) SetOptions(opts SprayScanOptions) {
	if opts.Concurrency > 0 {
		s.Concurrency = opts.Concurrency
	}
	if opts.Timeout > 0 {
		s.Timeout = opts.Timeout
	}
	if opts.RateLimit > 0 {
		s.RateLimit = opts.RateLimit
	}
	if opts.Depth >= 0 {
		s.Depth = opts.Depth
	}
	if opts.ExecutionTimeout > 0 {
		s.ExecutionTimeout = opts.ExecutionTimeout
	}
	s.EnableFingerprint = opts.EnableFingerprint
	s.EnableCrawl = opts.EnableCrawl
	s.EnableBackup = opts.EnableBackup
	s.EnableCommon = opts.EnableCommon
}

// SprayScanOptions Spray 扫描选项
type SprayScanOptions struct {
	Concurrency       int
	Timeout           int
	RateLimit         int
	Depth             int
	ExecutionTimeout  int
	EnableFingerprint bool
	EnableCrawl       bool
	EnableBackup      bool
	EnableCommon      bool
}
