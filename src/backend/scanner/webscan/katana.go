package webscan

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"github.com/c1ayooo/4zreark/internal/useragent"
	"github.com/c1ayooo/4zreark/scanner/core"
	"os"
	"os/exec"
	"strings"
	"time"
)

// KatanaScanner 使用 Katana 进行网页爬虫
type KatanaScanner struct {
	BinPath          string
	Depth            int // 爬取深度
	Concurrency      int // 并发数
	Timeout          int // 超时时间(秒)
	RateLimit        int // 每秒请求数
	TempDir          string
	ExecutionTimeout int // 执行超时时间（分钟）
}

// KatanaResult Katana 爬虫结果
type KatanaResult struct {
	Target    string             `json:"target"`
	URLs      []KatanaCrawledURL `json:"urls"`
	StartTime time.Time          `json:"start_time"`
	EndTime   time.Time          `json:"end_time"`
	Duration  string             `json:"duration"`
	Total     int                `json:"total"`
}

// KatanaCrawledURL 爬取到的URL
type KatanaCrawledURL struct {
	URL        string `json:"url"`
	Method     string `json:"method,omitempty"`
	StatusCode int    `json:"status_code,omitempty"`
	Source     string `json:"source,omitempty"` // 来源：form, script, link, etc.
}

// KatanaJSONOutput Katana JSON 输出格式
type KatanaJSONOutput struct {
	Timestamp string `json:"timestamp"`
	Request   struct {
		Method   string `json:"method"`
		Endpoint string `json:"endpoint"`
		Raw      string `json:"raw"`
	} `json:"request"`
	Response struct {
		StatusCode int `json:"status_code"`
	} `json:"response"`
}

// NewKatanaScanner 创建 Katana 扫描器
func NewKatanaScanner() *KatanaScanner {
	tm := core.NewToolsManager()
	binPath := tm.GetToolPath("katana")

	return &KatanaScanner{
		BinPath:          binPath,
		Depth:            3,   // 爬取深度
		Concurrency:      10,  // 并发数
		Timeout:          30,  // 每个请求超时（秒）
		RateLimit:        150, // 速率限制
		TempDir:          os.TempDir(),
		ExecutionTimeout: 10, // 执行超时（分钟）
	}
}

// commonArgs 是单目标与列表模式共用的参数。
// -fs rdn 把 katana 的爬取范围显式限制在注册域内，避免工具自身跟随站外链接；
// 结果层还有一次 scope 过滤，这里是工具层的第一道边界。
func (k *KatanaScanner) commonArgs(outputPath string) []string {
	return []string{
		"-d", fmt.Sprintf("%d", k.Depth),
		"-c", fmt.Sprintf("%d", k.Concurrency),
		"-timeout", fmt.Sprintf("%d", k.Timeout),
		"-rl", fmt.Sprintf("%d", k.RateLimit),
		"-fs", "rdn",
		"-H", "User-Agent: " + useragent.Pick(),
		"-silent",
		"-jsonl",                                                                                // 使用 JSON Lines 格式输出，包含状态码等信息
		"-ob",                                                                                   // 不带响应体：默认会在每行塞完整 body，单行轻易超 64KB
		"-or",                                                                                   // 不带原始请求/响应
		"-ef", "css,map,wasm,png,jpg,jpeg,gif,svg,ico,webp,avif,woff,woff2,ttf,otf,eot,mp4,mp3", // 只跳过非 JS 静态资源；JS 要留给 -jc 和后续接口分析
		"-jc",  // 解析 JS 里的链接与接口
		"-jsl", // jsluice：从 JS 内容里提取 API/端点（内存占用高，流式单目标可接受）
		"-kf", "all",
		"-o", outputPath,
	}
}

// IsAvailable 检查是否可用
func (k *KatanaScanner) IsAvailable() bool {
	return k.BinPath != "" && core.FileExists(k.BinPath)
}

// Crawl 爬取目标网站
func (k *KatanaScanner) Crawl(ctx context.Context, target string) (*KatanaResult, error) {
	if !k.IsAvailable() {
		return nil, fmt.Errorf("katana not available")
	}

	result := &KatanaResult{
		Target:    target,
		StartTime: time.Now(),
		URLs:      make([]KatanaCrawledURL, 0),
	}

	// 确保目标有协议
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	// 创建临时输出文件
	outputFile, err := os.CreateTemp(k.TempDir, "katana_output_*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %v", err)
	}
	outputPath := outputFile.Name()
	outputFile.Close()
	defer os.Remove(outputPath)

	// 构建命令
	args := append([]string{"-u", target}, k.commonArgs(outputPath)...)

	cmd := exec.CommandContext(ctx, k.BinPath, args...)

	fmt.Printf("[*] Running Katana: %s %s\n", k.BinPath, strings.Join(args, " "))

	err = cmd.Run()
	if err != nil {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		fmt.Printf("[!] Katana error: %v\n", err)
	}

	// 解析输出
	file, err := os.Open(outputPath)
	if err != nil {
		return result, nil
	}
	defer file.Close()

	// 逐行读而不是 bufio.Scanner：Scanner 单行上限 64KB，katana 的 jsonl 一行
	// 可能几百 KB（带了 body），一旦超限就读断，后面所有 URL 全部丢失。
	reader := bufio.NewReaderSize(file, 1<<20)
	seen := make(map[string]bool)

	for {
		line, readErr := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if line != "" {
			// 尝试解析 JSON 格式
			var jsonOutput KatanaJSONOutput
			if err := json.Unmarshal([]byte(line), &jsonOutput); err == nil {
				url := jsonOutput.Request.Endpoint
				if url != "" && !seen[url] {
					seen[url] = true
					result.URLs = append(result.URLs, KatanaCrawledURL{
						URL:        url,
						Method:     jsonOutput.Request.Method,
						StatusCode: jsonOutput.Response.StatusCode,
					})
				}
			} else if !seen[line] {
				// 纯文本格式（每行一个URL）
				seen[line] = true
				result.URLs = append(result.URLs, KatanaCrawledURL{
					URL: line,
				})
			}
		}
		if readErr != nil {
			break
		}
	}

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime).String()
	result.Total = len(result.URLs)

	return result, nil
}

// QuickCrawl 快速爬取（深度2）
func (k *KatanaScanner) QuickCrawl(ctx context.Context, target string) (*KatanaResult, error) {
	k.Depth = 2
	return k.Crawl(ctx, target)
}

// DeepCrawl 深度爬取（深度5）
func (k *KatanaScanner) DeepCrawl(ctx context.Context, target string) (*KatanaResult, error) {
	k.Depth = 5
	return k.Crawl(ctx, target)
}

// CrawlList 批量爬取多个URL（使用 -list 参数）
// 接收 URL 列表，写入临时文件，然后调用 katana -list
func (k *KatanaScanner) CrawlList(ctx context.Context, urls []string) (*KatanaResult, error) {
	if !k.IsAvailable() {
		return nil, fmt.Errorf("katana not available")
	}

	if len(urls) == 0 {
		return &KatanaResult{
			URLs: []KatanaCrawledURL{},
		}, nil
	}

	result := &KatanaResult{
		Target:    fmt.Sprintf("list(%d urls)", len(urls)),
		StartTime: time.Now(),
		URLs:      make([]KatanaCrawledURL, 0),
	}

	// 创建输入文件（URL列表）
	inputFile, err := os.CreateTemp(k.TempDir, "katana_input_*.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to create input file: %v", err)
	}
	inputPath := inputFile.Name()
	defer os.Remove(inputPath)

	// 写入 URL 列表
	for _, url := range urls {
		// 确保 URL 有协议
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			url = "https://" + url
		}
		inputFile.WriteString(url + "\n")
	}
	inputFile.Close()

	// 创建输出文件
	outputFile, err := os.CreateTemp(k.TempDir, "katana_output_*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create output file: %v", err)
	}
	outputPath := outputFile.Name()
	outputFile.Close()
	defer os.Remove(outputPath)

	// 构建命令
	args := append([]string{"-list", inputPath}, k.commonArgs(outputPath)...)

	cmd := exec.CommandContext(ctx, k.BinPath, args...)

	fmt.Printf("[*] Running Katana (list mode): %s -list [%d urls] ...\n", k.BinPath, len(urls))

	err = cmd.Run()
	if err != nil {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		fmt.Printf("[!] Katana error: %v\n", err)
	}

	// 解析输出
	file, err := os.Open(outputPath)
	if err != nil {
		return result, nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	seen := make(map[string]bool)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var jsonOutput KatanaJSONOutput
		if err := json.Unmarshal([]byte(line), &jsonOutput); err == nil {
			url := jsonOutput.Request.Endpoint
			if url != "" && !seen[url] {
				seen[url] = true
				result.URLs = append(result.URLs, KatanaCrawledURL{
					URL:        url,
					Method:     jsonOutput.Request.Method,
					StatusCode: jsonOutput.Response.StatusCode,
				})
			}
		} else {
			if !seen[line] {
				seen[line] = true
				result.URLs = append(result.URLs, KatanaCrawledURL{
					URL: line,
				})
			}
		}
	}

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime).String()
	result.Total = len(result.URLs)

	fmt.Printf("[*] Katana list crawl completed: %d URLs found from %d targets\n", result.Total, len(urls))

	return result, nil
}
