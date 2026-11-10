package webscan

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/internal/datadir"
	"github.com/c1ayooo/4zreark/internal/toolruntime"
	"github.com/c1ayooo/4zreark/internal/useragent"
	"github.com/c1ayooo/4zreark/scanner/core"
)

// KatanaScanner 使用 Katana 进行网页爬虫
type KatanaScanner struct {
	BinPath          string
	Depth            int // 爬取深度
	Concurrency      int // 并发数
	Timeout          int // 超时时间(秒)
	RateLimit        int // 每秒请求数（全局）
	HostRateLimit    int // 每主机每秒请求数（保护单业务站，0=不启用）
	MaxDomainPages   int // 每域爬取页数上限（katana -mdp，引擎层止损；0=不限）
	TempDir          string
	ExecutionTimeout int // 执行超时时间（分钟）
	// Headless 起无头浏览器执行 JS 路由，SPA 场景才有实质产出；
	// 渲染开销是普通模式的 5-10 倍，调用方按目标特征分流（见 crawler_module）。
	Headless bool
	// UASeed 是任务级 UA seed；按目标 host 派生会话，保证同站同 UA。
	UASeed string
	// MemLimit 是单进程 Go 内存软上限（GOMEMLIMIT）。-jsl/jsluice 会把 JS
	// 解析结果驻留内存，曾出现单进程 12-14GB 触发 WSL 全局 OOM；设软上限
	// 让运行时提前 GC，把单进程压在预算内（撞上限变慢而不是吃光整机）。
	MemLimit string
	// DisableJSL 关闭 -jsl（jsluice 从 JS 抽端点）。这是内存放大的主要来源
	// （katana 官方标注 memory intensive）；默认开启，极端目标可显式关闭降内存。
	DisableJSL bool
	// MaxResponseSize 是单响应读取上限（-mrs，字节）。超大 JS/HTML 不截断会
	// 被完整载入解析，默认 1MB 足够端点提取，0 表示用引擎默认（4MB）。
	MaxResponseSize int
}

// SetUASeed 设置任务级 UA seed。
func (k *KatanaScanner) SetUASeed(seed string) { k.UASeed = seed }

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
	URL         string `json:"url"`
	Method      string `json:"method,omitempty"`
	StatusCode  int    `json:"status_code,omitempty"`
	Source      string `json:"source,omitempty"` // 来源页面：form, script, link, etc.
	Tag         string `json:"tag,omitempty"`    // 发现该 URL 的 HTML 标签
	Attribute   string `json:"attribute,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	Length      int64  `json:"length,omitempty"`
}

// KatanaJSONOutput Katana JSON 输出格式
type KatanaJSONOutput struct {
	Timestamp string `json:"timestamp"`
	Request   struct {
		Method    string `json:"method"`
		Endpoint  string `json:"endpoint"`
		Raw       string `json:"raw"`
		Tag       string `json:"tag"`
		Attribute string `json:"attribute"`
		Source    string `json:"source"`
	} `json:"request"`
	Response struct {
		StatusCode    int               `json:"status_code"`
		Headers       map[string]string `json:"headers"`
		ContentLength int64             `json:"content_length"`
	} `json:"response"`
}

// katanaCrawledURL 把一行 JSON 输出转成内部结构。
// tag/attribute 是接口判定的一部分：jsluice-fetch 这类来源比路径前缀可靠。
func katanaCrawledURL(out KatanaJSONOutput) KatanaCrawledURL {
	return KatanaCrawledURL{
		URL:         strings.TrimSpace(out.Request.Endpoint),
		Method:      strings.ToUpper(strings.TrimSpace(out.Request.Method)),
		StatusCode:  out.Response.StatusCode,
		Source:      out.Request.Source,
		Tag:         out.Request.Tag,
		Attribute:   out.Request.Attribute,
		ContentType: headerValue(out.Response.Headers, "Content-Type"),
		Length:      out.Response.ContentLength,
	}
}

// siteKey 从目标 URL 取站点键（host:port）；没有协议时按原串处理。
func siteKey(target string) string {
	return useragent.NormalizeSiteKey(target)
}

func headerValue(headers map[string]string, name string) string {
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// NewKatanaScanner 创建 Katana 扫描器
func NewKatanaScanner() *KatanaScanner {
	// 直接走 toolruntime，避免 core.ToolsManager 中间层与其它模块的解析路径分叉。
	binPath := toolruntime.Default().ResolveToolPath("katana")

	return &KatanaScanner{
		BinPath:          binPath,
		Depth:            3,   // 爬取深度
		Concurrency:      10,  // 并发数
		Timeout:          30,  // 每个请求超时（秒）
		RateLimit:        150, // 速率限制
		TempDir:          datadir.TmpDir(),
		ExecutionTimeout: 10, // 执行超时（分钟）
		// 构造期兜底：不进 crawler_module 的调用路径（批量/直接调用）也要有
		// 页数上限，否则 -mdp 默认 unlimited，大站会把 URL 表撑爆。
		MaxDomainPages:  500,
		MaxResponseSize: 1 << 20, // 1MB
		// 单进程 1GiB 软限：流水线爬虫默认 8 并发，8×~1GiB 在 16-32GB 机器
		// 上留足余量；正常 500 页爬取实际只用 200-600MB，不会因 GC 变慢。
		MemLimit: "1GiB",
		// jsluice 保留（端点提取需要），内存风险由 MemLimit + 响应体上限兜底；
		// 极端场景可把单个任务的 DisableJSL 置 true。
	}
}

// katanaEnv 返回子进程环境：在继承当前环境的基础上注入 GOMEMLIMIT。
// GOMEMLIMIT 是 Go 运行时的软上限（超限激进 GC），不改变功能语义，
// 但能避免单个 katana 进程把 WSL 全局内存吃光触发整机 OOM。
func (k *KatanaScanner) katanaEnv() []string {
	env := os.Environ()
	if k.MemLimit != "" {
		env = append(env, "GOMEMLIMIT="+k.MemLimit)
	}
	return env
}

// headlessMinTimeoutSeconds headless 模式的单请求超时下限：无头浏览器要真渲染
// 页面，非 headless 的默认 30s 会大片超时。只抬升传给 katana 的值，不动结构体默认。
const headlessMinTimeoutSeconds = 60

// commonArgs 是单目标与列表模式共用的参数。
// -fs rdn 把 katana 的爬取范围显式限制在注册域内，避免工具自身跟随站外链接；
// 结果层还有一次 scope 过滤，这里是工具层的第一道边界。
func (k *KatanaScanner) commonArgs(target, outputPath string) []string {
	timeout := k.Timeout
	if k.Headless && timeout < headlessMinTimeoutSeconds {
		timeout = headlessMinTimeoutSeconds
	}
	args := []string{
		"-d", fmt.Sprintf("%d", k.Depth),
		"-c", fmt.Sprintf("%d", k.Concurrency),
		"-timeout", fmt.Sprintf("%d", timeout),
		"-rl", fmt.Sprintf("%d", k.RateLimit),
		"-fs", "rdn",
		"-H", "User-Agent: " + useragent.ForSite(k.UASeed, siteKey(target)).UserAgent,
		"-silent",
		"-jsonl", // 使用 JSON Lines 格式输出，包含状态码等信息
		"-ob",    // 不带响应体：默认会在每行塞完整 body，单行轻易超 64KB
		"-or",    // 不带原始请求/响应
		// 前端只保留 HTML/JS/接口，其余静态资源与二进制全部跳过；JS 必须保留。
		"-ef", "css,map,wasm,png,jpg,jpeg,gif,svg,ico,webp,avif,woff,woff2,ttf,otf,eot,mp4,mp3,pdf,zip,rar,7z,tar,gz,exe,dmg,apk,doc,docx,xls,xlsx,ppt,pptx",
		"-jc", // 解析 JS 里的链接与接口（轻量）
		"-kf", "all",
	}
	// 响应体读取上限：katana 默认 4MB，超大 bundle 会被完整载入解析；
	// 1MB 足够提取端点，显式传入降低峰值内存。
	if k.MaxResponseSize > 0 {
		args = append(args, "-mrs", fmt.Sprintf("%d", k.MaxResponseSize))
	}
	// jsluice 是内存主放大器（官方标注 memory intensive），默认开启保留端点
	// 发现能力；目标 JS 体量异常时可显式 DisableJSL 降内存。
	if !k.DisableJSL {
		args = append(args, "-jsl")
	}
	// 引擎层节奏钳制：每主机限速保护单业务站（多目标并发时全局 -rl 对单站过快），
	// 每域页数在 katana 内部止损——模块层 MaxPages 只截产出，不减少实际请求量。
	if k.HostRateLimit > 0 {
		args = append(args, "-hrl", fmt.Sprintf("%d", k.HostRateLimit))
	}
	if k.MaxDomainPages > 0 {
		args = append(args, "-mdp", fmt.Sprintf("%d", k.MaxDomainPages))
	}
	if k.Headless {
		// -no-sandbox：worker 跑在 WSL/rootless，浏览器沙箱起不来；
		// -xhr：SPA 的接口路径大多由 XHR 产生，渲染后直接抓出来（仅 headless 有意义）；
		// -sc：用环境里已装的系统 Chrome，免去 katana 自带 chrome 的下载与版本漂移
		args = append(args, "-headless", "-no-sandbox", "-xhr", "-sc")
	}
	return append(args, "-o", outputPath)
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
	args := append([]string{"-u", target}, k.commonArgs(target, outputPath)...)

	cmd := exec.CommandContext(ctx, k.BinPath, args...)
	cmd.Env = k.katanaEnv()

	fmt.Printf("[*] Running Katana: %s %s\n", k.BinPath, strings.Join(args, " "))

	err = cmd.Run()
	// 超时/取消不丢弃已爬到的结果：输出文件里已经写出的 URL 仍然有效，
	// 先解析完再把这个错误交给调用方，由调用方决定是否采用部分结果。
	var ctxErr error
	if err != nil {
		if ctx.Err() != nil {
			ctxErr = ctx.Err()
		} else {
			fmt.Printf("[!] Katana error: %v\n", err)
		}
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
	lines, jsonParsed := 0, 0

	for {
		line, readErr := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if line != "" {
			lines++
			// 尝试解析 JSON 格式
			var jsonOutput KatanaJSONOutput
			if err := json.Unmarshal([]byte(line), &jsonOutput); err == nil {
				jsonParsed++
				crawled := katanaCrawledURL(jsonOutput)
				if crawled.URL != "" && !seen[crawled.URL] {
					seen[crawled.URL] = true
					result.URLs = append(result.URLs, crawled)
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

	if lines > 0 {
		plainFallback := lines - jsonParsed
		log.Printf("[Katana] 输出解析: %d lines, %d json, %d plain-fallback (katana %s)",
			lines, jsonParsed, plainFallback, toolruntime.Default().ToolVersion("katana"))
		if jsonParsed == 0 && plainFallback > 50 {
			log.Printf("[Katana] 警告: 全部行都不是 JSON，疑似 -jsonl 输出失效（上游改版？），请在工具运行时面板检查")
		}
	}

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime).String()
	result.Total = len(result.URLs)

	return result, ctxErr
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

	// 构建命令。批量模式一次进程只能带一个 UA，按首个目标派生，
	// 流水线实际走单目标 Crawl，不会出现批量跨站复用 UA。
	first := ""
	if len(urls) > 0 {
		first = urls[0]
	}
	args := append([]string{"-list", inputPath}, k.commonArgs(first, outputPath)...)

	cmd := exec.CommandContext(ctx, k.BinPath, args...)
	cmd.Env = k.katanaEnv()

	fmt.Printf("[*] Running Katana (list mode): %s -list [%d urls] ...\n", k.BinPath, len(urls))

	err = cmd.Run()
	// 超时/取消不丢弃已爬到的结果：输出文件里已经写出的 URL 仍然有效，
	// 先解析完再把这个错误交给调用方，由调用方决定是否采用部分结果。
	var ctxErr error
	if err != nil {
		if ctx.Err() != nil {
			ctxErr = ctx.Err()
		} else {
			fmt.Printf("[!] Katana error: %v\n", err)
		}
	}

	// 解析输出
	file, err := os.Open(outputPath)
	if err != nil {
		return result, nil
	}
	defer file.Close()

	// 与单目标模式一致：jsonl 单行可能超过 bufio.Scanner 的 64KB 上限。
	reader := bufio.NewReaderSize(file, 1<<20)
	seen := make(map[string]bool)

	for {
		line, readErr := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if line != "" {
			var jsonOutput KatanaJSONOutput
			if err := json.Unmarshal([]byte(line), &jsonOutput); err == nil {
				crawled := katanaCrawledURL(jsonOutput)
				if crawled.URL != "" && !seen[crawled.URL] {
					seen[crawled.URL] = true
					result.URLs = append(result.URLs, crawled)
				}
			} else if !seen[line] {
				seen[line] = true
				result.URLs = append(result.URLs, KatanaCrawledURL{URL: line})
			}
		}
		if readErr != nil {
			break
		}
	}

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime).String()
	result.Total = len(result.URLs)

	fmt.Printf("[*] Katana list crawl completed: %d URLs found from %d targets\n", result.Total, len(urls))

	return result, ctxErr
}
