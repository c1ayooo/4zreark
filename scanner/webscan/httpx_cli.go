package webscan

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/c1ayooo/4zreark/internal/datadir"
	"github.com/c1ayooo/4zreark/internal/toolruntime"
)

// HTTPXScanner 封装 projectdiscovery/httpx 外部二进制，用于 S2 探活。
//
// 与 scanner/webscan/httpx.go 的纯 Go 实现是主备关系：外部 httpx 可用时
// 优先用它（更强的协议/指纹覆盖），缺失时由 http_probe_module 回退到纯 Go。
// 本文件只负责参数构建、进程执行与 JSONL 解析，不做并发编排。
type HTTPXScanner struct {
	BinPath   string
	Threads   int
	RateLimit int // 每秒请求数
	Timeout   int // 单请求超时（秒）
	TempDir   string
	// UserAgent 由调用方按站点会话注入；为空时由 httpx 自身默认 UA 兜底。
	UserAgent string
}

// HTTPXResult 是 httpx -json 一行的解析结果。字段按 httpx 的 JSON schema
// 取常用子集；未知字段忽略，上游新增字段不影响解析。
type HTTPXResult struct {
	Input         string   `json:"input"`
	URL           string   `json:"url"`
	Host          string   `json:"host"`
	IP            string   `json:"ip"`
	Port          string   `json:"port"`
	Scheme        string   `json:"scheme"`
	StatusCode    int      `json:"status_code"`
	Title         string   `json:"title"`
	WebServer     string   `json:"webserver"`
	Tech          []string `json:"tech"`
	ContentLength int64    `json:"content_length"`
	Failed        bool     `json:"failed"`
	Error         string   `json:"error"`
}

// NewHTTPXScanner 创建 httpx 扫描器。路径统一由 toolruntime 解析：
// 托管目录 data/tools/<os>/httpx 优先，vendored tools/<os>/httpx 兜底。
func NewHTTPXScanner() *HTTPXScanner {
	return &HTTPXScanner{
		BinPath:   toolruntime.Default().ResolveToolPath("httpx"),
		Threads:   10,
		RateLimit: 50,
		Timeout:   10,
		TempDir:   datadir.TmpDir(),
	}
}

// IsAvailable 检查 httpx 二进制是否在项目统一工具目录中可用。
func (h *HTTPXScanner) IsAvailable() bool {
	if h.BinPath == "" {
		return false
	}
	st, err := os.Stat(h.BinPath)
	return err == nil && !st.IsDir()
}

// Probe 对一批目标做 HTTP 探活与富化。
// 返回部分结果 + error：ctx 取消或进程非零退出时，已经写出的行仍然有效。
func (h *HTTPXScanner) Probe(ctx context.Context, targets []string) ([]HTTPXResult, error) {
	if !h.IsAvailable() {
		return nil, fmt.Errorf("httpx not available")
	}
	if len(targets) == 0 {
		return nil, nil
	}

	dir := h.TempDir
	if dir == "" {
		dir = datadir.TmpDir()
	}
	inFile, err := os.CreateTemp(dir, "httpx-in-*.txt")
	if err != nil {
		return nil, fmt.Errorf("create httpx input: %w", err)
	}
	inPath := inFile.Name()
	defer os.Remove(inPath)
	for _, target := range targets {
		if _, err := fmt.Fprintln(inFile, target); err != nil {
			inFile.Close()
			return nil, fmt.Errorf("write httpx input: %w", err)
		}
	}
	if err := inFile.Close(); err != nil {
		return nil, fmt.Errorf("close httpx input: %w", err)
	}

	outFile, err := os.CreateTemp(dir, "httpx-out-*.jsonl")
	if err != nil {
		return nil, fmt.Errorf("create httpx output: %w", err)
	}
	outPath := outFile.Name()
	outFile.Close()
	defer os.Remove(outPath)

	args := h.buildArgs(inPath, outPath)
	cmd := exec.CommandContext(ctx, h.BinPath, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	results, parseErr := parseHTTPXFile(outPath)
	if ctx.Err() != nil {
		// 取消/超时时保留已解析出的部分结果，错误交回调用方决定是否采用。
		return results, ctx.Err()
	}
	if runErr != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			return results, fmt.Errorf("httpx: %w", runErr)
		}
		return results, fmt.Errorf("httpx: %w (%s)", runErr, msg)
	}
	if parseErr != nil {
		return results, parseErr
	}
	return results, nil
}

func (h *HTTPXScanner) buildArgs(inPath, outPath string) []string {
	args := []string{
		"-l", inPath,
		"-json",
		"-silent",
		"-title",
		"-tech-detect",
		"-status-code",
		"-web-server",
		"-follow-redirects",
		"-no-color",
		"-o", outPath,
	}
	if h.Threads > 0 {
		args = append(args, "-threads", fmt.Sprintf("%d", h.Threads))
	}
	if h.RateLimit > 0 {
		args = append(args, "-rate-limit", fmt.Sprintf("%d", h.RateLimit))
	}
	if h.Timeout > 0 {
		args = append(args, "-timeout", fmt.Sprintf("%d", h.Timeout))
	}
	// 同站一致性：调用方注入的 UA 必须原样透传，不能在这里再随机。
	if ua := strings.TrimSpace(h.UserAgent); ua != "" {
		args = append(args, "-H", "User-Agent: "+ua)
	}
	return args
}

func parseHTTPXFile(path string) ([]HTTPXResult, error) {
	f, err := os.Open(path)
	if err != nil {
		// 进程没产出文件（例如直接失败）时按空结果处理，由调用方看 runErr。
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("open httpx output: %w", err)
	}
	defer f.Close()

	results := make([]HTTPXResult, 0, 32)
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var item HTTPXResult
		if err := json.Unmarshal([]byte(line), &item); err != nil {
			continue
		}
		key := item.URL
		if key == "" {
			key = item.Input
		}
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		results = append(results, item)
	}
	if err := scanner.Err(); err != nil {
		return results, fmt.Errorf("read httpx output: %w", err)
	}
	return results, nil
}
