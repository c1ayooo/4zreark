package subdomain

import (
	"bufio"
	"context"
	"log"
	"os/exec"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/scanner/core"
)

// SubfinderScanner subfinder 子域名扫描器
type SubfinderScanner struct {
	toolPath string
	timeout  time.Duration
}

// NewSubfinderScanner 创建新的 subfinder 扫描器
func NewSubfinderScanner() *SubfinderScanner {
	tm := core.NewToolsManager()
	toolPath := tm.GetToolPath("subfinder")
	if toolPath == "" {
		log.Printf("[Subfinder] Tool not found")
		return nil
	}
	log.Printf("[Subfinder] Found subfinder at: %s", toolPath)
	return &SubfinderScanner{
		toolPath: toolPath,
		timeout:  5 * time.Minute,
	}
}

// Scan 执行子域名扫描
func (s *SubfinderScanner) Scan(ctx context.Context, domain string) ([]string, error) {
	if s == nil || s.toolPath == "" {
		return nil, nil
	}

	log.Printf("[Subfinder] Starting enumeration for %s", domain)

	// 创建带超时的上下文
	scanCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	// 构建命令: subfinder -d domain -silent
	cmd := exec.CommandContext(scanCtx, s.toolPath, "-d", domain, "-silent")

	// 获取输出管道
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	// 启动命令
	if err := cmd.Start(); err != nil {
		log.Printf("[Subfinder] Failed to start: %v", err)
		return nil, err
	}

	// 读取输出
	var subdomains []string
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && strings.HasSuffix(line, domain) {
			subdomains = append(subdomains, line)
		}
	}

	// 等待命令完成
	if err := cmd.Wait(); err != nil {
		// 检查是否是超时
		if scanCtx.Err() == context.DeadlineExceeded {
			log.Printf("[Subfinder] Timed out after %v, got %d subdomains", s.timeout, len(subdomains))
			return subdomains, nil
		}
		log.Printf("[Subfinder] Command error: %v", err)
		// 即使出错也返回已收集的结果
		return subdomains, nil
	}

	log.Printf("[Subfinder] Found %d subdomains for %s", len(subdomains), domain)
	return subdomains, nil
}

// SetTimeout 设置超时时间
func (s *SubfinderScanner) SetTimeout(timeout time.Duration) {
	if s != nil {
		s.timeout = timeout
	}
}
