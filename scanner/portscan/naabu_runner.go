package portscan

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/internal/datadir"
	"github.com/c1ayooo/4zreark/internal/toolruntime"
	"github.com/c1ayooo/4zreark/scanner/core"
)

// NaabuScanner 封装 projectdiscovery/naabu 外部二进制，用于端口发现。
//
// 分工：naabu 只做 L4 端口发现（connect 模式不需要 root），gogo 继续负责
// 服务/协议识别与内置 poc；两者都缺失时由 port_module 回退纯 Go TCP。
// 本文件只负责参数构建、进程执行与 JSONL 解析。
type NaabuScanner struct {
	BinPath  string
	Rate     int // 每秒包数
	Threads  int // 并发
	Timeout  int // 单端口超时（秒）
	TempDir  string
	ScanType string // connect（默认，无 root）/ syn
}

// naabuJSON 是 naabu -json 一行的解析结果。
type naabuJSON struct {
	Host     string `json:"host"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	TLS      bool   `json:"tls"`
	// State 只在部分 naabu 版本/参数下出现；有值时只接受 open，
	// 避免 CDN/全响应目标把 filtered/closed 也当成开放端口。
	State string `json:"state"`
}

// NewNaabuScanner 创建 naabu 扫描器。路径统一由 toolruntime 解析。
func NewNaabuScanner() *NaabuScanner {
	return &NaabuScanner{
		BinPath:  toolruntime.Default().ResolveToolPath("naabu"),
		Rate:     500,
		Threads:  25,
		Timeout:  3,
		TempDir:  datadir.TmpDir(),
		ScanType: "connect",
	}
}

// IsAvailable 检查 naabu 二进制是否在项目统一工具目录中可用。
func (n *NaabuScanner) IsAvailable() bool {
	if n.BinPath == "" {
		return false
	}
	st, err := os.Stat(n.BinPath)
	return err == nil && !st.IsDir()
}

// ScanPorts 对单个目标做端口发现，返回与 gogo 一致的 core.ScanResult，
// 便于 port_module 在不改下游的情况下切换后端。
func (n *NaabuScanner) ScanPorts(ctx context.Context, target, ports string) (*core.ScanResult, error) {
	if !n.IsAvailable() {
		return nil, fmt.Errorf("naabu not available")
	}
	result := &core.ScanResult{
		Target:    target,
		StartTime: time.Now(),
		Ports:     make([]core.PortResult, 0, 16),
	}

	args := n.buildArgs(target, ports)
	cmd := exec.CommandContext(ctx, n.BinPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	// naabu 2.6.1 的 -o 文件在 -json/-silent 组合下可能为 0 字节，
	// 但 stdout 仍是 JSONL；直接解析 stdout，避免“永远未发现端口”。
	parsed, parseErr := parseNaabuOutput(stdout.Bytes())
	if ctx.Err() != nil {
		result.EndTime = time.Now()
		result.Ports = parsed
		return result, ctx.Err()
	}
	result.EndTime = time.Now()
	result.Ports = parsed
	if runErr != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			return result, fmt.Errorf("naabu: %w", runErr)
		}
		return result, fmt.Errorf("naabu: %w (%s)", runErr, msg)
	}
	if parseErr != nil {
		return result, parseErr
	}
	return result, nil
}

func (n *NaabuScanner) buildArgs(target, ports string) []string {
	scanType := n.ScanType
	if scanType == "" {
		scanType = "connect"
	}
	args := []string{
		"-host", target,
		"-p", ports,
		"-json",
		"-silent",
		"-no-color",
		"-scan-type", scanType,
		// 对 CDN/WAF 只扫 80/443，避免 1-1000 全响应导致 997 端口误报；
		// -verify 再做一次 TCP 复核。
		"-exclude-cdn",
		"-verify",
	}
	if n.Rate > 0 {
		args = append(args, "-rate", fmt.Sprintf("%d", n.Rate))
	}
	if n.Threads > 0 {
		args = append(args, "-c", fmt.Sprintf("%d", n.Threads))
	}
	if n.Timeout > 0 {
		args = append(args, "-timeout", fmt.Sprintf("%d", n.Timeout))
	}
	return args
}

func parseNaabuOutput(data []byte) ([]core.PortResult, error) {
	results := make([]core.PortResult, 0, 16)
	seen := make(map[int]bool)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 1*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var item naabuJSON
		if err := json.Unmarshal([]byte(line), &item); err != nil {
			continue
		}
		if item.Port <= 0 || item.Port > 65535 || seen[item.Port] {
			continue
		}
		if item.State != "" && item.State != "open" {
			continue
		}
		seen[item.Port] = true
		results = append(results, core.PortResult{
			Port:    item.Port,
			State:   "open",
			Service: guessService(item.Port),
			IP:      item.IP,
		})
	}
	if err := scanner.Err(); err != nil {
		return results, fmt.Errorf("read naabu output: %w", err)
	}
	return results, nil
}
