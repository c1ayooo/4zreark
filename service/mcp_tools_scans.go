package service

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/c1ayooo/4zreark/repo"
)

// scanTools 是直接扫描工具。它们同步返回结果、不落库；
// 需要把结果并入资产域时，应改用 create_task + start_task 的任务链路。
func (s *MCPService) scanTools() []mcpToolHandler {
	return []mcpToolHandler{
		{
			Tool: mcpTool{
				Name:        "scan_ports",
				Title:       "端口扫描",
				Description: "同步端口扫描，返回结果但不落库。mode=quick/custom/single；custom 需 ports，single 需 port。会产生网络流量。",
				InputSchema: inputSchema(map[string]any{
					"mode":    map[string]any{"type": "string", "enum": []string{"quick", "custom", "single"}, "default": "quick"},
					"target":  map[string]any{"type": "string", "description": "域名或 IP"},
					"ports":   map[string]any{"type": "string", "description": "custom 模式：80,443 或 1-1000"},
					"port":    map[string]any{"type": "integer", "minimum": 1, "maximum": 65535, "description": "single 模式端口"},
					"timeout": map[string]any{"type": "integer", "minimum": 1, "description": "超时秒数"},
				}, "target"),
				Annotations: writeAnnotations(false),
			},
			Scopes: []string{ScopeScansRun},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.scanPorts(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "scan_subdomains",
				Title:       "子域名扫描",
				Description: "同步子域名枚举（quick/full/custom），返回结果但不落库。custom 需 wordlist。",
				InputSchema: inputSchema(map[string]any{
					"mode":     map[string]any{"type": "string", "enum": []string{"quick", "full", "custom"}, "default": "quick"},
					"domain":   map[string]any{"type": "string"},
					"wordlist": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"timeout":  map[string]any{"type": "integer", "minimum": 1},
				}, "domain"),
				Annotations: writeAnnotations(false),
			},
			Scopes: []string{ScopeScansRun},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.scanSubdomains(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "get_domain_info",
				Title:       "域名信息",
				Description: "查询域名 A/AAAA/NS/MX/TXT 等解析信息（会发起 DNS 查询）。",
				InputSchema: inputSchema(map[string]any{
					"domain":  map[string]any{"type": "string"},
					"timeout": map[string]any{"type": "integer", "minimum": 1},
				}, "domain"),
				Annotations: readOnlyAnnotations(),
			},
			Scopes: []string{ScopeScansRun},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.domainInfo(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "scan_fingerprint",
				Title:       "指纹识别",
				Description: "同步识别目标 Web 指纹/技术栈；多个目标自动批量。",
				InputSchema: inputSchema(map[string]any{
					"targets": map[string]any{"type": "array", "minItems": 1, "maxItems": 500, "items": map[string]any{"type": "string"}},
					"timeout": map[string]any{"type": "integer", "minimum": 1},
				}, "targets"),
				Annotations: writeAnnotations(false),
			},
			Scopes: []string{ScopeScansRun},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.scanFingerprint(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "scan_vulns",
				Title:       "漏洞扫描",
				Description: "用内置 POC 模板同步扫描目标。quick=true 只跑 high/critical；可按 severity 或 template_ids 过滤。",
				InputSchema: inputSchema(map[string]any{
					"target":       map[string]any{"type": "string"},
					"quick":        map[string]any{"type": "boolean", "default": false},
					"severities":   map[string]any{"type": "array", "items": map[string]any{"type": "string", "enum": []string{"critical", "high", "medium", "low", "info"}}},
					"template_ids": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"timeout":      map[string]any{"type": "integer", "minimum": 1},
				}, "target"),
				Annotations: writeAnnotations(false),
			},
			Scopes: []string{ScopeScansRun},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.scanVulns(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "scan_dirs",
				Title:       "目录扫描",
				Description: "同步目录/路径爆破。quick=true 使用内置字典；custom 可传 wordlist。",
				InputSchema: inputSchema(map[string]any{
					"target":   map[string]any{"type": "string"},
					"wordlist": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"quick":    map[string]any{"type": "boolean", "default": false},
					"timeout":  map[string]any{"type": "integer", "minimum": 1},
				}, "target"),
				Annotations: writeAnnotations(false),
			},
			Scopes: []string{ScopeScansRun},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.scanDirs(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "scan_sensitive",
				Title:       "敏感信息扫描",
				Description: "同步扫描页面中的敏感信息（密钥、邮箱、内网地址等）。",
				InputSchema: inputSchema(map[string]any{
					"targets": map[string]any{"type": "array", "minItems": 1, "maxItems": 500, "items": map[string]any{"type": "string"}},
					"timeout": map[string]any{"type": "integer", "minimum": 1},
				}, "targets"),
				Annotations: writeAnnotations(false),
			},
			Scopes: []string{ScopeScansRun},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.scanSensitive(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "crawl_site",
				Title:       "站点爬虫",
				Description: "同步爬取站点 URL 与表单，返回结果但不落库。",
				InputSchema: inputSchema(map[string]any{
					"target":    map[string]any{"type": "string"},
					"max_depth": map[string]any{"type": "integer", "minimum": 1, "maximum": 20, "default": 3},
					"max_urls":  map[string]any{"type": "integer", "minimum": 1, "maximum": 10000, "default": 100},
					"timeout":   map[string]any{"type": "integer", "minimum": 1},
				}, "target"),
				Annotations: writeAnnotations(false),
			},
			Scopes: []string{ScopeScansRun},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.crawlSite(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "scan_weak_password",
				Title:       "弱口令扫描",
				Description: "对 ssh/ftp/mysql/redis 做弱口令尝试。会发起真实登录请求，请确认已获授权。",
				InputSchema: inputSchema(map[string]any{
					"target":  map[string]any{"type": "string"},
					"port":    map[string]any{"type": "integer", "minimum": 1, "maximum": 65535},
					"service": map[string]any{"type": "string", "enum": []string{"ssh", "ftp", "mysql", "redis"}},
					"timeout": map[string]any{"type": "integer", "minimum": 1},
				}, "target", "port", "service"),
				Annotations: writeAnnotations(false),
			},
			Scopes: []string{ScopeScansRun},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.scanWeakPassword(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "scan_takeover",
				Title:       "子域名接管检测",
				Description: "检测 CNAME 指向的云服务是否存在接管风险；可批量。",
				InputSchema: inputSchema(map[string]any{
					"domains": map[string]any{"type": "array", "minItems": 1, "maxItems": 1000, "items": map[string]any{"type": "string"}},
					"timeout": map[string]any{"type": "integer", "minimum": 1},
				}, "domains"),
				Annotations: writeAnnotations(false),
			},
			Scopes: []string{ScopeScansRun},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.scanTakeover(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "scan_nuclei",
				Title:       "Nuclei 扫描",
				Description: "用平台 POC 库物化 nuclei 模板并扫描目标。可按 severity/template_ids/tags 过滤；同步返回结果。",
				InputSchema: inputSchema(map[string]any{
					"targets":      map[string]any{"type": "array", "minItems": 1, "maxItems": 100, "items": map[string]any{"type": "string"}},
					"severity":     map[string]any{"type": "string", "description": "逗号分隔，如 high,critical"},
					"template_ids": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"tags":         map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"timeout":      map[string]any{"type": "integer", "minimum": 1},
				}, "targets"),
				Annotations: writeAnnotations(false),
			},
			Scopes: []string{ScopeScansRun},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.scanNuclei(ctx, key, args)
			},
		},
	}
}

// ensureScanTargetsAllowed 给绑定项目的 key 加目标归属校验；
// 全项目 key 不限制目标，但仍受 scans:run 授权。
func (s *MCPService) ensureScanTargetsAllowed(ctx context.Context, key *repo.APIKey, targets []string) error {
	if key.ProjectID == nil {
		return nil
	}
	for _, target := range targets {
		ok, err := s.scans.TargetAllowedForProject(ctx, *key.ProjectID, target)
		if err != nil {
			return fmt.Errorf("校验目标 %s 失败: %w", target, err)
		}
		if !ok {
			return fmt.Errorf("目标 %s 不在该项目的资产/种子范围内；如需扫描任意目标请使用「全部项目」的 key", target)
		}
	}
	return nil
}

func (s *MCPService) scanPorts(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	var args struct {
		Mode    string `json:"mode"`
		Target  string `json:"target"`
		Ports   string `json:"ports"`
		Port    int    `json:"port"`
		Timeout int    `json:"timeout"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if err := s.ensureScanTargetsAllowed(ctx, key, []string{args.Target}); err != nil {
		return toolError(err.Error())
	}
	res, err := s.scans.PortScan(ctx, args.Mode, args.Target, args.Ports, args.Port, args.Timeout)
	if err != nil {
		return toolError("端口扫描失败: " + err.Error())
	}
	return toolOK(res)
}

func (s *MCPService) scanSubdomains(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	var args struct {
		Mode     string   `json:"mode"`
		Domain   string   `json:"domain"`
		Wordlist []string `json:"wordlist"`
		Timeout  int      `json:"timeout"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if err := s.ensureScanTargetsAllowed(ctx, key, []string{args.Domain}); err != nil {
		return toolError(err.Error())
	}
	res, err := s.scans.SubdomainScan(ctx, args.Mode, args.Domain, args.Wordlist, args.Timeout)
	if err != nil {
		return toolError("子域名扫描失败: " + err.Error())
	}
	return toolOK(res)
}

func (s *MCPService) domainInfo(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	var args struct {
		Domain  string `json:"domain"`
		Timeout int    `json:"timeout"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if err := s.ensureScanTargetsAllowed(ctx, key, []string{args.Domain}); err != nil {
		return toolError(err.Error())
	}
	res, err := s.scans.DomainInfo(ctx, args.Domain, args.Timeout)
	if err != nil {
		return toolError("域名查询失败: " + err.Error())
	}
	return toolOK(res)
}

func (s *MCPService) scanFingerprint(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	var args struct {
		Targets []string `json:"targets"`
		Timeout int      `json:"timeout"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if err := s.ensureScanTargetsAllowed(ctx, key, args.Targets); err != nil {
		return toolError(err.Error())
	}
	res, err := s.scans.FingerprintScan(ctx, args.Targets, args.Timeout)
	if err != nil {
		return toolError("指纹识别失败: " + err.Error())
	}
	return toolOK(res)
}

func (s *MCPService) scanVulns(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	var args struct {
		Target      string   `json:"target"`
		Quick       bool     `json:"quick"`
		Severities  []string `json:"severities"`
		TemplateIDs []string `json:"template_ids"`
		Timeout     int      `json:"timeout"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if err := s.ensureScanTargetsAllowed(ctx, key, []string{args.Target}); err != nil {
		return toolError(err.Error())
	}
	res, err := s.scans.VulnScan(ctx, args.Target, args.Quick, args.Severities, args.TemplateIDs, args.Timeout)
	if err != nil {
		return toolError("漏洞扫描失败: " + err.Error())
	}
	return toolOK(res)
}

func (s *MCPService) scanDirs(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	var args struct {
		Target   string   `json:"target"`
		Wordlist []string `json:"wordlist"`
		Quick    bool     `json:"quick"`
		Timeout  int      `json:"timeout"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if err := s.ensureScanTargetsAllowed(ctx, key, []string{args.Target}); err != nil {
		return toolError(err.Error())
	}
	res, err := s.scans.DirScan(ctx, args.Target, args.Wordlist, args.Quick, args.Timeout)
	if err != nil {
		return toolError("目录扫描失败: " + err.Error())
	}
	return toolOK(res)
}

func (s *MCPService) scanSensitive(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	var args struct {
		Targets []string `json:"targets"`
		Timeout int      `json:"timeout"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if err := s.ensureScanTargetsAllowed(ctx, key, args.Targets); err != nil {
		return toolError(err.Error())
	}
	res, err := s.scans.SensitiveScan(ctx, args.Targets, args.Timeout)
	if err != nil {
		return toolError("敏感信息扫描失败: " + err.Error())
	}
	return toolOK(res)
}

func (s *MCPService) crawlSite(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	var args struct {
		Target   string `json:"target"`
		MaxDepth int    `json:"max_depth"`
		MaxURLs  int    `json:"max_urls"`
		Timeout  int    `json:"timeout"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if err := s.ensureScanTargetsAllowed(ctx, key, []string{args.Target}); err != nil {
		return toolError(err.Error())
	}
	res, err := s.scans.Crawl(ctx, args.Target, args.MaxDepth, args.MaxURLs, args.Timeout)
	if err != nil {
		return toolError("爬取失败: " + err.Error())
	}
	return toolOK(res)
}

func (s *MCPService) scanWeakPassword(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	var args struct {
		Target  string `json:"target"`
		Port    int    `json:"port"`
		Service string `json:"service"`
		Timeout int    `json:"timeout"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if err := s.ensureScanTargetsAllowed(ctx, key, []string{args.Target}); err != nil {
		return toolError(err.Error())
	}
	res, err := s.scans.WeakPasswordScan(ctx, args.Target, args.Port, args.Service, args.Timeout)
	if err != nil {
		return toolError("弱口令扫描失败: " + err.Error())
	}
	return toolOK(res)
}

func (s *MCPService) scanTakeover(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	var args struct {
		Domains []string `json:"domains"`
		Timeout int      `json:"timeout"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if err := s.ensureScanTargetsAllowed(ctx, key, args.Domains); err != nil {
		return toolError(err.Error())
	}
	res, err := s.scans.TakeoverScan(ctx, args.Domains, args.Timeout)
	if err != nil {
		return toolError("接管检测失败: " + err.Error())
	}
	return toolOK(res)
}

func (s *MCPService) scanNuclei(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	var args struct {
		Targets     []string `json:"targets"`
		Severity    string   `json:"severity"`
		TemplateIDs []string `json:"template_ids"`
		Tags        []string `json:"tags"`
		Timeout     int      `json:"timeout"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if err := s.ensureScanTargetsAllowed(ctx, key, args.Targets); err != nil {
		return toolError(err.Error())
	}
	res, err := s.scans.NucleiScan(ctx, args.Targets, args.Severity, args.TemplateIDs, args.Tags, args.Timeout)
	if err != nil {
		return toolError("nuclei 扫描失败: " + err.Error())
	}
	return toolOK(res)
}
