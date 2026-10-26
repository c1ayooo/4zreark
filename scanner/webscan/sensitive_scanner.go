package webscan

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/config"
)

// SensitiveResult represents sensitive information detection result
type SensitiveResult struct {
	Target   string             `json:"target"`
	URL      string             `json:"url"`
	Found    int                `json:"found"`
	Findings []SensitiveFinding `json:"findings"`
	ScanTime time.Duration      `json:"scan_time_ms"`
}

// SensitiveFinding represents a single sensitive information finding
type SensitiveFinding struct {
	Type       string   `json:"type"`
	Pattern    string   `json:"pattern"`
	Matches    []string `json:"matches"`
	Location   string   `json:"location"` // url, body, header, js
	Severity   string   `json:"severity"`
	Confidence int      `json:"confidence"`
}

// SensitivePattern represents a sensitive information pattern
type SensitivePattern struct {
	Name     string
	Pattern  string
	Type     string
	Severity string
	Regex    *regexp.Regexp
}

// Global sensitive patterns (loaded once)
var sensitivePatterns map[string]*SensitivePattern
var sensitivePatternOnce sync.Once

// loadSensitivePatternsFromConfig loads sensitive patterns from configuration
func loadSensitivePatternsFromConfig() map[string]*SensitivePattern {
	patterns := make(map[string]*SensitivePattern)
	vulnConfig := config.GetVulnConfig()

	if vulnConfig != nil && len(vulnConfig.SensitivePatterns) > 0 {
		for _, p := range vulnConfig.SensitivePatterns {
			regex, err := regexp.Compile(p.Pattern)
			if err != nil {
				continue
			}
			patterns[p.Name] = &SensitivePattern{
				Name:     p.Name,
				Pattern:  p.Pattern,
				Type:     "sensitive",
				Severity: p.Severity,
				Regex:    regex,
			}
		}
	}

	// Add minimal defaults if no config
	if len(patterns) == 0 {
		patterns = getDefaultSensitivePatterns()
	}

	return patterns
}

// getDefaultSensitivePatterns 返回内置缺省规则集。
// 选取标准是「结构强特征」：云厂商密钥格式、带凭据的连接串、私钥块——
// 误报率低，不依赖 config 注入也能覆盖最常见的泄露面。
// 配置了 vuln.sensitive_patterns 时完全以配置为准（不合并），沿用原语义。
func getDefaultSensitivePatterns() map[string]*SensitivePattern {
	patterns := map[string]*SensitivePattern{
		"password_field": {
			Name:     "password_field",
			Pattern:  `(?i)(password|passwd|pwd|secret)\s*[=:]\s*['"]([^'"]+)['"]`,
			Type:     "credential",
			Severity: "high",
		},
		"api_key": {
			Name:     "api_key",
			Pattern:  `(?i)(api[_-]?key|apikey)\s*[=:]\s*['"]([a-zA-Z0-9_-]{16,})['"]`,
			Type:     "credential",
			Severity: "high",
		},
		"client_secret": {
			Name:     "client_secret",
			Pattern:  `(?i)client_secret\s*[=:]\s*['"][a-zA-Z0-9_\-]{20,}['"]`,
			Type:     "credential",
			Severity: "high",
		},
		"private_key": {
			Name:     "private_key",
			Pattern:  `-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----`,
			Type:     "credential",
			Severity: "critical",
		},
		"aws_access_key": {
			Name:     "aws_access_key",
			Pattern:  `\bAKIA[0-9A-Z]{16}\b`,
			Type:     "credential",
			Severity: "high",
		},
		"aws_secret_key": {
			Name:     "aws_secret_key",
			Pattern:  `(?i)aws_secret_access_key\s*[=:]\s*['"][a-zA-Z0-9/+=]{40}['"]`,
			Type:     "credential",
			Severity: "high",
		},
		"google_api_key": {
			Name:     "google_api_key",
			Pattern:  `\bAIza[0-9A-Za-z\-_]{35}\b`,
			Type:     "credential",
			Severity: "high",
		},
		"alibaba_access_key": {
			// 阿里云 AccessKey：LTAI 前缀（含 LTAI4/LTAI5 代次）
			Name:     "alibaba_access_key",
			Pattern:  `\bLTAI[0-9A-Za-z]{12,28}\b`,
			Type:     "credential",
			Severity: "high",
		},
		"tencent_secret_id": {
			// 腾讯云 SecretId：AKID 前缀
			Name:     "tencent_secret_id",
			Pattern:  `\bAKID[A-Za-z0-9]{30,44}\b`,
			Type:     "credential",
			Severity: "high",
		},
		"github_token": {
			// ghp_ 经典 PAT 与 github_pat_ 细粒度令牌
			Name:     "github_token",
			Pattern:  `\b(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{60,})\b`,
			Type:     "credential",
			Severity: "critical",
		},
		"slack_token": {
			Name:     "slack_token",
			Pattern:  `\bxox[abprs]-[0-9a-zA-Z-]{10,}\b`,
			Type:     "credential",
			Severity: "high",
		},
		"jwt_token": {
			// 页面里硬编码的 JWT（三段式 base64url）；常态出现在调试页/前端源码
			Name:     "jwt_token",
			Pattern:  `\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`,
			Type:     "credential",
			Severity: "medium",
		},
		"connection_uri_with_credentials": {
			// 带凭据的数据库/消息队列连接串：user:pass@host
			Name:     "connection_uri_with_credentials",
			Pattern:  `(?i)\b(mongodb(\+srv)?|mysql|postgres(ql)?|redis|amqps?|mssql|jdbc:[a-z0-9]+)://[^\s'"@<]+:[^\s'"@<]+@[^\s'"<]+`,
			Type:     "credential",
			Severity: "critical",
		},
		"id_card_cn": {
			// 18 位身份证（19/20 世纪出生段 + 校验位形态），用于页面泄露 PII
			Name:     "id_card_cn",
			Pattern:  `\b[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:[0-2]\d|3[01])\d{3}[\dXx]\b`,
			Type:     "pii",
			Severity: "medium",
		},
		"email": {
			Name:     "email",
			Pattern:  `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`,
			Type:     "pii",
			Severity: "low",
		},
	}

	// Compile regex
	for _, p := range patterns {
		p.Regex = regexp.MustCompile(p.Pattern)
	}

	return patterns
}

// getSensitivePatterns returns the sensitive patterns, loading if needed
func getSensitivePatterns() map[string]*SensitivePattern {
	sensitivePatternOnce.Do(func() {
		sensitivePatterns = loadSensitivePatternsFromConfig()
	})
	return sensitivePatterns
}

// ScanSensitiveInfo scans for sensitive information in a URL
func (s *ContentScanner) ScanSensitiveInfo(ctx context.Context, target string) *SensitiveResult {
	start := time.Now()
	result := &SensitiveResult{
		Target:   target,
		Findings: make([]SensitiveFinding, 0),
	}

	// Normalize URL
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}
	result.URL = target

	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		result.ScanTime = time.Since(start) / time.Millisecond
		return result
	}
	req.Header.Set("User-Agent", s.UserAgent)

	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		result.ScanTime = time.Since(start) / time.Millisecond
		return result
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		result.ScanTime = time.Since(start) / time.Millisecond
		return result
	}
	bodyStr := string(body)

	// Get sensitive patterns from config
	patterns := getSensitivePatterns()

	// Check body for sensitive patterns
	for name, pattern := range patterns {
		matches := pattern.Regex.FindAllString(bodyStr, 10) // Limit to 10 matches
		if len(matches) > 0 {
			// Deduplicate
			seen := make(map[string]bool)
			uniqueMatches := make([]string, 0)
			for _, m := range matches {
				if !seen[m] && len(m) < 200 { // Skip very long matches
					seen[m] = true
					uniqueMatches = append(uniqueMatches, m)
				}
			}

			if len(uniqueMatches) > 0 {
				result.Findings = append(result.Findings, SensitiveFinding{
					Type:       pattern.Type,
					Pattern:    name,
					Matches:    uniqueMatches,
					Location:   "body",
					Severity:   pattern.Severity,
					Confidence: 70,
				})
				result.Found += len(uniqueMatches)
			}
		}
	}

	// Check for server version disclosure in headers
	if serverHeader := resp.Header.Get("Server"); serverHeader != "" {
		if strings.Contains(serverHeader, "/") {
			result.Findings = append(result.Findings, SensitiveFinding{
				Type:       "info",
				Pattern:    "server_version",
				Matches:    []string{serverHeader},
				Location:   "header",
				Severity:   "info",
				Confidence: 90,
			})
			result.Found++
		}
	}

	// Check X-Powered-By
	if poweredBy := resp.Header.Get("X-Powered-By"); poweredBy != "" {
		result.Findings = append(result.Findings, SensitiveFinding{
			Type:       "info",
			Pattern:    "powered_by",
			Matches:    []string{poweredBy},
			Location:   "header",
			Severity:   "info",
			Confidence: 90,
		})
		result.Found++
	}

	// Sort by severity
	severityOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
	sort.Slice(result.Findings, func(i, j int) bool {
		return severityOrder[result.Findings[i].Severity] < severityOrder[result.Findings[j].Severity]
	})

	result.ScanTime = time.Since(start) / time.Millisecond
	return result
}

// BatchScanSensitive scans multiple URLs for sensitive information
func (s *ContentScanner) BatchScanSensitive(ctx context.Context, targets []string) []*SensitiveResult {
	results := make([]*SensitiveResult, len(targets))
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, s.Concurrency)
	var mu sync.Mutex

	for i, target := range targets {
		wg.Add(1)
		semaphore <- struct{}{}

		go func(idx int, t string) {
			defer wg.Done()
			defer func() { <-semaphore }()

			result := s.ScanSensitiveInfo(ctx, t)

			mu.Lock()
			results[idx] = result
			mu.Unlock()
		}(i, target)
	}

	wg.Wait()
	return results
}
