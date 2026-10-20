package fingerprint

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// DSLEngine 指纹识别 DSL 引擎
type DSLEngine struct {
	Rules    map[string]*FingerprintRule
	mu       sync.RWMutex
	compiled map[string]*regexp.Regexp
}

// NewDSLEngine 创建新的 DSL 引擎
func NewDSLEngine() *DSLEngine {
	return &DSLEngine{
		Rules:    make(map[string]*FingerprintRule),
		compiled: make(map[string]*regexp.Regexp),
	}
}

// LoadRulesFromFile 从单个文件加载规则
func (e *DSLEngine) LoadRulesFromFile(filePath string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %w", filePath, err)
	}

	var rules map[string]*FingerprintRule
	if err := yaml.Unmarshal(data, &rules); err != nil {
		return fmt.Errorf("failed to parse YAML %s: %w", filePath, err)
	}

	for name, rule := range rules {
		if rule == nil {
			continue
		}
		rule.ID = name
		rule.Name = name
		if rule.Condition == "" {
			rule.Condition = "or"
		}
		e.Rules[name] = rule
	}

	return nil
}

// LoadRulesFromDir 从目录加载所有规则文件
func (e *DSLEngine) LoadRulesFromDir(dirPath string) error {
	return filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".yaml" || ext == ".yml" {
			if loadErr := e.LoadRulesFromFile(path); loadErr != nil {
				fmt.Printf("Warning: failed to load rules from %s: %v\n", path, loadErr)
			}
		}
		return nil
	})
}

// RulesCount 返回已加载的规则数量
func (e *DSLEngine) RulesCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.Rules)
}

// AnalyzeResponse 分析 HTTP 响应并返回匹配的指纹
func (e *DSLEngine) AnalyzeResponse(resp *HTTPResponse) []*FingerprintMatch {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if resp == nil {
		return nil
	}

	matches := make([]*FingerprintMatch, 0)
	seen := make(map[string]bool)

	for _, rule := range e.Rules {
		if match := e.matchRule(resp, rule); match != nil {
			if !seen[rule.Name] {
				seen[rule.Name] = true
				matches = append(matches, match)
			}
		}
	}

	return matches
}

// matchRule 检查响应是否匹配规则
func (e *DSLEngine) matchRule(resp *HTTPResponse, rule *FingerprintRule) *FingerprintMatch {
	if len(rule.DSL) == 0 {
		return nil
	}

	matchedDSLs := make([]string, 0)
	isAnd := strings.ToLower(rule.Condition) == "and"

	for _, dsl := range rule.DSL {
		matched := e.evaluateDSL(dsl, resp)
		if matched {
			matchedDSLs = append(matchedDSLs, dsl)
			if !isAnd {
				// OR 条件：匹配一个即可
				break
			}
		} else if isAnd {
			// AND 条件：必须全部匹配
			return nil
		}
	}

	if len(matchedDSLs) == 0 {
		return nil
	}

	// 根据匹配的 DSL 数量计算置信度
	confidence := 70
	if len(matchedDSLs) >= 2 {
		confidence = 85
	}
	if isAnd && len(matchedDSLs) == len(rule.DSL) {
		confidence = 95
	}

	// 解析标签
	var tags []string
	if rule.Tags != "" {
		tags = strings.Split(rule.Tags, ",")
		for i := range tags {
			tags[i] = strings.TrimSpace(tags[i])
		}
	}

	return &FingerprintMatch{
		URL:        resp.URL,
		RuleName:   rule.Name,
		Technology: rule.Name,
		DSLMatched: matchedDSLs,
		Category:   rule.Category,
		Tags:       tags,
		Confidence: confidence,
		Method:     "dsl",
	}
}

// evaluateDSL 评估单个 DSL 表达式
func (e *DSLEngine) evaluateDSL(dsl string, resp *HTTPResponse) bool {
	dsl = strings.TrimSpace(dsl)

	// 解析 DSL 函数
	if strings.HasPrefix(dsl, "contains(") {
		return e.evalContains(dsl, resp)
	}
	if strings.HasPrefix(dsl, "contains_all(") {
		return e.evalContainsAll(dsl, resp)
	}
	if strings.HasPrefix(dsl, "contains_any(") {
		return e.evalContainsAny(dsl, resp)
	}
	if strings.HasPrefix(dsl, "title(") {
		return e.evalTitle(dsl, resp)
	}
	if strings.HasPrefix(dsl, "icon(") {
		return e.evalIcon(dsl, resp)
	}
	if strings.HasPrefix(dsl, "status(") {
		return e.evalStatus(dsl, resp)
	}
	if strings.HasPrefix(dsl, "regex(") {
		return e.evalRegex(dsl, resp)
	}
	if strings.HasPrefix(dsl, "header(") {
		return e.evalHeader(dsl, resp)
	}

	return false
}

// evalContains 评估 contains(target, value1, value2, ...)
// 如果 target 包含任意一个 value 则返回 true
func (e *DSLEngine) evalContains(dsl string, resp *HTTPResponse) bool {
	args := e.parseDSLArgs(dsl, "contains")
	if len(args) < 2 {
		return false
	}

	source := strings.ToLower(strings.Trim(args[0], "'\""))
	var content string

	switch source {
	case "body":
		content = strings.ToLower(resp.Body)
	case "header", "headers":
		content = strings.ToLower(resp.GetAllHeaders())
	case "title":
		content = strings.ToLower(resp.Title)
	case "server":
		content = strings.ToLower(resp.GetHeader("Server"))
	case "url":
		content = strings.ToLower(resp.URL)
	default:
		return false
	}

	// 检查任意一个模式是否匹配（OR 逻辑）
	for i := 1; i < len(args); i++ {
		pattern := strings.ToLower(strings.Trim(args[i], "'\""))
		if strings.Contains(content, pattern) {
			return true
		}
	}

	return false
}

// evalContainsAll 评估 contains_all(target, value1, value2, ...)
// 如果 target 包含所有 value 则返回 true
func (e *DSLEngine) evalContainsAll(dsl string, resp *HTTPResponse) bool {
	args := e.parseDSLArgs(dsl, "contains_all")
	if len(args) < 2 {
		return false
	}

	source := strings.ToLower(strings.Trim(args[0], "'\""))
	var content string

	switch source {
	case "body":
		content = strings.ToLower(resp.Body)
	case "header", "headers":
		content = strings.ToLower(resp.GetAllHeaders())
	case "title":
		content = strings.ToLower(resp.Title)
	case "server":
		content = strings.ToLower(resp.GetHeader("Server"))
	case "url":
		content = strings.ToLower(resp.URL)
	default:
		return false
	}

	// 检查所有模式是否都匹配（AND 逻辑）
	for i := 1; i < len(args); i++ {
		pattern := strings.ToLower(strings.Trim(args[i], "'\""))
		if !strings.Contains(content, pattern) {
			return false
		}
	}

	return true
}

// evalContainsAny 与 contains 相同
func (e *DSLEngine) evalContainsAny(dsl string, resp *HTTPResponse) bool {
	newDSL := "contains" + dsl[len("contains_any"):]
	return e.evalContains(newDSL, resp)
}

// evalTitle 评估 title('value')
func (e *DSLEngine) evalTitle(dsl string, resp *HTTPResponse) bool {
	args := e.parseDSLArgs(dsl, "title")
	if len(args) < 1 {
		return false
	}

	titleLower := strings.ToLower(resp.Title)
	patternLower := strings.ToLower(strings.Trim(args[0], "'\""))

	return strings.Contains(titleLower, patternLower)
}

// evalIcon 评估 icon('/path', 'hash') 或 icon('/path', 'hash1', 'hash2', ...)
func (e *DSLEngine) evalIcon(dsl string, resp *HTTPResponse) bool {
	args := e.parseDSLArgs(dsl, "icon")
	if len(args) < 2 {
		return false
	}

	// 跳过第一个参数（path），检查 hash 值
	for i := 1; i < len(args); i++ {
		hash := strings.Trim(args[i], "'\"")
		if resp.IconHash == hash || resp.IconMD5 == hash {
			return true
		}
	}

	return false
}

// evalStatus 评估 status(code)
func (e *DSLEngine) evalStatus(dsl string, resp *HTTPResponse) bool {
	args := e.parseDSLArgs(dsl, "status")
	if len(args) < 1 {
		return false
	}

	code, err := strconv.Atoi(strings.TrimSpace(args[0]))
	if err != nil {
		return false
	}

	return resp.StatusCode == code
}

// evalRegex 评估 regex(target, pattern)
func (e *DSLEngine) evalRegex(dsl string, resp *HTTPResponse) bool {
	args := e.parseDSLArgs(dsl, "regex")
	if len(args) < 2 {
		return false
	}

	target := strings.ToLower(strings.Trim(args[0], "'\""))
	pattern := strings.Trim(args[1], "'\"")

	var content string
	switch target {
	case "body":
		content = resp.Body
	case "header", "headers":
		content = resp.GetAllHeaders()
	case "title":
		content = resp.Title
	default:
		content = resp.Body
	}

	// 使用缓存的正则表达式或编译新的
	re, ok := e.compiled[pattern]
	if !ok {
		var err error
		re, err = regexp.Compile("(?i)" + pattern)
		if err != nil {
			return false
		}
		e.compiled[pattern] = re
	}

	return re.MatchString(content)
}

// evalHeader 评估 header(name, value) 或 header('value')
func (e *DSLEngine) evalHeader(dsl string, resp *HTTPResponse) bool {
	args := e.parseDSLArgs(dsl, "header")
	if len(args) < 1 {
		return false
	}

	if len(args) == 1 {
		// 检查任意 header 中是否包含该值
		value := strings.ToLower(strings.Trim(args[0], "'\""))
		headerStr := strings.ToLower(resp.GetAllHeaders())
		return strings.Contains(headerStr, value)
	}

	// 检查指定 header 是否包含指定值
	headerName := strings.Trim(args[0], "'\"")
	headerValue := strings.ToLower(resp.GetHeader(headerName))
	pattern := strings.ToLower(strings.Trim(args[1], "'\""))

	return strings.Contains(headerValue, pattern)
}

// parseDSLArgs 解析 DSL 函数的参数
func (e *DSLEngine) parseDSLArgs(dsl, funcName string) []string {
	prefix := funcName + "("
	if !strings.HasPrefix(dsl, prefix) {
		return nil
	}

	content := dsl[len(prefix):]
	if idx := strings.LastIndex(content, ")"); idx >= 0 {
		content = content[:idx]
	}

	// 解析参数，处理带引号的字符串
	args := make([]string, 0)
	var current strings.Builder
	inQuote := false
	quoteChar := byte(0)

	for i := 0; i < len(content); i++ {
		c := content[i]

		if !inQuote && (c == '\'' || c == '"') {
			inQuote = true
			quoteChar = c
			current.WriteByte(c)
		} else if inQuote && c == quoteChar {
			inQuote = false
			quoteChar = 0
			current.WriteByte(c)
		} else if !inQuote && c == ',' {
			arg := strings.TrimSpace(current.String())
			if arg != "" {
				args = append(args, arg)
			}
			current.Reset()
		} else {
			current.WriteByte(c)
		}
	}

	// 添加最后一个参数
	if current.Len() > 0 {
		arg := strings.TrimSpace(current.String())
		if arg != "" {
			args = append(args, arg)
		}
	}

	return args
}

// GetRule 根据名称获取规则
func (e *DSLEngine) GetRule(name string) *FingerprintRule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.Rules[name]
}

// ListRules 列出所有规则名称
func (e *DSLEngine) ListRules() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	names := make([]string, 0, len(e.Rules))
	for name := range e.Rules {
		names = append(names, name)
	}
	return names
}
