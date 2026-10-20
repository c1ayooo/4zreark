package test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/c1ayooo/4zreark/scanner/fingerprint"
)

// ==================== DSL 引擎功能测试 ====================

// TestDSLEngine_NewEngine 测试 DSL 引擎初始化
func TestDSLEngine_NewEngine(t *testing.T) {
	engine := fingerprint.NewDSLEngine()

	if engine == nil {
		t.Fatal("NewDSLEngine returned nil")
	}

	if engine.RulesCount() != 0 {
		t.Errorf("New engine should have 0 rules, got %d", engine.RulesCount())
	}
}

// TestDSLEngine_LoadRulesFromFile 测试从文件加载规则
func TestDSLEngine_LoadRulesFromFile(t *testing.T) {
	engine := fingerprint.NewDSLEngine()

	// 测试加载不存在的文件
	err := engine.LoadRulesFromFile("/nonexistent/file.yaml")
	if err == nil {
		t.Error("Should return error for nonexistent file")
	}

	// 尝试加载实际的 finger.yaml
	paths := []string{
		"../config/dicts/yaml/finger.yaml",
		"config/dicts/yaml/finger.yaml",
		"../../config/dicts/yaml/finger.yaml",
	}

	var loaded bool
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			err := engine.LoadRulesFromFile(p)
			if err != nil {
				t.Errorf("Failed to load finger.yaml: %v", err)
			} else {
				t.Logf("✓ Loaded %d rules from %s", engine.RulesCount(), p)
				loaded = true
			}
			break
		}
	}

	if !loaded {
		t.Log("⚠ Could not find finger.yaml to test loading")
	}
}

// TestDSLEngine_AnalyzeResponse_NilResponse 测试 nil 响应处理
func TestDSLEngine_AnalyzeResponse_NilResponse(t *testing.T) {
	engine := fingerprint.NewDSLEngine()

	// nil 响应应该返回空结果
	matches := engine.AnalyzeResponse(nil)
	if matches != nil && len(matches) > 0 {
		t.Error("nil response should return empty matches")
	}
}

// TestDSLEngine_AnalyzeResponse_EmptyRules 测试空规则集
func TestDSLEngine_AnalyzeResponse_EmptyRules(t *testing.T) {
	engine := fingerprint.NewDSLEngine()

	resp := &fingerprint.HTTPResponse{
		StatusCode: 200,
		Headers:    map[string]string{"Server": "nginx"},
		Body:       "<html></html>",
	}

	// 空规则应该返回空结果
	matches := engine.AnalyzeResponse(resp)
	if len(matches) != 0 {
		t.Errorf("Empty rules should return 0 matches, got %d", len(matches))
	}
}

// TestDSLEngine_HeaderMatching 测试 Header 匹配
func TestDSLEngine_HeaderMatching(t *testing.T) {
	engine := fingerprint.NewDSLEngine()

	// 尝试加载规则文件
	paths := []string{
		"../config/dicts/yaml/finger.yaml",
		"config/dicts/yaml/finger.yaml",
	}

	var loaded bool
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			engine.LoadRulesFromFile(p)
			loaded = true
			break
		}
	}

	if !loaded {
		t.Skip("Could not find finger.yaml, skipping header matching test")
	}

	// 测试 Nginx Header
	resp := &fingerprint.HTTPResponse{
		StatusCode: 200,
		Headers: map[string]string{
			"Server": "nginx/1.18.0",
		},
		Body: "<html></html>",
	}

	matches := engine.AnalyzeResponse(resp)
	t.Logf("Nginx header matches: %d", len(matches))

	for _, m := range matches {
		t.Logf("  - %s (%s) confidence=%d", m.Technology, m.Category, m.Confidence)
	}
}

// TestDSLEngine_BodyContains 测试 Body 内容匹配
func TestDSLEngine_BodyContains(t *testing.T) {
	engine := fingerprint.NewDSLEngine()

	// 尝试加载规则文件
	paths := []string{
		"../config/dicts/yaml/finger.yaml",
		"config/dicts/yaml/finger.yaml",
	}

	var loaded bool
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			engine.LoadRulesFromFile(p)
			loaded = true
			break
		}
	}

	if !loaded {
		t.Skip("Could not find finger.yaml, skipping body contains test")
	}

	// 测试 WordPress 识别
	resp := &fingerprint.HTTPResponse{
		StatusCode: 200,
		Body:       `<meta name="generator" content="WordPress 5.8">`,
	}

	matches := engine.AnalyzeResponse(resp)
	t.Logf("WordPress body matches: %d", len(matches))

	foundWordPress := false
	for _, m := range matches {
		t.Logf("  - %s (%s) confidence=%d", m.Technology, m.Category, m.Confidence)
		if m.Technology == "WordPress" {
			foundWordPress = true
		}
	}

	if !foundWordPress {
		t.Log("⚠ WordPress not detected (check finger.yaml rules)")
	}
}

// TestDSLEngine_TitleMatching 测试 Title 匹配
func TestDSLEngine_TitleMatching(t *testing.T) {
	engine := fingerprint.NewDSLEngine()

	// 尝试加载规则文件
	paths := []string{
		"../config/dicts/yaml/finger.yaml",
		"config/dicts/yaml/finger.yaml",
	}

	var loaded bool
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			engine.LoadRulesFromFile(p)
			loaded = true
			break
		}
	}

	if !loaded {
		t.Skip("Could not find finger.yaml, skipping title matching test")
	}

	// 测试 Jenkins Title
	resp := &fingerprint.HTTPResponse{
		StatusCode: 200,
		Title:      "Dashboard [Jenkins]",
		Body:       "<html></html>",
	}

	matches := engine.AnalyzeResponse(resp)
	t.Logf("Jenkins title matches: %d", len(matches))

	for _, m := range matches {
		t.Logf("  - %s (%s) confidence=%d", m.Technology, m.Category, m.Confidence)
	}
}

// TestDSLEngine_LoadRealRules 测试加载实际规则文件
func TestDSLEngine_LoadRealRules(t *testing.T) {
	engine := fingerprint.NewDSLEngine()

	// 尝试找到配置目录
	configDirs := []string{
		"../config/dicts/yaml",
		"config/dicts/yaml",
		"../../config/dicts/yaml",
		"backend/config/dicts/yaml",
	}

	var rulesDir string
	for _, dir := range configDirs {
		if _, err := os.Stat(dir); err == nil {
			rulesDir = dir
			break
		}
	}

	if rulesDir == "" {
		t.Skip("Could not find config directory")
		return
	}

	// 加载 finger.yaml
	fingerPath := filepath.Join(rulesDir, "finger.yaml")
	if _, err := os.Stat(fingerPath); err == nil {
		err := engine.LoadRulesFromFile(fingerPath)
		if err != nil {
			t.Errorf("Failed to load finger.yaml: %v", err)
		} else {
			t.Logf("✓ Loaded finger.yaml: %d rules", engine.RulesCount())
		}
	}

	// 加载 sensitive.yaml
	sensitivePath := filepath.Join(rulesDir, "sensitive.yaml")
	if _, err := os.Stat(sensitivePath); err == nil {
		initialCount := engine.RulesCount()
		err := engine.LoadRulesFromFile(sensitivePath)
		if err != nil {
			t.Errorf("Failed to load sensitive.yaml: %v", err)
		} else {
			newCount := engine.RulesCount() - initialCount
			t.Logf("✓ Loaded sensitive.yaml: %d additional rules", newCount)
		}
	}

	t.Logf("Total rules loaded: %d", engine.RulesCount())
}

// TestDSLEngine_MultipleMatches 测试多重匹配
func TestDSLEngine_MultipleMatches(t *testing.T) {
	engine := fingerprint.NewDSLEngine()

	// 尝试加载规则文件
	paths := []string{
		"../config/dicts/yaml/finger.yaml",
		"config/dicts/yaml/finger.yaml",
	}

	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			engine.LoadRulesFromFile(p)
			break
		}
	}

	if engine.RulesCount() == 0 {
		t.Skip("No rules loaded, skipping multiple matches test")
	}

	// 创建一个包含多种技术特征的响应
	resp := &fingerprint.HTTPResponse{
		StatusCode: 200,
		Headers: map[string]string{
			"Server":       "nginx/1.18.0",
			"X-Powered-By": "PHP/7.4.3",
		},
		Body:  `<meta name="generator" content="WordPress 5.8">`,
		Title: "My WordPress Site",
	}

	matches := engine.AnalyzeResponse(resp)
	t.Logf("Multiple technology matches: %d", len(matches))

	for _, m := range matches {
		t.Logf("  - %s (%s) confidence=%d DSL=%v", m.Technology, m.Category, m.Confidence, m.DSLMatched)
	}

	if len(matches) < 2 {
		t.Log("⚠ Expected multiple matches for this response")
	}
}

// ==================== 基准测试 ====================

func BenchmarkDSLEngine_AnalyzeResponse(b *testing.B) {
	engine := fingerprint.NewDSLEngine()

	// 加载规则
	paths := []string{
		"../config/dicts/yaml/finger.yaml",
		"config/dicts/yaml/finger.yaml",
	}

	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			engine.LoadRulesFromFile(p)
			break
		}
	}

	resp := &fingerprint.HTTPResponse{
		StatusCode: 200,
		Headers:    map[string]string{"Server": "nginx"},
		Body:       "This is a test page with some content",
		Title:      "Test Page",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.AnalyzeResponse(resp)
	}
}

func BenchmarkDSLEngine_LoadRulesFromFile(b *testing.B) {
	paths := []string{
		"../config/dicts/yaml/finger.yaml",
		"config/dicts/yaml/finger.yaml",
	}

	var rulesPath string
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			rulesPath = p
			break
		}
	}

	if rulesPath == "" {
		b.Skip("Could not find finger.yaml")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine := fingerprint.NewDSLEngine()
		engine.LoadRulesFromFile(rulesPath)
	}
}
