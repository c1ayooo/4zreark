package test

import (
	"testing"

	"github.com/c1ayooo/4zreark/scanner/fingerprint"
)

// ==================== DSL 引擎基础测试 ====================
//
// T13：finger.yaml 已退役，规则匹配的完整矩阵在
// scanner/fingerprint/t8_characterization_test.go 与 t10_engine_test.go 里。
// 这里只保留引擎初始化/加载错误/空输入的契约测试。

func TestDSLEngine_NewEngine(t *testing.T) {
	engine := fingerprint.NewDSLEngine()
	if engine == nil {
		t.Fatal("NewDSLEngine returned nil")
	}
	if engine.RulesCount() != 0 {
		t.Errorf("New engine should have 0 rules, got %d", engine.RulesCount())
	}
}

func TestDSLEngine_LoadRulesFromFile(t *testing.T) {
	engine := fingerprint.NewDSLEngine()

	if err := engine.LoadRulesFromFile("/nonexistent/file.yaml"); err == nil {
		t.Error("Should return error for nonexistent file")
	}

	// 用 T8 的固定规则样本验证 YAML 加载路径仍然可用。
	if err := engine.LoadRulesFromFile("../scanner/fingerprint/testdata/t8_rules.yaml"); err != nil {
		t.Fatalf("Failed to load testdata rules: %v", err)
	}
	if got := engine.RulesCount(); got != 5 {
		t.Errorf("RulesCount = %d, want 5", got)
	}
}

func TestDSLEngine_AnalyzeResponse_NilResponse(t *testing.T) {
	engine := fingerprint.NewDSLEngine()
	matches := engine.AnalyzeResponse(nil)
	if len(matches) > 0 {
		t.Error("nil response should return empty matches")
	}
}

func TestDSLEngine_AnalyzeResponse_EmptyRules(t *testing.T) {
	engine := fingerprint.NewDSLEngine()
	resp := &fingerprint.HTTPResponse{
		StatusCode: 200,
		Headers:    map[string]string{"Server": "nginx"},
		Body:       "<html></html>",
	}
	if matches := engine.AnalyzeResponse(resp); len(matches) != 0 {
		t.Errorf("Empty rules should return 0 matches, got %d", len(matches))
	}
}
