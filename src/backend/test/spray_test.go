package test

import (
	"context"
	"encoding/json"
	"github.com/c1ayooo/4zreark/scanner/webscan"
	"testing"
	"time"
)

// TestSprayScanner 测试 Spray 扫描器基本功能
func TestSprayScanner(t *testing.T) {
	scanner := webscan.NewSprayScanner()

	// 检查二进制文件路径
	if scanner.BinPath == "" {
		t.Skip("Spray binary not found, skipping test")
	}

	t.Logf("Spray binary path: %s", scanner.BinPath)
	t.Logf("Spray available: %v", scanner.IsAvailable())

	if !scanner.IsAvailable() {
		t.Skip("Spray is not available, skipping test")
	}
}

// TestSprayScan 测试实际扫描
func TestSprayScan(t *testing.T) {
	requireLiveNetwork(t)
	scanner := webscan.NewSprayScanner()

	if !scanner.IsAvailable() {
		t.Skip("Spray is not available, skipping test")
	}

	// 测试扫描 example.com
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	result, err := scanner.Scan(ctx, "https://example.com")
	if err != nil {
		t.Logf("Scan returned error (may be expected): %v", err)
	}

	if result != nil {
		t.Logf("Scan found %d results", len(result.Results))
		t.Logf("Duration: %s", result.Duration)

		// 打印前几个结果
		for i, entry := range result.Results {
			if i >= 5 {
				break
			}
			t.Logf("Result %d: URL=%s, Status=%d, BodyLength=%d, Title=%s",
				i, entry.URL, entry.StatusCode, entry.BodyLength, entry.Title)

			if len(entry.Frameworks) > 0 {
				frameworksJSON, _ := json.Marshal(entry.Frameworks)
				t.Logf("  Frameworks: %s", string(frameworksJSON))
			}
		}
	}
}

// TestSprayBatchScan 测试批量扫描
func TestSprayBatchScan(t *testing.T) {
	requireLiveNetwork(t)
	scanner := webscan.NewSprayScanner()

	if !scanner.IsAvailable() {
		t.Skip("Spray is not available, skipping test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	targets := []string{
		"https://example.com",
		"https://example.org",
	}

	result, err := scanner.ScanBatch(ctx, targets)
	if err != nil {
		t.Logf("Batch scan error (may be expected): %v", err)
	}

	if result != nil {
		t.Logf("Batch scan found %d total results", len(result.Results))

		for i, entry := range result.Results {
			if i >= 5 {
				break
			}
			t.Logf("Result %d: URL=%s, Status=%d", i, entry.URL, entry.StatusCode)
		}
	}
}

// TestSprayJSONParsing 测试 JSON 解析
func TestSprayJSONParsing(t *testing.T) {
	// 模拟 spray 输出
	testJSON := `{"number":0,"parent":0,"valid":true,"fuzzy":false,"url":"https://example.com/","path":"","status":200,"body_length":1256,"header_length":325,"content_type":"html","title":"Example Domain","frameworks":{"alt-svc":{"name":"alt-svc"}},"extracts":null,"error":"","reason":"","source":3,"depth":0,"unique":19068,"hashes":{"md5":"9b36b13b7e90a4542a82d8a08be3932e","mmh3":"-2087618365"}}`

	var output webscan.SprayJSONOutput
	err := json.Unmarshal([]byte(testJSON), &output)
	if err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	// 验证解析结果
	if output.URL != "https://example.com/" {
		t.Errorf("URL mismatch: expected 'https://example.com/', got '%s'", output.URL)
	}

	if output.Status != 200 {
		t.Errorf("Status mismatch: expected 200, got %d", output.Status)
	}

	if output.BodyLength != 1256 {
		t.Errorf("BodyLength mismatch: expected 1256, got %d", output.BodyLength)
	}

	if output.Title != "Example Domain" {
		t.Errorf("Title mismatch: expected 'Example Domain', got '%s'", output.Title)
	}

	if output.ContentType != "html" {
		t.Errorf("ContentType mismatch: expected 'html', got '%s'", output.ContentType)
	}

	// 验证 frameworks
	if output.Frameworks == nil {
		t.Error("Frameworks should not be nil")
	} else if _, ok := output.Frameworks["alt-svc"]; !ok {
		t.Error("Frameworks should contain 'alt-svc'")
	}

	// 验证 hashes
	if output.Hashes == nil {
		t.Error("Hashes should not be nil")
	} else {
		if md5, ok := output.Hashes["md5"]; !ok || md5 != "9b36b13b7e90a4542a82d8a08be3932e" {
			t.Errorf("MD5 hash mismatch")
		}
	}

	t.Log("JSON parsing test passed!")
}
