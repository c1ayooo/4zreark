package test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/scanner/fingerprint"
)

// ==================== 指纹扫描器功能测试 ====================

// TestFingerprintScanner_NewScanner 测试扫描器初始化
func TestFingerprintScanner_NewScanner(t *testing.T) {
	scanner := fingerprint.NewFingerprintScanner(10)

	if scanner == nil {
		t.Fatal("NewFingerprintScanner returned nil")
	}

	// 测试 DSL 引擎加载
	if scanner.DSLEngine == nil {
		t.Error("DSLEngine is nil")
	} else {
		t.Logf("✓ Loaded %d fingerprint rules", scanner.DSLEngine.RulesCount())
	}

	// 测试 JS 库模式加载
	if len(scanner.JSLibPatterns) == 0 {
		t.Log("⚠ Warning: No JS library patterns loaded (jslib.yaml may not be found)")
	} else {
		t.Logf("✓ Loaded %d JS library patterns", len(scanner.JSLibPatterns))
	}

	// 测试端口服务映射加载
	if len(scanner.PortServices) == 0 {
		t.Log("⚠ Warning: No port services loaded (ports.yaml may not be found)")
	} else {
		t.Logf("✓ Loaded %d port services", len(scanner.PortServices))
	}

	// 测试 favicon 哈希加载
	if len(scanner.FaviconHashes) == 0 {
		t.Log("⚠ Warning: No favicon hashes loaded (favicon.yaml may not be found)")
	} else {
		t.Logf("✓ Loaded %d favicon hashes", len(scanner.FaviconHashes))
	}

	// 验证并发数
	if scanner.Concurrency != 10 {
		t.Errorf("Concurrency = %d, want 10", scanner.Concurrency)
	}

	// 测试默认并发数
	scanner2 := fingerprint.NewFingerprintScanner(0)
	if scanner2.Concurrency <= 0 {
		t.Error("Default concurrency should be > 0")
	}
}

// TestFingerprintScanner_PortServicesLoaded 测试端口服务映射加载
func TestFingerprintScanner_PortServicesLoaded(t *testing.T) {
	scanner := fingerprint.NewFingerprintScanner(10)

	// 如果没有加载配置，跳过测试
	if len(scanner.PortServices) == 0 {
		t.Skip("Port services not loaded, skipping test")
	}

	expectedPorts := map[int]string{
		22:    "ssh",
		80:    "http",
		443:   "https",
		3306:  "mysql",
		6379:  "redis",
		27017: "mongodb",
		21:    "ftp",
		25:    "smtp",
		5432:  "postgresql",
	}

	for port, expected := range expectedPorts {
		if got, ok := scanner.PortServices[port]; ok {
			if got != expected {
				t.Errorf("Port %d: got %s, want %s", port, got, expected)
			} else {
				t.Logf("✓ Port %d -> %s", port, got)
			}
		} else {
			t.Logf("⚠ Port %d not found in config", port)
		}
	}
}

// TestFingerprintScanner_WithMockServer 使用模拟服务器测试指纹扫描
func TestFingerprintScanner_WithMockServer(t *testing.T) {
	// 创建模拟 HTTP 服务器
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Server", "nginx/1.18.0")
			w.Header().Set("X-Powered-By", "PHP/7.4.3")
			w.WriteHeader(200)
			w.Write([]byte(`<!DOCTYPE html>
<html>
<head>
    <title>测试页面 - Test Page</title>
    <script src="/js/jquery-3.6.0.min.js"></script>
    <script src="/js/vue.min.js"></script>
</head>
<body>
    <h1>Welcome</h1>
    <p>Powered by WordPress</p>
</body>
</html>`))
		case "/favicon.ico":
			w.WriteHeader(404)
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()

	scanner := fingerprint.NewFingerprintScanner(5)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := scanner.ScanFingerprint(ctx, server.URL)

	t.Logf("=== 扫描结果 ===")
	t.Logf("Target: %s", result.Target)
	t.Logf("URL: %s", result.URL)
	t.Logf("Status Code: %d", result.StatusCode)
	t.Logf("Title: %s", result.Title)
	t.Logf("Server: %s", result.Server)
	t.Logf("Powered By: %s", result.PoweredBy)
	t.Logf("Body Length: %d", result.BodyLength)
	t.Logf("JS Libraries: %v", result.JSLibraries)
	t.Logf("Scan Time: %dms", result.ScanTime)

	// 验证基本结果
	if result.StatusCode != 200 {
		t.Errorf("Expected status 200, got %d", result.StatusCode)
	}

	if result.Title != "测试页面 - Test Page" {
		t.Errorf("Title mismatch: %s", result.Title)
	}

	if result.Server != "nginx/1.18.0" {
		t.Errorf("Server mismatch: %s", result.Server)
	}

	if result.PoweredBy != "PHP/7.4.3" {
		t.Errorf("PoweredBy mismatch: %s", result.PoweredBy)
	}

	// 打印指纹
	t.Logf("Fingerprints (%d):", len(result.Fingerprints))
	for _, fp := range result.Fingerprints {
		t.Logf("  - %s [%s] confidence=%d method=%s", fp.Name, fp.Category, fp.Confidence, fp.Method)
	}
}

// TestFingerprintScanner_NginxDetection 测试 Nginx 指纹识别
func TestFingerprintScanner_NginxDetection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		w.WriteHeader(200)
		w.Write([]byte(`<html><head><title>Nginx Welcome</title></head><body>Welcome to nginx!</body></html>`))
	}))
	defer server.Close()

	scanner := fingerprint.NewFingerprintScanner(5)
	ctx := context.Background()
	result := scanner.ScanFingerprint(ctx, server.URL)

	foundNginx := false
	for _, fp := range result.Fingerprints {
		if fp.Name == "Nginx" {
			foundNginx = true
			t.Logf("✓ Found Nginx fingerprint: confidence=%d method=%s", fp.Confidence, fp.Method)
		}
	}

	if !foundNginx {
		t.Log("⚠ Nginx fingerprint not detected (DSL rules may not be loaded)")
	}

	// 验证 Server header 被正确提取
	if result.Server != "nginx" {
		t.Errorf("Server header not extracted correctly: %s", result.Server)
	}
}

// TestFingerprintScanner_ApacheDetection 测试 Apache 指纹识别
func TestFingerprintScanner_ApacheDetection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.41 (Ubuntu)")
		w.WriteHeader(200)
		w.Write([]byte(`<html><head><title>Apache2 Default Page</title></head><body>It works!</body></html>`))
	}))
	defer server.Close()

	scanner := fingerprint.NewFingerprintScanner(5)
	ctx := context.Background()
	result := scanner.ScanFingerprint(ctx, server.URL)

	foundApache := false
	for _, fp := range result.Fingerprints {
		if fp.Name == "Apache" {
			foundApache = true
			t.Logf("✓ Found Apache fingerprint: confidence=%d method=%s", fp.Confidence, fp.Method)
		}
	}

	if !foundApache {
		t.Log("⚠ Apache fingerprint not detected")
	}
}

// TestFingerprintScanner_PHPDetection 测试 PHP 指纹识别
func TestFingerprintScanner_PHPDetection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/8.1.0")
		w.WriteHeader(200)
		w.Write([]byte(`<html><head><title>PHP Info</title></head><body>PHP Application</body></html>`))
	}))
	defer server.Close()

	scanner := fingerprint.NewFingerprintScanner(5)
	ctx := context.Background()
	result := scanner.ScanFingerprint(ctx, server.URL)

	foundPHP := false
	for _, fp := range result.Fingerprints {
		if fp.Name == "PHP" {
			foundPHP = true
			t.Logf("✓ Found PHP fingerprint: confidence=%d method=%s", fp.Confidence, fp.Method)
		}
	}

	if !foundPHP {
		t.Log("⚠ PHP fingerprint not detected")
	}

	// 验证 X-Powered-By 被正确提取
	if result.PoweredBy != "PHP/8.1.0" {
		t.Errorf("PoweredBy not extracted correctly: %s", result.PoweredBy)
	}
}

// TestFingerprintScanner_BatchScan 测试批量扫描
func TestFingerprintScanner_BatchScan(t *testing.T) {
	// 创建多个模拟服务器
	servers := make([]*httptest.Server, 3)
	targets := make([]string, 3)

	for i := 0; i < 3; i++ {
		idx := i
		servers[i] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Server", "TestServer")
			w.WriteHeader(200)
			w.Write([]byte(`<html><head><title>Server ` + string(rune('A'+idx)) + `</title></head></html>`))
		}))
		targets[i] = servers[i].URL
	}
	defer func() {
		for _, s := range servers {
			s.Close()
		}
	}()

	scanner := fingerprint.NewFingerprintScanner(3)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	start := time.Now()
	results := scanner.BatchScanFingerprint(ctx, targets)
	elapsed := time.Since(start)

	t.Logf("Batch scan completed in %v", elapsed)
	t.Logf("Results: %d", len(results))

	if len(results) != 3 {
		t.Errorf("Expected 3 results, got %d", len(results))
	}

	for i, result := range results {
		if result == nil {
			t.Errorf("Result %d is nil", i)
			continue
		}
		t.Logf("  [%d] %s - Status: %d, Title: %s", i, result.URL, result.StatusCode, result.Title)
	}
}

// TestFingerprintScanner_Timeout 测试超时处理
func TestFingerprintScanner_Timeout(t *testing.T) {
	// 创建一个慢响应服务器
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second) // 延迟响应
		w.WriteHeader(200)
	}))
	defer server.Close()

	scanner := fingerprint.NewFingerprintScanner(5)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	start := time.Now()
	result := scanner.ScanFingerprint(ctx, server.URL)
	elapsed := time.Since(start)

	t.Logf("Scan completed in %v (timeout test)", elapsed)

	// 应该在超时内返回
	if elapsed > 3*time.Second {
		t.Error("Scan did not respect timeout")
	}

	// 由于超时，状态码应该是 0
	if result.StatusCode != 0 {
		t.Logf("Note: Status code = %d (may have partial response)", result.StatusCode)
	}
}

// TestFingerprintScanner_HTTPS 测试 HTTPS 扫描
func TestFingerprintScanner_HTTPS(t *testing.T) {
	// 创建 HTTPS 服务器
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		w.WriteHeader(200)
		w.Write([]byte(`<html><head><title>HTTPS Test</title></head></html>`))
	}))
	defer server.Close()

	scanner := fingerprint.NewFingerprintScanner(5)
	ctx := context.Background()

	result := scanner.ScanFingerprint(ctx, server.URL)

	t.Logf("HTTPS scan result: Status=%d, Title=%s", result.StatusCode, result.Title)

	if result.StatusCode == 200 {
		t.Log("✓ HTTPS scan successful")
	}
}

// TestFingerprintScanner_InvalidURL 测试无效 URL 处理
func TestFingerprintScanner_InvalidURL(t *testing.T) {
	scanner := fingerprint.NewFingerprintScanner(5)
	ctx := context.Background()

	testCases := []string{
		"not-a-valid-url",
		"http://localhost:99999",
		"http://256.256.256.256",
	}

	for _, url := range testCases {
		result := scanner.ScanFingerprint(ctx, url)
		t.Logf("Invalid URL %q: Status=%d", url, result.StatusCode)
		// 应该优雅处理，不崩溃
		if result == nil {
			t.Errorf("Result should not be nil for invalid URL: %s", url)
		}
	}
}

// TestFingerprintScanner_JSLibrariesDetection 测试 JS 库检测
func TestFingerprintScanner_JSLibrariesDetection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`<!DOCTYPE html>
<html>
<head>
    <title>JS Libraries Test</title>
    <script src="/js/jquery-3.6.0.min.js"></script>
    <script src="/js/vue.min.js"></script>
    <script src="/js/react.production.min.js"></script>
    <script src="/js/bootstrap.min.js"></script>
    <script src="/js/axios.min.js"></script>
</head>
<body></body>
</html>`))
	}))
	defer server.Close()

	scanner := fingerprint.NewFingerprintScanner(5)

	// 如果没有加载 JS 库模式，跳过测试
	if len(scanner.JSLibPatterns) == 0 {
		t.Skip("JS library patterns not loaded, skipping test")
	}

	ctx := context.Background()
	result := scanner.ScanFingerprint(ctx, server.URL)

	t.Logf("Detected JS Libraries: %v", result.JSLibraries)

	if len(result.JSLibraries) == 0 {
		t.Log("⚠ No JS libraries detected (check jslib.yaml patterns)")
	} else {
		t.Logf("✓ Detected %d JS libraries", len(result.JSLibraries))
	}
}

// TestFingerprintScanner_TitleExtraction 测试标题提取
func TestFingerprintScanner_TitleExtraction(t *testing.T) {
	testCases := []struct {
		name     string
		html     string
		expected string
	}{
		{
			name:     "Normal title",
			html:     `<html><head><title>Test Page</title></head></html>`,
			expected: "Test Page",
		},
		{
			name:     "Chinese title",
			html:     `<html><head><title>百度一下，你就知道</title></head></html>`,
			expected: "百度一下，你就知道",
		},
		{
			name:     "Empty title",
			html:     `<html><head><title></title></head></html>`,
			expected: "",
		},
		{
			name:     "No title",
			html:     `<html><head></head></html>`,
			expected: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(200)
				w.Write([]byte(tc.html))
			}))
			defer server.Close()

			scanner := fingerprint.NewFingerprintScanner(5)
			ctx := context.Background()
			result := scanner.ScanFingerprint(ctx, server.URL)

			if result.Title != tc.expected {
				t.Errorf("Title = %q, want %q", result.Title, tc.expected)
			} else {
				t.Logf("✓ Title extracted correctly: %q", result.Title)
			}
		})
	}
}

// TestFingerprintScanner_HeadersExtraction 测试 Headers 提取
func TestFingerprintScanner_HeadersExtraction(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.18.0")
		w.Header().Set("X-Powered-By", "PHP/7.4")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(200)
		w.Write([]byte(`<html></html>`))
	}))
	defer server.Close()

	scanner := fingerprint.NewFingerprintScanner(5)
	ctx := context.Background()
	result := scanner.ScanFingerprint(ctx, server.URL)

	t.Logf("Headers extracted: %d", len(result.Headers))
	for k, v := range result.Headers {
		t.Logf("  %s: %s", k, v)
	}

	if result.Server != "nginx/1.18.0" {
		t.Errorf("Server = %s, want nginx/1.18.0", result.Server)
	}

	if result.PoweredBy != "PHP/7.4" {
		t.Errorf("PoweredBy = %s, want PHP/7.4", result.PoweredBy)
	}
}

// ==================== 基准测试 ====================

func BenchmarkFingerprintScanner_ScanFingerprint(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		w.WriteHeader(200)
		w.Write([]byte(`<html><head><title>Benchmark</title></head><body>Test</body></html>`))
	}))
	defer server.Close()

	scanner := fingerprint.NewFingerprintScanner(10)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.ScanFingerprint(ctx, server.URL)
	}
}

func BenchmarkFingerprintScanner_NewScanner(b *testing.B) {
	for i := 0; i < b.N; i++ {
		fingerprint.NewFingerprintScanner(10)
	}
}
