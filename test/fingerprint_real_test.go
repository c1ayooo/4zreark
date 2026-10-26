package test

import (
	"context"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/scanner/fingerprint"
)

// TestFingerprintScanner_RealWebsites 测试真实网站指纹识别
// 运行: go test -v ./test/... -run TestFingerprintScanner_RealWebsites -timeout 60s
func TestFingerprintScanner_RealWebsites(t *testing.T) {
	requireLiveNetwork(t)
	scanner := fingerprint.NewFingerprintScanner(10)

	// 测试目标网站列表
	targets := []struct {
		url         string
		description string
	}{
		{"https://www.baidu.com", "百度 - 中国搜索引擎"},
		{"https://www.taobao.com", "淘宝 - 电商平台"},
		{"https://www.jd.com", "京东 - 电商平台"},
		{"https://www.qq.com", "腾讯门户"},
		{"https://www.163.com", "网易门户"},
		{"https://www.sina.com.cn", "新浪门户"},
		{"https://www.zhihu.com", "知乎"},
		{"https://www.bilibili.com", "哔哩哔哩"},
		{"https://www.douyin.com", "抖音"},
		{"https://gitee.com", "Gitee 代码托管"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	t.Logf("开始测试 %d 个真实网站...\n", len(targets))
	t.Log("=" + string(make([]byte, 79)))

	for _, target := range targets {
		t.Run(target.description, func(t *testing.T) {
			start := time.Now()
			result := scanner.ScanFingerprint(ctx, target.url)
			elapsed := time.Since(start)

			t.Logf("\n【%s】", target.description)
			t.Logf("  URL: %s", result.URL)
			t.Logf("  状态码: %d", result.StatusCode)
			t.Logf("  标题: %s", result.Title)
			t.Logf("  服务器: %s", result.Server)
			t.Logf("  X-Powered-By: %s", result.PoweredBy)
			t.Logf("  Body 长度: %d bytes", result.BodyLength)
			t.Logf("  Body Hash: %s", result.BodyHash)
			t.Logf("  Favicon Hash: %s", result.IconHash)
			t.Logf("  扫描耗时: %v", elapsed)

			// JS 库
			if len(result.JSLibraries) > 0 {
				t.Logf("  JS 库: %v", result.JSLibraries)
			}

			// 指纹信息
			t.Logf("  检测到指纹 (%d):", len(result.Fingerprints))
			for _, fp := range result.Fingerprints {
				t.Logf("    - %s [%s] 置信度=%d%% 方法=%s",
					fp.Name, fp.Category, fp.Confidence, fp.Method)
			}

			// 技术栈
			if len(result.Technologies) > 0 {
				t.Logf("  技术栈: %v", result.Technologies)
			}

			// 分类信息
			if result.WebServer != "" {
				t.Logf("  Web服务器: %s", result.WebServer)
			}
			if result.Framework != "" {
				t.Logf("  框架: %s", result.Framework)
			}
			if result.Language != "" {
				t.Logf("  语言: %s", result.Language)
			}
			if result.CMS != "" {
				t.Logf("  CMS: %s", result.CMS)
			}

			// 验证基本功能
			if result.StatusCode == 0 {
				t.Logf("  ⚠️ 无法连接到目标")
			} else if result.StatusCode >= 200 && result.StatusCode < 400 {
				t.Logf("  ✅ 扫描成功")
			}
		})
	}
}

// TestFingerprintScanner_TechSites 测试技术类网站
func TestFingerprintScanner_TechSites(t *testing.T) {
	requireLiveNetwork(t)
	scanner := fingerprint.NewFingerprintScanner(10)

	targets := []struct {
		url         string
		description string
		expected    []string // 期望检测到的技术
	}{
		{
			url:         "https://nginx.org",
			description: "Nginx 官网",
			expected:    []string{"Nginx"},
		},
		{
			url:         "https://httpd.apache.org",
			description: "Apache 官网",
			expected:    []string{"Apache"},
		},
		{
			url:         "https://wordpress.org",
			description: "WordPress 官网",
			expected:    []string{"WordPress"},
		},
		{
			url:         "https://www.php.net",
			description: "PHP 官网",
			expected:    []string{"PHP"},
		},
		{
			url:         "https://vuejs.org",
			description: "Vue.js 官网",
			expected:    []string{},
		},
		{
			url:         "https://react.dev",
			description: "React 官网",
			expected:    []string{},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	for _, target := range targets {
		t.Run(target.description, func(t *testing.T) {
			result := scanner.ScanFingerprint(ctx, target.url)

			t.Logf("\n【%s】 %s", target.description, target.url)
			t.Logf("  状态码: %d | 标题: %s", result.StatusCode, result.Title)
			t.Logf("  服务器: %s", result.Server)

			// 打印检测到的指纹
			for _, fp := range result.Fingerprints {
				t.Logf("  → %s [%s] %d%%", fp.Name, fp.Category, fp.Confidence)
			}

			// 验证期望的技术是否被检测到
			for _, expected := range target.expected {
				found := false
				for _, fp := range result.Fingerprints {
					if fp.Name == expected {
						found = true
						break
					}
				}
				// 也检查 Server header
				if !found && result.Server != "" {
					if contains(result.Server, expected) {
						found = true
					}
				}
				if found {
					t.Logf("  ✅ 检测到 %s", expected)
				} else {
					t.Logf("  ⚠️ 未检测到 %s", expected)
				}
			}
		})
	}
}

// TestFingerprintScanner_SingleTarget 单目标深度测试
func TestFingerprintScanner_SingleTarget(t *testing.T) {
	requireLiveNetwork(t)
	scanner := fingerprint.NewFingerprintScanner(10)

	// 可以修改这个 URL 测试任意目标
	targetURL := "https://www.baidu.com"

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Logf("深度扫描目标: %s\n", targetURL)
	t.Log(string(make([]byte, 60)))

	result := scanner.ScanFingerprint(ctx, targetURL)

	// 详细输出
	t.Logf("目标: %s", result.Target)
	t.Logf("最终URL: %s", result.URL)
	t.Logf("状态码: %d", result.StatusCode)
	t.Logf("标题: %s", result.Title)
	t.Logf("服务器: %s", result.Server)
	t.Logf("X-Powered-By: %s", result.PoweredBy)
	t.Logf("Body长度: %d", result.BodyLength)
	t.Logf("Body Hash (MD5): %s", result.BodyHash)
	t.Logf("Favicon Hash (MMH3): %s", result.IconHash)
	t.Logf("Favicon MD5: %s", result.IconMD5)
	t.Logf("扫描耗时: %dms", result.ScanTime)

	t.Log("\n--- HTTP Headers ---")
	for k, v := range result.Headers {
		t.Logf("  %s: %s", k, v)
	}

	t.Log("\n--- JS Libraries ---")
	if len(result.JSLibraries) > 0 {
		for _, lib := range result.JSLibraries {
			t.Logf("  - %s", lib)
		}
	} else {
		t.Log("  (无)")
	}

	t.Log("\n--- Fingerprints ---")
	if len(result.Fingerprints) > 0 {
		for _, fp := range result.Fingerprints {
			t.Logf("  [%s] %s - 置信度: %d%%, 方法: %s, 版本: %s",
				fp.Category, fp.Name, fp.Confidence, fp.Method, fp.Version)
		}
	} else {
		t.Log("  (无匹配的指纹)")
	}

	t.Log("\n--- Technologies ---")
	if len(result.Technologies) > 0 {
		t.Logf("  %v", result.Technologies)
	} else {
		t.Log("  (无)")
	}

	t.Log("\n--- Classification ---")
	t.Logf("  Web Server: %s", result.WebServer)
	t.Logf("  Framework: %s", result.Framework)
	t.Logf("  Language: %s", result.Language)
	t.Logf("  CMS: %s", result.CMS)
	t.Logf("  OS: %s", result.OS)
}

// TestFingerprintScanner_BatchRealSites 批量扫描真实网站
func TestFingerprintScanner_BatchRealSites(t *testing.T) {
	requireLiveNetwork(t)
	scanner := fingerprint.NewFingerprintScanner(5)

	targets := []string{
		"https://www.baidu.com",
		"https://www.taobao.com",
		"https://www.jd.com",
		"https://www.qq.com",
		"https://www.163.com",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	t.Logf("批量扫描 %d 个目标...", len(targets))
	start := time.Now()

	results := scanner.BatchScanFingerprint(ctx, targets)

	elapsed := time.Since(start)
	t.Logf("批量扫描完成，总耗时: %v\n", elapsed)

	for i, result := range results {
		if result == nil {
			t.Logf("[%d] %s - 扫描失败", i+1, targets[i])
			continue
		}
		t.Logf("[%d] %s", i+1, result.URL)
		title := result.Title
		if len(title) > 40 {
			title = title[:40] + "..."
		}
		t.Logf("    状态: %d | 标题: %s", result.StatusCode, title)
		t.Logf("    服务器: %s | 指纹: %d个", result.Server, len(result.Fingerprints))
		if len(result.Fingerprints) > 0 {
			techs := make([]string, 0)
			for _, fp := range result.Fingerprints {
				techs = append(techs, fp.Name)
			}
			t.Logf("    技术: %v", techs)
		}
	}
}

// 辅助函数
func contains(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr ||
			len(s) > len(substr) &&
				(s[:len(substr)] == substr ||
					s[len(s)-len(substr):] == substr ||
					findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
