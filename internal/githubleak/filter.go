package githubleak

import (
	"path"
	"strings"
)

// filter.go — 泄露监控误报治理（检测/入库层的噪声过滤）。
//
// 误报三大来源与对应手段：
//  1. 测试/示例/文档路径的样板凭据（fixture 密钥、.env.example、文档粘贴的样例）
//     → isNoisePath：路径级整条跳过，不入库不通知（service 层）。
//  2. 已知公开/演示凭据值（Stripe 测试 key、Django 演示 key、AWS 文档示例 key 等）
//     → isKnownNonSecretValue：值级放行。
//  3. JWT 形态的 bearer/access token（三段 base64url）——多为文档样例或短时效
//     令牌，真实长期凭据价值低而噪声占比极高 → isJWTShape：值级放行。
// 连接串误报（docker-compose 教程里的 postgres://user:password@db）→
// credibleDatabaseURL：常见示例口令 / 本地或无 TLD 服务名主机 → 放行。

// noisePathDirMarkers 路径任一段命中即视为测试/示例资产。
var noisePathDirMarkers = []string{
	"test", "tests", "testdata", "__tests__", "__snapshots__", "spec", "specs",
	"example", "examples", "sample", "samples", "demo", "demos", "docs", "doc",
	"documentation", "fixture", "fixtures", "mock", "mocks", "stub", "stubs",
	"vendor", "node_modules", "benchmark", "benchmarks", ".github", ".idea", ".vscode",
	// 实测数据驱动补充：运行日志目录、端到端测试目录（值多为转录/测试配置）
	"logs", "e2e",
}

// noisePathNameMarkers 文件名（含扩展名）命中即视为噪声：
//   - 名称含 test/spec/mock/fixture/sample/example/demo（_test.go / *.test.js / *.spec.ts / mock-server.py）
//   - 文档类扩展名（.md/.mdx/.rst/.adoc/.txt）
//   - 样例配置与锁文件（.example/.sample/.template、.env.example、package-lock.json、go.sum 等）
var (
	noisePathNameMarkers  = []string{"test", "spec", "mock", "fixture", "sample", "example", "demo"}
	noisePathNameSuffixes = []string{
		".md", ".mdx", ".rst", ".adoc", ".txt",
		".example", ".sample", ".tmpl", ".template", ".dist",
	}
	noisePathExactNames = []string{
		"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "go.sum", "composer.lock",
		"cargo.lock", "poetry.lock", "docker-compose.override.yml",
	}
)

// isNoisePath 判定搜索命中路径是否为测试/示例/文档类噪声（service 层整条跳过）。
// 只看小写后的路径段与文件名，避免 "latest"/"protest" 这类子串误伤目录语义。
func isNoisePath(p string) bool {
	p = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(p), "/"))
	if p == "" {
		return false
	}
	dir, name := path.Split(p)
	for _, seg := range strings.Split(strings.Trim(dir, "/"), "/") {
		if seg == "" {
			continue
		}
		for _, marker := range noisePathDirMarkers {
			if seg == marker {
				return true
			}
		}
		// 目录段前缀形态：demo-repo/、test9/、mock-server/、sample_app/——
		// "testing-guides"（test+ing）不误伤，仅 [-_0-9] 连接视为测试资产。
		for _, prefix := range []string{"test", "demo", "sample", "mock", "fixture", "example"} {
			if len(seg) > len(prefix) && strings.HasPrefix(seg, prefix) {
				switch seg[len(prefix)] {
				case '-', '_', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
					return true
				}
			}
		}
	}
	lower := strings.ToLower(name)
	for _, exact := range noisePathExactNames {
		if lower == exact {
			return true
		}
	}
	for _, suffix := range noisePathNameSuffixes {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	// 名称含标记（_test.go / *.test.js / mock-server.py / sample.env）
	if strings.Contains(lower, "-test.") || strings.Contains(lower, "_test.") ||
		strings.Contains(lower, ".test.") || strings.Contains(lower, ".spec.") ||
		strings.HasPrefix(lower, "test_") || strings.HasPrefix(lower, "test-") ||
		strings.HasPrefix(lower, "mock") || strings.HasPrefix(lower, "fixture") ||
		strings.HasPrefix(lower, "sample") || strings.HasPrefix(lower, "example") ||
		strings.HasPrefix(lower, "fake") || strings.HasPrefix(lower, "dummy") {
		return true
	}
	for _, marker := range noisePathNameMarkers {
		if strings.Contains(lower, marker) {
			// 名称级标记只在明确形态下生效，避免 "latest.py" 这类误伤：
			// 上面的前缀/分隔符形态已覆盖常见命名，这里仅兜底 .env/.json/.yaml 样例名
			if strings.HasSuffix(lower, ".env") || strings.HasSuffix(lower, ".json") ||
				strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml") {
				return true
			}
		}
	}
	return false
}

// knownNonSecretValueFragments 已知公开文档/演示凭据的特征片段
// （值含任一片段即判定非真实凭据；均为公开材料中稳定出现的字面量）。
var knownNonSecretValueFragments = []string{
	"wJalrXUtnFEMI",   // AWS 文档示例 AccessKey
	"AKIAIOSFODNN7",   // AWS 文档示例 KeyID
	"ASIAIOSFODNN7",   // AWS 文档示例临时凭据 KeyID（R2 配套：ASIA 模式上线后的样例闸）
	"django-insecure", // Django 脚手架开发密钥
	"sk_test_",        // Stripe 测试密钥前缀（非 live）
	"pk_test_",        // Stripe 测试可发布密钥
	"rk_test_",        // Stripe 测试受限密钥
	"test@example",    // 万能示例邮箱（常见于配套口令样例）
}

// isKnownNonSecretValue 值级放行：已知公开/演示凭据。
func isKnownNonSecretValue(value string) bool {
	lower := strings.ToLower(value)
	for _, fragment := range knownNonSecretValueFragments {
		if strings.Contains(lower, strings.ToLower(fragment)) {
			return true
		}
	}
	return false
}

// isJWTShape 判定值是否为 JWT 形态（header.payload.signature，三段 base64url）。
func isJWTShape(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" || len(part) > 4096 {
			return false
		}
		for _, r := range part {
			if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '=') {
				return false
			}
		}
	}
	// header 恒为 base64url 且以 eyJ（{" 开头）落最多数情况；不强制，避免误放行。
	return true
}

// commonSamplePasswords 连接串/口令字段中的常见示例口令。
var commonSamplePasswords = []string{
	"password", "passwd", "passw0rd", "postgres", "mysql", "redis", "mongo",
	"root", "admin", "administrator", "guest", "test", "tester", "testing",
	"example", "sample", "secret", "changeme", "change", "letmein", "qwerty",
	"123456", "12345678", "123456789", "abc123", "welcome", "master", "dragon",
	"monkey", "password1", "password123", "admin123", "nimda", "toor", "placeholder",
}

// isLocalOrServiceHost 主机是否为本地地址或 docker-compose 风格无 TLD 服务名。
func isLocalOrServiceHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" || host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]" {
		return true
	}
	if strings.HasPrefix(host, "127.") || strings.HasPrefix(host, "192.168.") ||
		strings.HasPrefix(host, "10.") || strings.HasPrefix(host, "172.") {
		return true
	}
	// 无点 = 无 TLD = compose/内网服务名（db、redis、mysql-primary...）
	return !strings.Contains(host, ".")
}

// credibleDatabaseURL 对 database_connection_string 强特征做二次校验：
// 示例口令或本地/服务名主机的连接串视为教学样板，跳过。
func credibleDatabaseURL(value string) bool {
	// 形如 scheme://[user[:password]@]host[:port][/db]
	rest := value
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	at := strings.LastIndex(rest, "@")
	var userinfo, hostpart string
	if at >= 0 {
		userinfo, hostpart = rest[:at], rest[at+1:]
	} else {
		hostpart = rest
	}
	if j := strings.IndexAny(hostpart, "/?#"); j >= 0 {
		hostpart = hostpart[:j]
	}
	if isLocalOrServiceHost(hostpart) {
		return false
	}
	if at >= 0 {
		password := userinfo
		if k := strings.Index(userinfo, ":"); k >= 0 {
			password = userinfo[k+1:]
		}
		if password == "" {
			return false
		}
		lower := strings.ToLower(password)
		for _, sample := range commonSamplePasswords {
			if lower == sample {
				return false
			}
		}
		// 口令段整体是环境变量/模板占位（$(VAR)、{VAR}、<VAR>、$VAR）
		if strings.ContainsAny(password, "${}<(") {
			return false
		}
	}
	return true
}

// IsNoisePath 路径级噪声判定（导出供维护工具/清洗任务复用，与检测层同源）。
func IsNoisePath(p string) bool {
	return isNoisePath(p)
}
