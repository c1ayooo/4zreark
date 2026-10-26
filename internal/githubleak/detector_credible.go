package githubleak

import (
	"math"
	"strings"
	"unicode"
)

func credibleAssignedValue(value string, spec assignmentSpec, allowJWT bool) bool {
	value = strings.TrimSpace(value)
	if len(value) < spec.minLength || len(value) > 512 || isPlaceholderCredentialValue(value) ||
		isSymbolicCredentialValue(value) || isNonLiteralCredentialValue(value) ||
		isIdentifierShapeValue(value) {
		return false
	}
	// 误报治理：已知公开/演示凭据与 JWT 形态令牌直接放行。JWT 例外仅限
	// MiniMax 专属变量名（其 key 即 JWT 形态，见 vendor.go isMinimaxCredentialKey）。
	if isKnownNonSecretValue(value) {
		return false
	}
	if isJWTShape(value) && !allowJWT {
		return false
	}
	if credentialValueClasses(value) < spec.minClasses {
		return false
	}
	return shannonEntropy(value) >= spec.minEntropy
}

// isPlaceholderCredentialValue 赋值类命中的第一道闸：空值/占位符/环境变量引用/
// 哨兵说明值/经典示例序列都不是凭据明文。
func isPlaceholderCredentialValue(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return true
	}
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") || strings.HasPrefix(lower, "arn:") ||
		isCredentialReferenceValue(lower) {
		return true
	}
	for _, exact := range []string{
		"none", "null", "undefined", "nil", "n/a", "na", "unset", "not set", "not-set", "not_set",
		"not configured", "not-configured", "not_configured", "not provided", "not-provided",
		"not_provided", "missing", "required", "todo", "tbd", "fixme",
		"secret", "password", "passwd", "token", "apikey", "api_key",
		"development", "production", "default", "true", "false",
	} {
		if lower == exact {
			return true
		}
	}
	for _, marker := range []string{
		"example", "sample", "dummy", "changeme", "change-me", "change_me", "replace",
		"placeholder", "<redacted", "redacted:", "your_", "your-", "your.", "not-a-real",
		"not_real", "fake-key", "fake_key", "test-key", "test_key", "test-token", "test_token",
		"sk-test", "${", "{{", "<%", "localhost", "xxxxx",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	if isCredentialSentinelValue(value) || isCanonicalExampleCredential(value) {
		return true
	}
	// 顺序占位形态（实测误报：sk-proj-<完整字母表><数字环>）——这类值字符种类
	// 多且分布均匀，Shannon 熵无判别力，只能按游程序列特征拦。
	if isSequentialPlaceholderValue(value) {
		return true
	}
	runes := []rune(value)
	if len(runes) > 0 {
		allSame := true
		for _, r := range runes[1:] {
			if r != runes[0] {
				allSame = false
				break
			}
		}
		if allSame {
			return true
		}
	}
	return false
}

// isCredentialReferenceValue 引用形态：环境变量/配置读取/密钥管理服务/容器密钥
// 文件等取值表达式，不是明文凭据（比对前剔除空白，容忍 `process.env .KEY` 写法）。
func isCredentialReferenceValue(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	if lower == "" {
		return true
	}
	withoutSpace := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, lower)
	for _, prefix := range []string{
		"$", "%", "process.env.", "process.env[", "import.meta.env.", "import.meta.env[",
		"deno.env.", "deno.env[", "bun.env.", "bun.env[", "os.getenv", "os.environ",
		"system.getenv", "system.getproperty", "environment.getenvironmentvariable",
		"std::env::", "env(", "env[", "env.", "getenv(", "get_env(", "get-env(",
		"config(", "config[", "config.", "configuration(", "configuration[", "configuration.",
		"settings(", "settings[", "settings.", "viper.get", ".values.", "values.",
		"vault://", "vault.", "secret://", "env://", "ssm://", "keyvault://", "op://", "ref+",
		"file://", "/run/secrets/", "/var/run/secrets/", "secretmanager.", "secretmanager(",
		"secretsmanager.", "secretsmanager(", "aws_secretsmanager_", "keyvault.", "keyvault(",
		"parameterstore.", "parameterstore(", "parameters(", "var.", "local.", "module.", "data.",
		"secrets.", "secrets[", "@microsoft.keyvault(", "ref(", "reference(",
	} {
		if strings.HasPrefix(withoutSpace, prefix) {
			return true
		}
	}
	for _, marker := range []string{
		".env.get(", "::env::", "getenv(", "get_env(", "getenvironmentvariable(",
		"secretkeyref", "valuefrom", "secretsmanager", "secretmanager", "keyvault", "parameterstore",
		"/run/secrets/", "/var/run/secrets/", "file://",
	} {
		if strings.Contains(withoutSpace, marker) {
			return true
		}
	}
	if strings.HasPrefix(withoutSpace, "*") && containsCredentialName(compactCredentialKey(withoutSpace)) {
		return true
	}
	// 由函数/属性表达式初始化的凭据字段是引用而非字面量；要求表达式里出现凭据
	// 词汇，避免仅因标点符号就放过不透明随机值。
	if strings.ContainsAny(withoutSpace, "([") && containsCredentialName(compactCredentialKey(withoutSpace)) {
		return true
	}
	return false
}

// isCredentialSentinelValue 哨兵/说明值：NOT_SET、YOUR_KEY_HERE、REQUIRED 等。
func isCredentialSentinelValue(value string) bool {
	compact := compactCredentialKey(value)
	if compact == "" {
		return true
	}
	for _, exact := range []string{
		"notset", "notconfigured", "notprovided", "notavailable", "missing", "required", "redacted", "masked",
	} {
		if compact == exact {
			return true
		}
	}
	if !containsCredentialName(compact) {
		return false
	}
	for _, qualifier := range []string{
		"your", "example", "sample", "dummy", "fake", "test", "mock", "demo", "placeholder",
		"replace", "insert", "paste", "enter", "provide", "redacted", "masked", "hidden",
		"changeme", "fillme", "here", "goeshere", "value", "unset", "notset", "notconfigured",
		"notprovided", "notavailable", "missing", "required", "todo", "tbd", "fixme", "variable",
	} {
		if strings.Contains(compact, qualifier) {
			return true
		}
	}
	return false
}

// isIdentifierShapeValue 赋值类值的标识符形态闸：纯单一大小写字母加 _-. 连接符、
// 无数字——i18n 翻译键/枚举映射表/属性路径形态（如 prowler UI 的
// SERVICE_ACCOUNT_KEY: "service_account_key"）。含数字即放行给后续闸门，
// 大小写混合也放行——真实随机凭据几乎必然含数字或大小写混合。
func isIdentifierShapeValue(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	hasLower, hasUpper := false, false
	for _, r := range value {
		switch {
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsDigit(r):
			return false
		case r == '_' || r == '-' || r == '.':
		default:
			return false
		}
	}
	return hasLower != hasUpper
}

// isSymbolicCredentialValue 标识符形态：全大写无数字（ENV_VAR）或仅含标识符
// 字符且带凭据词汇（API_KEY 之类）——真实随机凭据通常大小写混合含数字。
func isSymbolicCredentialValue(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return true
	}
	hasLower, hasUpper, hasDigit := false, false, false
	for _, r := range value {
		switch {
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsDigit(r):
			hasDigit = true
		case r == '_', r == '-', r == '.', r == ':', r == '<', r == '>', r == '[', r == ']':
		default:
			return false
		}
	}
	if !containsCredentialName(compactCredentialKey(value)) {
		return false
	}
	// 环境变量/配置标识符通常无数字或全大写；混合大小写且带数字的不透明凭据仍可入库。
	return !hasDigit || (hasUpper && !hasLower)
}

// isNonLiteralCredentialValue 赋值类值形态闸（误报治理，覆盖真实运营数据里的一类
// 高频误报）：真实凭据是窄字符集字面量；含代码标点（括号/引号/问号/分号/尖括号/
// 星号等）、空白，或呈路径形态（以 / 开头、含 / 且完全无数字）的值，是代码表达式、
// 配置路径或句子而非凭据明文——如 value_as_string(...)、options?.KEY、
// ("llm_providers"、/data/attributes/secret/access_key_secret。
// PEM 私钥块（含换行）例外，其完整性由强特征校验兜底。
func isNonLiteralCredentialValue(value string) bool {
	if strings.Contains(value, "-----BEGIN") {
		return false
	}
	if strings.ContainsAny(value, " \t\r\n\"'`()[]{};?|<>*^~\\") {
		return true
	}
	if strings.HasPrefix(value, "/") {
		return true
	}
	if strings.Contains(value, "/") {
		// base64 凭据几乎恒含数字（16 位时缺数字概率仅 ~6%）；含 / 却无数字的
		// 值基本是路径片段（/data/attributes/secret/access_key_secret 类）。
		hasDigit := false
		for _, r := range value {
			if unicode.IsDigit(r) {
				hasDigit = true
				break
			}
		}
		if !hasDigit {
			return true
		}
	}
	return false
}

// containsCredentialName 紧凑小写串中是否含凭据词汇（符号/引用/哨兵判定的共性部分）。
func containsCredentialName(compact string) bool {
	for _, marker := range []string{
		"apikey", "accesskey", "secret", "clientsecret", "consumersecret", "token",
		"password", "passwd", "credential", "privatekey",
	} {
		if strings.Contains(compact, marker) {
			return true
		}
	}
	return false
}

// isCanonicalExampleCredential 文档/模板里的经典示例序列（非真实凭据）。
func isCanonicalExampleCredential(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	for _, example := range []string{
		"0123456789abcdef", "abcdef0123456789", "1234567890abcdef", "fedcba9876543210",
		"0123456789abcdef0123456789abcdef", "abcdef0123456789abcdef0123456789",
	} {
		if lower == example {
			return true
		}
	}
	return false
}

// sequentialPlaceholderRuns 顺序占位值特征游程：完整字母表、键盘行、数字环。
// 随机凭据出现任一 10~26 位有序游程的概率在 1e-15 量级，判定零误杀风险。
var sequentialPlaceholderRuns = []string{
	"abcdefghijklmnopqrstuvwxyz", // 完整字母表（实测误报形态）
	"qwertyuiop",                 // 键盘顶行
	"0123456789",                 // 数字环（升序任意起点：0123… / 1234… / 90123…）
	"1234567890",
	"9876543210", // 降序
}

// isSequentialPlaceholderValue 顺序/键盘/超长同字符游程的占位值判定。
func isSequentialPlaceholderValue(value string) bool {
	lower := strings.ToLower(value)
	for _, run := range sequentialPlaceholderRuns {
		if strings.Contains(lower, run) {
			return true
		}
	}
	// ≥10 位同字符游程（aaaaaaaaaaaa…）：44 位随机值出现概率 <1e-16。
	run := 1
	for i := 1; i < len(lower); i++ {
		if lower[i] == lower[i-1] {
			run++
			if run >= 10 {
				return true
			}
		} else {
			run = 1
		}
	}
	return false
}

// isSelfEchoValue 自回显占位值：值的紧凑形态以自身键名开头——文档示例的
// "键名+编号"形态（access_token: accesstoken000001 / api_key: apikey123456）。
// 真实随机凭据几乎不可能复述自己的变量名；判定零联网、零参数。
// 只查赋值路径（强特征命中没有键名概念）。
func isSelfEchoValue(key, value string) bool {
	compactKey := compactCredentialKey(key)
	if compactKey == "" {
		return false
	}
	value = strings.TrimSpace(value)
	if len(value) < len(compactKey) {
		return false
	}
	return strings.HasPrefix(compactCredentialKey(value), compactKey)
}

// placeholderKeySegments 键名分段占位词：生产变量名的任一分段（_-. 分隔）
// 精确命中这些词即测试/示例配置（WX_TEST_APP_SECRET 类）。
var placeholderKeySegments = map[string]bool{
	"test": true, "tests": true, "testing": true,
	"mock": true, "mocks": true, "demo": true, "demos": true,
	"sample": true, "samples": true, "fixture": true, "fixtures": true,
	"example": true, "examples": true, "dummy": true, "fake": true,
}

// isPlaceholderCredentialKey 键名维度占位判定（数据驱动，详见 detectAll 调用点）：
//   - 任一分段为测试/示例词（WX_TEST_APP_SECRET / MOCK_TOKEN）
//   - 布尔语义键 hasApiKey/hasSecretKey/hasToken——代码特征标志而非凭据赋值
//     （remainder 精确匹配，"hashkey" 类命名不受影响）
func isPlaceholderCredentialKey(key string) bool {
	lower := strings.ToLower(key)
	for _, seg := range strings.FieldsFunc(lower, func(r rune) bool { return r == '_' || r == '-' || r == '.' }) {
		if placeholderKeySegments[seg] {
			return true
		}
	}
	compact := compactCredentialKey(lower)
	if strings.HasPrefix(compact, "has") {
		switch compact[3:] {
		case "apikey", "secretkey", "secret", "token", "password":
			return true
		}
	}
	return false
}

func credibleStrongSecret(value string) bool {
	if isPlaceholderCredentialValue(value) || isKnownNonSecretValue(value) {
		return false
	}
	// 单行 token（云 AK/LLM key 等）真实形态只含字母/数字/-/_/.，不会出现引号、
	// 括号、空白等代码上下文字符；出现即说明匹配到的是代码表达式
	// （如 util.GetFromEnv("ACCESS_KEY"...)）而非凭据本身——这类假阳性曾直接
	// 进入 IM 通知的"key 值"。PEM 私钥块（含 JSON/代码转义形态，头尾有空格且
	// 可能无真实换行）带 -----BEGIN 标记，走完整页脚校验，不受此限。
	if !strings.Contains(value, "-----BEGIN") {
		trimmed := strings.Trim(value, "\"'`")
		if strings.ContainsAny(trimmed, " \t\"'`()[]{};,") {
			return false
		}
	}
	return credentialValueClasses(value) >= 2 && shannonEntropy(value) >= 2.8
}

func credentialValueClasses(value string) int {
	classes := 0
	for _, predicate := range []func(rune) bool{
		unicode.IsLower,
		unicode.IsUpper,
		unicode.IsDigit,
		func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) },
	} {
		for _, r := range value {
			if predicate(r) {
				classes++
				break
			}
		}
	}
	return classes
}

func shannonEntropy(value string) float64 {
	if value == "" {
		return 0
	}
	counts := make(map[rune]int)
	total := 0
	for _, r := range value {
		counts[r]++
		total++
	}
	entropy := 0.0
	for _, count := range counts {
		p := float64(count) / float64(total)
		entropy -= p * math.Log2(p)
	}
	return entropy
}
