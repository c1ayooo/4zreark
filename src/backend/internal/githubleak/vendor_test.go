package githubleak

import (
	"strings"
	"testing"
)

// vendor_test.go — R8 静态闸门与 R9.1 LLM 值级规格的回归样本
// （docs/GitHub敏感信息监控改进建议.md R2/R8/R9.1）。
//
// 样本值全部为合成构造：AWS KeyID 体严格使用 Base32 字母表（A-Z + 2-7，与
// gitleaks aws-access-token 同源），违规样本显式包含 0/1/8/9。

const (
	vendorAKBase32   = "AKIA" + "Q2W3E4R5T6Y7UAIO" // 16 位合规体
	vendorAKOffAlpha = "AKIA" + "Q1W2E3R4T5Y6U7I8" // 含 1/8，字母表违规
	vendorASIAKey    = "ASIA" + "Z4K2Q5W3V7R6J4H6" // 临时凭据前缀（16 位 Base32 体）
	// 40 位 base64（AWS Secret 规格）
	vendorAWSSecret  = "p9/Qx4m7Nc2Rt8Vk5Za3Qw6Yh1Ui4Op2As7DfGhJ"
	vendorSessionTok = "FwoGZXIvYXdzEBKaHn0mZx1Qb7Vc3Tn5Wp8Mj4Lg"
	vendorAliyunSk30 = "Q7v2Lm9R4x8Nc6Wp3ZaQb5Tn8Wd2Kf"   // 30 位
	vendorTcSk32     = "Zx8Kp2Qw5Ln9Vc3Ry7Jm4Ht6Bd1Gf0Sk" // 32 位
	vendorHex32      = "6a1f2c3d4e5f60718293a4b5c6d7e8f9" // 32 位 hex
	vendorJWTKey     = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.Q7v2Lm9R4x8Nc6Wp3Za5Kd2Fb8Tn3Vc6Xy9.Q7v2Lm9R4x8Nc6Wp3Za5Kd2Fb8Tn3Vc6Xy0"

	// LLM 值级样本体：高熵（可信闸要求熵 ≥2.8），长度落在 R9.1 各厂商规格区间。
	// proj/svcacct/admin 真实 key 总长 150+，强模式按 {100,} 判定（R8-1 规格）。
	llmOpenAIKey     = "sk-proj-" + "Ab9Qx4Lm7Nc2Rt8Vk5Za3" + "Qw6Yh1Ui4Op2As7DfGhJe5Kd2Fb8Tn3Vc6Xy0Mz1Wq4Rt7Yu2Io5Pp8Ss3Dd6Gg9Hh4Jk1Ll5Zz7Cc0Vv8Bb2Nn6Mm3Q"
	llmAnthropicKey  = "sk-ant-api03-p9Qx4m7Nc2Rt8Vk5Za3Qw6Yh1Ui4Op2As7DfGhJ"
	llmGroqKey       = "gsk_Q7v2Lm9R4x8Nc6Wp3ZaQb5Tn8Wd2Kf3Xz6Vb9M0Hj"
	llmOpenRouterKey = "sk-or-v1-Zx8Kp2Qw5Ln9Vc3Ry7Jm4Ht6Bd1Gf0SkQ7v2Lm9R4x8Nc6Wp3Za"
	llmPerplexityKey = "pplx-Q7v2Lm9R4x8Nc6Wp3ZaQb5Tn8Wd2Kf3Xz"
	llmSkStyleKey    = "sk-Q7v2Lm9R4x8Nc6Wp3ZaQb5Tn8Wd2Kf3Xz6Vb9M0"
)

func detectVendorFragment(t *testing.T, d *Detector, path, fragment string) []Candidate {
	t.Helper()
	return d.Detect("vendor-gate", SearchItem{
		Repository: "owner/repo", Path: path, BlobSHA: strings.Repeat("a", 40),
		HTMLURL:   "https://github.com/owner/repo/blob/main/" + path,
		Fragments: []string{fragment},
	})
}

// R8-2 配对完整性：Base32 合规的单 AK 保留但降级 suspected（文档/转录残留形态），
// 与 Secret 成对出现时保持 likely。
func TestPairingGateDowngradesUnpairedAccessKeyIDs(t *testing.T) {
	detector := testDetector(t, "unit-test-fingerprint-key-32-bytes", "")

	// 单 AK（合规 Base32）→ suspected
	got := detectVendorFragment(t, detector, "deploy.py", `access_key_id = "`+vendorAKBase32+`"`)
	if len(got) != 1 || got[0].SecretType != "aws_access_key_id" || got[0].Confidence != "suspected" {
		t.Fatalf("bare AKIA candidates = %+v, want suspected aws_access_key_id", got)
	}

	// AK + Secret 成对 → AK 保持 likely，Secret 照常入库
	fragment := `AWS_ACCESS_KEY_ID=` + vendorAKBase32 + ` AWS_SECRET_ACCESS_KEY="` + vendorAWSSecret + `"`
	got = detectVendorFragment(t, detector, "prod.env", fragment)
	if len(got) != 2 {
		t.Fatalf("paired AKIA candidates = %+v, want 2", got)
	}
	ak, ok := candidateOfType(got, "aws_access_key_id")
	if !ok || ak.Confidence != "likely" {
		t.Fatalf("paired AKIA = %+v, want likely", got)
	}
	if sk, ok := candidateOfType(got, "cloud_secret_access_key"); !ok || sk.Confidence != "suspected" {
		t.Fatalf("paired secret = %+v, want suspected cloud_secret_access_key", got)
	}

	// ASIA 临时凭据：配 SESSION_TOKEN → likely；缺失 → suspected（文档 R2 配套）
	got = detectVendorFragment(t, detector, "session.env",
		`AWS_ACCESS_KEY_ID=`+vendorASIAKey+` AWS_SESSION_TOKEN="`+vendorSessionTok+`"`)
	if ak, ok := candidateOfType(got, "aws_access_key_id"); !ok || ak.Confidence != "likely" {
		t.Fatalf("ASIA + session token = %+v, want likely", got)
	}
	got = detectVendorFragment(t, detector, "session.env", `aws_access_key_id = `+vendorASIAKey)
	if ak, ok := candidateOfType(got, "aws_access_key_id"); !ok || ak.Confidence != "suspected" {
		t.Fatalf("bare ASIA = %+v, want suspected", got)
	}

	// 阿里云/腾讯云同理：单 AK 降级
	got = detectVendorFragment(t, detector, "legacy.sh", `oss_ak = "LTAIQ2W3E4R5T6Y7U"`)
	if len(got) != 1 || got[0].SecretType != "aliyun_access_key" || got[0].Confidence != "suspected" {
		t.Fatalf("bare LTAI = %+v, want suspected aliyun_access_key", got)
	}
	got = detectVendorFragment(t, detector, "cvm.env",
		`tencent_secret_id = AKIDZx8Kp2Qw5Ln9Vc3Ry7Jm4Ht6Bd1Gf0
		 tencent_secret_key = `+vendorTcSk32)
	if ak, ok := candidateOfType(got, "tencentcloud_secret_id"); !ok || ak.Confidence != "likely" {
		t.Fatalf("paired AKID = %+v, want likely", got)
	}
}

// R8-1 结构性字母表闸门：AWS KeyID 体含 Base32 外字符（0/1/8/9）→ 降级 suspected；
// 配对满足也不回升（降级只降不升，防字母表论断有例外时误杀真实凭据）。
func TestAWSKeyIDAlphabetGateDowngradesNotDrops(t *testing.T) {
	detector := testDetector(t, "unit-test-fingerprint-key-32-bytes", "")

	got := detectVendorFragment(t, detector, "readme.md", `key_bare `+vendorAKOffAlpha)
	if len(got) != 1 || got[0].Confidence != "suspected" {
		t.Fatalf("off-alphabet AKIA = %+v, want suspected", got)
	}

	// 字母表违规但配对完整 → 仍是 suspected（闸门不可被配对回滚）
	fragment := `AWS_ACCESS_KEY_ID=` + vendorAKOffAlpha + ` AWS_SECRET_ACCESS_KEY="` + vendorAWSSecret + `"`
	got = detectVendorFragment(t, detector, "odd.env", fragment)
	ak, ok := candidateOfType(got, "aws_access_key_id")
	if !ok || ak.Confidence != "suspected" {
		t.Fatalf("off-alphabet paired AKIA = %+v, want suspected", got)
	}
}

// R8-1 厂商专属变量名精确规格：变量名可唯一归属厂商时，值不符合公开规格判假
// （丢弃）；泛化变量名不 gating。
func TestAssignmentVendorFormatGates(t *testing.T) {
	detector := testDetector(t, "unit-test-fingerprint-key-32-bytes", "")

	cases := []struct {
		name     string
		fragment string
		want     int
		wantKind string
	}{
		{"aws secret 40 ok", `aws_secret_access_key = "` + vendorAWSSecret + `"`, 1, "cloud_secret_access_key"},
		{"aws secret 39 fake", `aws_secret_access_key = "` + vendorAWSSecret[:39] + `"`, 0, ""},
		{"aliyun secret 30 ok", `aliyun_access_key_secret = ` + vendorAliyunSk30, 1, "cloud_secret_access_key"},
		{"aliyun secret 29 fake", `aliyun_access_key_secret = ` + vendorAliyunSk30[:29], 0, ""},
		{"tencent secret 32 ok", `tencent_secret_key = ` + vendorTcSk32, 1, "generic_secret_assignment"},
		{"tencent secret 31 fake", `tencent_secret_key = ` + vendorTcSk32[:31], 0, ""},
		{"wechat appsecret 32hex ok", `wx_app_secret = ` + vendorHex32, 1, "generic_secret_assignment"},
		{"wechat appsecret 31hex fake", `wx_app_secret = ` + vendorHex32[:31], 0, ""},
		{"generic appsecret not gated", `app_secret = ` + vendorHex32[:31], 1, "generic_secret_assignment"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := detectVendorFragment(t, detector, "config.env", tc.fragment)
			if len(got) != tc.want {
				t.Fatalf("candidates = %+v, want %d", got, tc.want)
			}
			if tc.want == 1 && got[0].SecretType != tc.wantKind {
				t.Fatalf("kind = %s, want %s", got[0].SecretType, tc.wantKind)
			}
		})
	}
}

// R9.1 MiniMax JWT 例外：仅 MiniMax 专属变量名豁免 isJWTShape 过滤，
// 其他 LLM 变量名的 JWT 值照常放行（防 JWT 噪声回灌）。
func TestMinimaxJWTException(t *testing.T) {
	detector := testDetector(t, "unit-test-fingerprint-key-32-bytes", "")

	got := detectVendorFragment(t, detector, "llm.env", `MINIMAX_API_KEY = "`+vendorJWTKey+`"`)
	if len(got) != 1 || got[0].SecretType != "llm_api_key" {
		t.Fatalf("minimax jwt candidates = %+v, want llm_api_key", got)
	}
	got = detectVendorFragment(t, detector, "llm.env", `OPENAI_API_KEY = "`+vendorJWTKey+`"`)
	if len(got) != 0 {
		t.Fatalf("non-minimax jwt candidates = %+v, want none", got)
	}
}

// R9.1 值级规格表：前缀独立的 LLM key 不再依赖变量名关键词。
func TestLLMValueLevelPatterns(t *testing.T) {
	detector := testDetector(t, "unit-test-fingerprint-key-32-bytes", "")

	cases := []struct {
		value      string
		kind       string
		confidence string
	}{
		{llmOpenAIKey, "openai_api_key", "likely"},
		{llmAnthropicKey, "anthropic_api_key", "likely"},
		{llmGroqKey, "groq_api_key", "likely"},
		{llmOpenRouterKey, "openrouter_api_key", "likely"},
		{llmPerplexityKey, "perplexity_api_key", "likely"},
		{vendorHex32 + ".AbCdEf9134567820", "zhipu_api_key", "likely"}, // secret 段 16 位且避开数字环
		{"bce-v3/ALTAK-" + strings.Repeat("Ak9", 8) + "/" + vendorTcSk32, "qianfan_api_key", "likely"},
		{"xai-" + vendorAliyunSk30, "xai_api_key", "likely"},
		// sk- 泛前缀多厂商共用，无法唯一归属 → 疑似级（R9.1 落地要点）
		{llmSkStyleKey, "sk_style_api_key", "suspected"},
	}
	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			got := detectVendorFragment(t, detector, "snippet.txt", tc.value)
			if len(got) != 1 {
				t.Fatalf("value %q candidates = %+v, want 1", tc.value, got)
			}
			if got[0].SecretType != tc.kind || got[0].Confidence != tc.confidence {
				t.Fatalf("classification = %s/%s, want %s/%s",
					got[0].SecretType, got[0].Confidence, tc.kind, tc.confidence)
			}
		})
	}
}

// R3 动态规则加载可见性：数量为 0 即提示接线问题。
func TestDynamicRuleCountVisibility(t *testing.T) {
	detector := testDetector(t, "unit-test-fingerprint-key-32-bytes", "")
	if detector.DynamicRuleCount() != 0 {
		t.Fatalf("no extra rules configured, dynamic = %d", detector.DynamicRuleCount())
	}
}

// 顺序占位值闸门（实测误报回归）：教学样例值的字符频率熵很高（≈5.0），
// 熵闸拦不住，必须按游程序列特征拦。
func TestSequentialPlaceholderValueGate(t *testing.T) {
	for _, value := range []string{
		"sk-proj-abcdefghijklmnopqrstuvwxyz123456789012345678", // 实测误报：字母表 + 数字环
		"aaaaaaaaaaaaaaaaaaaaaaaa",
		"Ab9Qx4Lm7Ncqwert" + "yuiop" + "Rt8Vk5Za3", // 键盘行内嵌
		"Ab9Qx4Lm7Nc0123456789Rt8Vk5Za3",           // 数字环内嵌
	} {
		if !isSequentialPlaceholderValue(value) {
			t.Fatalf("sequential placeholder %q not detected", value)
		}
	}
	for _, value := range []string{
		vendorAWSSecret,
		vendorTcSk32,
		llmOpenAIKey,
		llmSkStyleKey,
	} {
		if isSequentialPlaceholderValue(value) {
			t.Fatalf("random-looking value %q falsely flagged as sequential", value)
		}
	}
}

// 实测误报（IM 通知）：sk-proj-<字母表><数字环> 曾以 openai_api_key likely 级
// 推送——长度规格（{100,}）+ 顺序闸门双保险，强特征与赋值路径都必须零命中。
func TestOpenAIProjPlaceholderNotDetected(t *testing.T) {
	detector := testDetector(t, "unit-test-fingerprint-key-32-bytes", "")
	strong := detectVendorFragment(t, detector, "readme.md",
		"sk-proj-abcdefghijklmnopqrstuvwxyz123456789012345678")
	if len(strong) != 0 {
		t.Fatalf("placeholder proj key candidates = %+v, want none", strong)
	}
	assigned := detectVendorFragment(t, detector, "demo.env",
		`OPENAI_API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz123456789012345678"`)
	if len(assigned) != 0 {
		t.Fatalf("placeholder assignment candidates = %+v, want none", assigned)
	}
	// 真实长度（100+ 高熵体）不受影响
	real := detectVendorFragment(t, detector, "prod.env",
		"sk-proj-"+strings.Repeat("Ab9Qx4Lm7Nc2Rt8Vk5Za3", 5))
	if len(real) != 1 || real[0].SecretType != "openai_api_key" || real[0].Confidence != "likely" {
		t.Fatalf("realistic proj key = %+v, want likely openai_api_key", real)
	}
}

// 实测误报（IM 通知）：access_token: accesstoken000001（bk-itsm 微信网关文档）。
// 值以自身键名开头 = "键名+编号"文档占位形态；熵恰好压线（3.05 vs 3.0）曾漏网。
func TestSelfEchoPlaceholderGate(t *testing.T) {
	detector := testDetector(t, "unit-test-fingerprint-key-32-bytes", "")
	negatives := []string{
		`access_token: accesstoken000001`,
		`access_token = "accesstoken000002"`,
		`api_key: apikey1234567890`,
		`AUTH_TOKEN=authtoken000001`,
	}
	for _, fragment := range negatives {
		if got := detectVendorFragment(t, detector, "core/api.py", fragment); len(got) != 0 {
			t.Fatalf("self-echo placeholder %q produced candidates: %+v", fragment, got)
		}
	}
	// 正常值不受影响（紧凑形态不以键名开头）
	positives := []string{
		`access_token: "tok_Q7v2Lm9R4x8Nc6Wp3Za5"`,
		`auth_token = Q7v2Lm9R4x8Nc6Wp3Za5Kd2Fb8`,
	}
	for _, fragment := range positives {
		if got := detectVendorFragment(t, detector, "core/api.py", fragment); len(got) == 0 {
			t.Fatalf("normal assignment %q produced no candidates", fragment)
		}
	}
}

// 数据驱动的键名/路径噪声收敛（库存 206 条 new 命中的形态分析：
// WX_TEST_APP_SECRET、hasApiKey/hasSecretKey、logs/ e2e/ demo-repo/ 是
// 确定性最高的误报源）。
func TestKeyAndPathNoiseTuning(t *testing.T) {
	for _, key := range []string{"WX_TEST_APP_SECRET", "hasApiKey", "hasSecretKey", "HAS_TOKEN", "MOCK_TOKEN"} {
		if !isPlaceholderCredentialKey(key) {
			t.Fatalf("placeholder key %q not detected", key)
		}
	}
	for _, key := range []string{"WX_APP_SECRET", "ACCESS_TOKEN", "hashKey", "latest_secret", "contest_key"} {
		if isPlaceholderCredentialKey(key) {
			t.Fatalf("normal key %q falsely flagged", key)
		}
	}
	for _, p := range []string{
		"logs/interactions.jsonl",
		"openclaw/scripts/e2e/upgrade.sh",
		"app/demo-repo/app-vulnerable.py",
		"results/test9/latency.json",
		"conf/mock-server/settings.yml",
	} {
		if !isNoisePath(p) {
			t.Fatalf("noise path %q not detected", p)
		}
	}
	for _, p := range []string{
		"src/testing/guide.py",
		"src/latest/config.py",
		"wechat/core/api.py",
	} {
		if isNoisePath(p) {
			t.Fatalf("normal path %q falsely flagged", p)
		}
	}
	// 端到端：测试键名的赋值命中整条跳过（即便值形态合规）
	detector := testDetector(t, "unit-test-fingerprint-key-32-bytes", "")
	fragment := `WX_TEST_APP_SECRET = ` + vendorHex32
	if got := detectVendorFragment(t, detector, ".env.production", fragment); len(got) != 0 {
		t.Fatalf("test-named key produced candidates: %+v", got)
	}
}
