package githubleak

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func testDetector(t *testing.T, key, token string) *Detector {
	t.Helper()
	detector, err := NewDetector(Settings{
		Token:          token,
		FingerprintKey: key,
		Keywords:       []string{"storage-service"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return detector
}

func syntheticGitHubToken(seed string) string {
	return "ghp_" + seed + "7b9C2d4E6f8G1h3J5k7L9m2N4p6Q8r0S1t3"
}

func candidateOfType(candidates []Candidate, kind string) (Candidate, bool) {
	for _, candidate := range candidates {
		if candidate.SecretType == kind {
			return candidate, true
		}
	}
	return Candidate{}, false
}

func TestDetectorStrongRulesReturnOnlySanitizedEvidence(t *testing.T) {
	key := "unit-test-fingerprint-key-32-bytes"
	detector := testDetector(t, key, "")
	tests := []struct {
		kind string
		raw  string
	}{
		{kind: "github_token", raw: syntheticGitHubToken("A")},
		{kind: "stripe_live_secret", raw: "sk_live_" + "A1b2C3d4E5f6G7h8I9j0K1l2"},
		{kind: "google_api_key", raw: "AIza" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r"},
		{kind: "gitlab_token", raw: "glpat-" + "A1b2C3d4E5f6G7h8I9j0K1l2"},
		// 机器人 ID 用非顺序值：1234567890 是文档教学形态，会被顺序占位闸门拦
		{kind: "telegram_bot_token", raw: "9362517308:AA" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"},
		{kind: "pypi_token", raw: "pypi-" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4"},
		{kind: "docker_hub_pat", raw: "dckr_pat_" + "A1b2C3d4E5f6G7h8I9j0K1l2M"},
		{kind: "im_bot_webhook", raw: "qyapi.weixin.qq.com/cgi-bin/webhook/send?key=1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"},
		{kind: "database_connection_string", raw: "postgres://app:7hZ3xQ9wLm2VtR8@db.internal.local:5432/prod"},
	}
	for _, tc := range tests {
		t.Run(tc.kind, func(t *testing.T) {
			item := SearchItem{
				Repository: "owner/repo", Path: "config.env", BlobSHA: strings.Repeat("a", 40),
				HTMLURL:   "https://github.com/owner/repo/blob/main/config.env",
				Fragments: []string{"value = \"" + tc.raw + "\""},
			}
			candidates := detector.Detect("storage-service", item)
			candidate, ok := candidateOfType(candidates, tc.kind)
			if !ok {
				t.Fatal("strong detector did not return the expected type")
			}
			serialized, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(serialized), tc.raw) || strings.Contains(candidate.MaskedExcerpt, tc.raw) || candidate.Fingerprint == tc.raw {
				t.Fatal("raw credential survived detector sanitization")
			}
			if len(candidate.Fingerprint) != sha256.Size*2 {
				t.Fatalf("fingerprint length = %d", len(candidate.Fingerprint))
			}
			if _, err := hex.DecodeString(candidate.Fingerprint); err != nil {
				t.Fatal("fingerprint is not hexadecimal")
			}
		})
	}
}

func TestDetectorPrivateKeyRequiresCompleteFooterAndSupportsEscapedEncryptedKeys(t *testing.T) {
	detector := testDetector(t, "unit-test-fingerprint-key-32-bytes", "")
	body := "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7V2m9R4x8Nc6W"
	tests := []struct {
		name     string
		fragment string
		want     int
	}{
		{name: "complete pem", fragment: "-----BEGIN " + "PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----", want: 1},
		{name: "encrypted pem", fragment: "-----BEGIN ENCRYPTED " + "PRIVATE KEY-----\n" + body + "\n-----END ENCRYPTED PRIVATE KEY-----", want: 1},
		{name: "json escaped rsa pem", fragment: `{"key":"-----BEGIN RSA ` + `PRIVATE KEY-----\n` + body + `\n-----END RSA PRIVATE KEY-----"}`, want: 1},
		{name: "missing footer", fragment: "-----BEGIN " + "PRIVATE KEY-----\n" + body, want: 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := detector.Detect("private-key", SearchItem{
				Repository: "owner/repo", Path: "key.txt", BlobSHA: strings.Repeat("a", 40),
				HTMLURL: "https://github.com/owner/repo/blob/main/key.txt", Fragments: []string{tc.fragment},
			})
			if len(got) != tc.want {
				t.Fatalf("private key candidates = %+v, want %d", got, tc.want)
			}
			if tc.want == 1 {
				if got[0].SecretType != "private_key" {
					t.Fatalf("private key type = %q", got[0].SecretType)
				}
				// PEM 私钥块没有 key 概念
				if got[0].SecretKey != "" {
					t.Fatalf("private key SecretKey = %q, want empty", got[0].SecretKey)
				}
			}
		})
	}
}

func TestDetectorExcerptNeverRetainsAnyFragmentValue(t *testing.T) {
	detector := testDetector(t, "unit-test-fingerprint-key-32-bytes", "")
	primary := syntheticGitHubToken("B")
	secondary := "111111111111"
	candidates := detector.Detect("vendor.example", SearchItem{
		Repository: "owner/repo", Path: "config.env", BlobSHA: strings.Repeat("a", 40),
		HTMLURL:   "https://github.com/owner/repo/blob/main/config.env",
		Fragments: []string{"AWS_ACCESS_KEY_ID=" + primary + " backup_password=" + secondary},
	})
	if len(candidates) == 0 {
		t.Fatal("GitHub token fixture was not detected")
	}
	for _, candidate := range candidates {
		serialized, err := json.Marshal(candidate)
		if err != nil {
			t.Fatal(err)
		}
		// 明文只允许出现在 SecretValue（json:"-" 不参与序列化），其余通道必须脱敏
		if strings.Contains(string(serialized), primary) || strings.Contains(string(serialized), secondary) {
			t.Fatalf("candidate leaked plaintext outside SecretValue: %s", serialized)
		}
		if want := "<redacted:" + candidate.SecretType + ">"; candidate.MaskedExcerpt != want {
			t.Fatalf("masked excerpt = %q, want fixed marker %q", candidate.MaskedExcerpt, want)
		}
		if candidate.SecretType == "github_token" {
			if candidate.SecretValue != primary {
				t.Fatalf("SecretValue = %q, want the original GitHub token", candidate.SecretValue)
			}
			// 强特征命中(token 本身即凭据)没有 key 概念
			if candidate.SecretKey != "" {
				t.Fatalf("strong-pattern SecretKey = %q, want empty", candidate.SecretKey)
			}
		}
	}
}

func TestDetectorSuppressesGenericDuplicateForStrongAssignment(t *testing.T) {
	detector := testDetector(t, "unit-test-fingerprint-key-32-bytes", "")
	raw := syntheticGitHubToken("D")
	candidates := detector.Detect("storage-service", SearchItem{
		Repository: "owner/repo", Path: "secret.env", BlobSHA: strings.Repeat("b", 40),
		HTMLURL:   "https://github.com/owner/repo/blob/main/secret.env",
		Fragments: []string{"token = \"" + raw + "\""},
	})
	if len(candidates) != 1 || candidates[0].SecretType != "github_token" {
		t.Fatalf("strong assignment produced %d candidates; want one strong candidate", len(candidates))
	}
	if strings.Contains(candidates[0].MaskedExcerpt, raw) {
		t.Fatal("strong assignment excerpt contains the raw credential")
	}
}

func TestDetectorOAuthClientSecretUsesKeyedHMAC(t *testing.T) {
	key := "unit-test-fingerprint-key-32-bytes"
	raw := "Ab9/7Kp2_Qx4-Zm8+Rt6"
	detector := testDetector(t, key, "")
	candidates := detector.Detect("vendor.example", SearchItem{
		Repository: "owner/repo", Path: "settings.ini", BlobSHA: strings.Repeat("c", 40),
		HTMLURL:   "https://github.com/owner/repo/blob/main/settings.ini",
		Fragments: []string{"client_secret = \"" + raw + "\""},
	})
	if len(candidates) != 1 || candidates[0].SecretType != "oauth_client_secret" {
		t.Fatalf("generic assignment candidates = %d", len(candidates))
	}
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write([]byte("oauth_client_secret"))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(raw))
	want := hex.EncodeToString(mac.Sum(nil))
	if candidates[0].Fingerprint != want {
		t.Fatal("generic assignment did not use the configured keyed HMAC")
	}
	if strings.Contains(candidates[0].MaskedExcerpt, raw) {
		t.Fatal("generic assignment excerpt contains the raw credential")
	}
}

func TestDetectorAssignmentSyntaxesAndClientIdentifiersStaySanitized(t *testing.T) {
	detector := testDetector(t, "unit-test-fingerprint-key-32-bytes", "")
	tests := []struct {
		name       string
		fragment   string
		raw        string
		key        string
		kind       string
		confidence string
		severity   string
	}{
		{name: "json client secret", fragment: `{"clientSecret": "Ab9/7Kp2_Qx4-Zm8+Rt6"}`, raw: "Ab9/7Kp2_Qx4-Zm8+Rt6", key: "clientSecret", kind: "oauth_client_secret", confidence: "suspected", severity: "high"},
		{name: "yaml secret access key", fragment: `secretAccessKey: Ab9/7Kp2_Qx4-Zm8+Rt6`, raw: "Ab9/7Kp2_Qx4-Zm8+Rt6", key: "secretAccessKey", kind: "cloud_secret_access_key", confidence: "suspected", severity: "high"},
		{name: "env client secret", fragment: `CLIENT_SECRET=Ab9/7Kp2_Qx4-Zm8+Rt6`, raw: "Ab9/7Kp2_Qx4-Zm8+Rt6", key: "CLIENT_SECRET", kind: "oauth_client_secret", confidence: "suspected", severity: "high"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			item := SearchItem{
				Repository: "owner/repo", Path: "config.txt", BlobSHA: strings.Repeat("a", 40),
				HTMLURL: "https://github.com/owner/repo/blob/main/config.txt", Fragments: []string{tc.fragment},
			}
			candidate, ok := candidateOfType(detector.Detect(`"clientid" AND "vendor.example" in:file`, item), tc.kind)
			if !ok {
				t.Fatalf("%s assignment was not detected", tc.kind)
			}
			if candidate.Confidence != tc.confidence || candidate.Severity != tc.severity {
				t.Fatalf("classification = %s/%s", candidate.Confidence, candidate.Severity)
			}
			serialized, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(serialized), tc.raw) || strings.Contains(candidate.MaskedExcerpt, tc.raw) {
				t.Fatalf("raw assignment value leaked outside SecretValue: %s", serialized)
			}
			if candidate.SecretValue != tc.raw {
				t.Fatalf("SecretValue = %q, want %q", candidate.SecretValue, tc.raw)
			}
			if candidate.SecretKey != tc.key {
				t.Fatalf("SecretKey = %q, want %q", candidate.SecretKey, tc.key)
			}
		})
	}
}

func TestDetectorCredentialFieldFamilies(t *testing.T) {
	detector := testDetector(t, "unit-test-fingerprint-key-32-bytes", "")
	tests := []struct {
		name, fragment, raw, key, kind string
	}{
		{name: "snake api key", fragment: `api_key="ak_live_Q7v2Lm9_R4x8Nc6Wp3Za"`, raw: "ak_live_Q7v2Lm9_R4x8Nc6Wp3Za", key: "api_key", kind: "api_key"},
		{name: "camel api key", fragment: `{"apiKey":"ak_prod_N8z4Kp2_Qx7Lm9R5Vc3W"}`, raw: "ak_prod_N8z4Kp2_Qx7Lm9R5Vc3W", key: "apiKey", kind: "api_key"},
		{name: "compact api key", fragment: `apikey: ak_prod_R5v8Nc3_Wp7Kq2Lm9Xz4`, raw: "ak_prod_R5v8Nc3_Wp7Kq2Lm9Xz4", key: "apikey", kind: "api_key"},
		{name: "header api key", fragment: `x-api-key: "ak_prod_Z4m7Qp2_Ln9Vc5Rx8Kw3"`, raw: "ak_prod_Z4m7Qp2_Ln9Vc5Rx8Kw3", key: "x-api-key", kind: "api_key"},
		{name: "cloud secret", fragment: `AWS_SECRET_ACCESS_KEY="p9/Qx4m7Nc2Rt8Vk5Za3Qw6Yh1Ui4Op2As7DfGhJ"`, raw: "p9/Qx4m7Nc2Rt8Vk5Za3Qw6Yh1Ui4Op2As7DfGhJ", key: "AWS_SECRET_ACCESS_KEY", kind: "cloud_secret_access_key"},
		{name: "oauth client secret", fragment: `oauth_client_secret="cs_Q7v2Lm9_R4x8Nc6Wp3Za"`, raw: "cs_Q7v2Lm9_R4x8Nc6Wp3Za", key: "oauth_client_secret", kind: "oauth_client_secret"},
		{name: "webhook secret", fragment: `SLACK_SIGNING_SECRET="wh_Q7v2Lm9!R4x8#Nc6$Wp3%Za"`, raw: "wh_Q7v2Lm9!R4x8#Nc6$Wp3%Za", key: "SLACK_SIGNING_SECRET", kind: "webhook_signing_secret"},
		{name: "access token", fragment: `ACCESS_TOKEN="tok_Q7v2Lm9!R4x8#Nc6$Wp3%Za"`, raw: "tok_Q7v2Lm9!R4x8#Nc6$Wp3%Za", key: "ACCESS_TOKEN", kind: "auth_token"},
		{name: "bearer variable", fragment: `BEARER_TOKEN="bt_Q7v2Lm9!R4x8#Nc6$Wp3%Za"`, raw: "bt_Q7v2Lm9!R4x8#Nc6$Wp3%Za", key: "BEARER_TOKEN", kind: "bearer_token"},
		{name: "bearer header", fragment: `Authorization: Bearer Q7v2Lm9R4x8Nc6Wp3Za5Kd2Fb8`, raw: "Q7v2Lm9R4x8Nc6Wp3Za5Kd2Fb8", key: "Authorization", kind: "bearer_token"},
		{name: "qianfan sk", fragment: `QIANFAN_SK="QFs_Q7v2Lm9R4x8Nc6Wp3Za"`, raw: "QFs_Q7v2Lm9R4x8Nc6Wp3Za", key: "QIANFAN_SK", kind: "llm_secret_key"},
		{name: "oauth consumer secret", fragment: `CONSUMER_SECRET="cs_Q7v2Lm9_R4x8Nc6Wp3Za"`, raw: "cs_Q7v2Lm9_R4x8Nc6Wp3Za", key: "CONSUMER_SECRET", kind: "oauth_client_secret"},
		{name: "jwt secret", fragment: `JWT_SECRET="jwt_Q7v2Lm9_R4x8Nc6Wp3Za"`, raw: "jwt_Q7v2Lm9_R4x8Nc6Wp3Za", key: "JWT_SECRET", kind: "generic_secret_assignment"},
		{name: "generic secret key", fragment: `SECRET_KEY="sec_Q7v2Lm9_R4x8Nc6Wp3Za"`, raw: "sec_Q7v2Lm9_R4x8Nc6Wp3Za", key: "SECRET_KEY", kind: "generic_secret_assignment"},
		{name: "github named token", fragment: `GITHUB_TOKEN="tok_Q7v2Lm9_R4x8Nc6Wp3Za"`, raw: "tok_Q7v2Lm9_R4x8Nc6Wp3Za", key: "GITHUB_TOKEN", kind: "auth_token"},
		{name: "redis password", fragment: `REDIS_PASSWORD="pw!Q7v2Lm9_R4x8Nc6Wp3Za"`, raw: "pw!Q7v2Lm9_R4x8Nc6Wp3Za", key: "REDIS_PASSWORD", kind: "generic_secret_assignment"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			candidates := detector.Detect("field-family", SearchItem{
				Repository: "owner/repo", Path: "config.env", BlobSHA: strings.Repeat("a", 40),
				HTMLURL: "https://github.com/owner/repo/blob/main/config.env", Fragments: []string{tc.fragment},
			})
			candidate, ok := candidateOfType(candidates, tc.kind)
			if !ok || len(candidates) != 1 {
				t.Fatalf("candidates = %+v, want one %s", candidates, tc.kind)
			}
			data, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), tc.raw) || candidate.MaskedExcerpt != "<redacted:"+tc.kind+">" {
				t.Fatalf("candidate was not fully sanitized: %s", data)
			}
			if candidate.SecretKey != tc.key {
				t.Fatalf("SecretKey = %q, want %q", candidate.SecretKey, tc.key)
			}
		})
	}

	for _, key := range []string{
		"OPENAI_API_KEY", "ANTHROPIC_API_KEY", "DEEPSEEK_API_KEY", "DASHSCOPE_API_KEY",
		"ARK_API_KEY", "MOONSHOT_API_KEY", "ZHIPUAI_API_KEY", "GEMINI_API_KEY",
		"GOOGLE_API_KEY", "GOOGLE_GENAI_API_KEY", "XAI_API_KEY", "FIREWORKS_API_KEY",
		"AZURE_OPENAI_KEY", "REPLICATE_API_TOKEN", "HF_TOKEN",
	} {
		t.Run(key, func(t *testing.T) {
			fragment := key + `="llm_Q7v2Lm9_R4x8Nc6Wp3Za"`
			candidates := detector.Detect("llm", SearchItem{Repository: "owner/repo", Path: "llm.env", BlobSHA: strings.Repeat("b", 40), HTMLURL: "https://github.com/owner/repo/blob/main/llm.env", Fragments: []string{fragment}})
			if len(candidates) != 1 || candidates[0].SecretType != "llm_api_key" {
				t.Fatalf("%s candidates = %+v", key, candidates)
			}
		})
	}
}

func TestDetectorRejectsMetadataPlaceholdersAndClientIDOnly(t *testing.T) {
	detector := testDetector(t, "unit-test-fingerprint-key-32-bytes", "")
	negatives := []string{
		`token password api_key`,
		`token_endpoint=https://auth.example.com/token`,
		`password_policy=Q7v2Lm9_R4x8Nc6Wp3Za`,
		`secret_name=Q7v2Lm9_R4x8Nc6Wp3Za`,
		`api_key_ref=Q7v2Lm9_R4x8Nc6Wp3Za`,
		`OPENAI_API_KEY=sk-your-api-key-here`,
		`OPENAI_API_KEY=${OPENAI_API_KEY}`,
		`OPENAI_API_KEY=$OPENAI_API_KEY`,
		`OPENAI_API_KEY=%OPENAI_API_KEY%`,
		`OPENAI_API_KEY=os.environ["OPENAI_API_KEY"]`,
		`OPENAI_API_KEY=process.env["OPENAI_API_KEY"]`,
		`OPENAI_API_KEY=Environment.GetEnvironmentVariable("OPENAI_API_KEY")`,
		`OPENAI_API_KEY=settings.OPENAI_API_KEY`,
		`client_secret=process.env.OAUTH_CLIENT_SECRET`,
		`password=hunter2`,
		`token=ordinarytokenvalue`,
		`api_key=1234567890123456`,
		"client_secret:\nordinary_value=Q7v2Lm9_R4x8Nc6Wp3Za",
		`client_secret="unterminated_Q7v2Lm9_R4x8Nc6Wp3Za`,
		`client_id=mt_8F3kL7pQ2xV9nR5c`,
		`AWS_ACCESS_KEY_ID=AKIA` + `IOSFODNN7EXAMPLE`,
		`QIANFAN_AK=QF7mP2xN9cR4vK8z`,
		`TWILIO_API_KEY=SK` + `0123456789abcdef0123456789abcdef`,
		`SK` + `0123456789abcdef0123456789abcdef`,
		`token=ghp_` + `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`,
	}
	for _, fragment := range negatives {
		if got := detector.Detect("negative", SearchItem{Repository: "owner/repo", Path: "fixture.txt", BlobSHA: strings.Repeat("c", 40), HTMLURL: "https://github.com/owner/repo/blob/main/fixture.txt", Fragments: []string{fragment}}); len(got) != 0 {
			t.Fatalf("negative fragment %q produced candidates: %+v", fragment, got)
		}
	}

	fragment := `client_id=mt_8F3kL7pQ2xV9nR5c client_secret="cs_Q7v2Lm9_R4x8Nc6Wp3Za"`
	got := detector.Detect("oauth", SearchItem{Repository: "owner/repo", Path: "oauth.env", BlobSHA: strings.Repeat("d", 40), HTMLURL: "https://github.com/owner/repo/blob/main/oauth.env", Fragments: []string{fragment}})
	if len(got) != 1 || got[0].SecretType != "oauth_client_secret" {
		t.Fatalf("client id + secret produced %+v; want only oauth_client_secret", got)
	}

	// AWS 公开标识 + 配对 Secret：AK 强特征按 R8 闸门走（合规 Base32 + 配对完整
	// → likely），Secret 走赋值启发式（suspected）——两类命中并存。
	fragment = `AWS_ACCESS_KEY_ID=AKIA` + `Q2W3E4R5T6Y7UAIO AWS_SECRET_ACCESS_KEY="p9/Qx4m7Nc2Rt8Vk5Za3Qw6Yh1Ui4Op2As7DfGhJ"`
	got = detector.Detect("aws-pair", SearchItem{Repository: "owner/repo", Path: "aws.env", BlobSHA: strings.Repeat("e", 40), HTMLURL: "https://github.com/owner/repo/blob/main/aws.env", Fragments: []string{fragment}})
	if _, ok := candidateOfType(got, "aws_access_key_id"); !ok {
		t.Fatalf("AWS identifier + secret produced %+v; want aws_access_key_id", got)
	}
	if _, ok := candidateOfType(got, "cloud_secret_access_key"); !ok {
		t.Fatalf("AWS identifier + secret produced %+v; want cloud_secret_access_key", got)
	}
	if len(got) != 2 {
		t.Fatalf("AWS identifier + secret produced %+v; want exactly the AK/secret pair", got)
	}
}

func TestMaskOtherSecretsRedactsCompletePunctuatedValues(t *testing.T) {
	raw := "P!ssw0rd?Long#2026&More"
	got := maskOtherSecrets(`provider failed password="` + raw + `"`)
	if strings.Contains(got, raw) || strings.Contains(got, "2026&More") || !strings.Contains(got, "<redacted:generic_secret_assignment>") {
		t.Fatalf("safe error masking retained credential bytes: %q", got)
	}
	unquoted := "Ab9/7Kp2,Qx4;Zm8+Rt6&More"
	got = maskOtherSecrets("provider failed api_key=" + unquoted + " retry denied")
	if strings.Contains(got, unquoted) || strings.Contains(got, "Qx4;Zm8") || !strings.Contains(got, "<redacted:api_key>") {
		t.Fatalf("safe error masking retained an unquoted credential tail: %q", got)
	}
	got = maskOtherSecrets(`provider failed client_secret="Ab9/7Kp2,Qx4;Zm8+Rt6&More`)
	if strings.Contains(got, "Qx4;Zm8") || !strings.Contains(got, "<redacted:oauth_client_secret>") {
		t.Fatalf("safe error masking retained an unterminated credential tail: %q", got)
	}
	first, second := "Ak9/Qx4,Lm7+Nc2", "Cs8/Rt5;Wp3+Za6"
	got = maskOtherSecrets("api_key=" + first + ",client_secret=" + second)
	if strings.Contains(got, first) || strings.Contains(got, second) || !strings.Contains(got, "<redacted:api_key>") {
		t.Fatalf("safe error masking mishandled overlapping assignments: %q", got)
	}
}

func TestDetectorExplicitFingerprintKeyIsStableAcrossGitHubTokenChanges(t *testing.T) {
	raw := syntheticGitHubToken("E")
	item := SearchItem{
		Repository: "owner/repo", Path: "token.txt", BlobSHA: strings.Repeat("d", 40),
		HTMLURL:   "https://github.com/owner/repo/blob/main/token.txt",
		Fragments: []string{raw},
	}
	first, ok := candidateOfType(testDetector(t, "stable-fingerprint-key-material", "first-unit-token").Detect("storage-service", item), "github_token")
	if !ok {
		t.Fatal("first detector did not identify the strong token fixture")
	}
	second, ok := candidateOfType(testDetector(t, "stable-fingerprint-key-material", "second-unit-token").Detect("storage-service", item), "github_token")
	if !ok {
		t.Fatal("second detector did not identify the strong token fixture")
	}
	if first.Fingerprint != second.Fingerprint {
		t.Fatal("GitHub token rotation changed an explicitly keyed fingerprint")
	}
	other, ok := candidateOfType(testDetector(t, "different-fingerprint-key-material", "second-unit-token").Detect("storage-service", item), "github_token")
	if !ok || other.Fingerprint == first.Fingerprint {
		t.Fatal("different HMAC keys did not produce independent fingerprints")
	}
}

func TestDetectorHexFingerprintKeyPreservesLegacyTokenFingerprints(t *testing.T) {
	legacyToken := "legacy-unit-test-pat"
	replacementToken := "rotated-unit-test-pat"
	raw := syntheticGitHubToken("H")
	item := SearchItem{
		Repository: "owner/repo", Path: "token.txt", BlobSHA: strings.Repeat("e", 40),
		HTMLURL:   "https://github.com/owner/repo/blob/main/token.txt",
		Fragments: []string{raw},
	}
	legacy, ok := candidateOfType(testDetector(t, "", legacyToken).Detect("storage-service", item), "github_token")
	if !ok {
		t.Fatal("legacy token-derived detector did not identify the fixture")
	}
	digest := sha256.Sum256([]byte("4zreco/githubleak/fingerprint/v1\x00" + legacyToken))
	migratedKey := "hex:" + hex.EncodeToString(digest[:])
	migrated, ok := candidateOfType(testDetector(t, migratedKey, replacementToken).Detect("storage-service", item), "github_token")
	if !ok {
		t.Fatal("hex-key detector did not identify the fixture")
	}
	if migrated.Fingerprint != legacy.Fingerprint {
		t.Fatal("hex migration key changed the legacy token-derived fingerprint")
	}
	if _, err := NewDetector(Settings{FingerprintKey: "hex:not-a-64-byte-key", Keywords: []string{"storage-service"}}); err == nil {
		t.Fatal("invalid hex fingerprint key was accepted")
	}
}

func TestDetectorRequiresFingerprintMaterial(t *testing.T) {
	if _, err := NewDetector(Settings{Keywords: []string{"storage-service"}}); err == nil {
		t.Fatal("detector accepted empty token and fingerprint key")
	}
}

func TestDetectorOnlyUsesTrustedGitHubURLLine(t *testing.T) {
	detector := testDetector(t, "unit-test-fingerprint-key-32-bytes", "")
	raw := syntheticGitHubToken("F")
	item := SearchItem{
		Repository: "owner/repo", Path: "token.txt", BlobSHA: strings.Repeat("e", 40),
		HTMLURL:   "https://github.com/owner/repo/blob/main/token.txt",
		Fragments: []string{"first line\n" + raw},
	}
	candidate, ok := candidateOfType(detector.Detect("storage-service", item), "github_token")
	if !ok || candidate.Line != 0 {
		t.Fatalf("fragment-relative line was trusted: %+v", candidate)
	}
	item.HTMLURL += "#L42"
	candidate, ok = candidateOfType(detector.Detect("storage-service", item), "github_token")
	if !ok || candidate.Line != 42 {
		t.Fatalf("trusted URL line was not used: %+v", candidate)
	}
}

func TestDetectorMasksOtherCredentialLikeValueOnExcerptLine(t *testing.T) {
	detector := testDetector(t, "unit-test-fingerprint-key-32-bytes", "")
	primary := syntheticGitHubToken("G")
	secondary := "Z9aB7cD5eF3gH1"
	candidate, ok := candidateOfType(detector.Detect("storage-service", SearchItem{
		Repository: "owner/repo", Path: "token.txt", BlobSHA: strings.Repeat("f", 40),
		HTMLURL:   "https://github.com/owner/repo/blob/main/token.txt",
		Fragments: []string{"token=" + primary + " other=" + secondary},
	}), "github_token")
	if !ok || strings.Contains(candidate.MaskedExcerpt, primary) || strings.Contains(candidate.MaskedExcerpt, secondary) {
		t.Fatalf("masked excerpt retained a credential-like value: %q", candidate.MaskedExcerpt)
	}
}

// 回归：代码表达式（util.GetFromEnv("ALIBABA_CLOUD_ACCESS_KEY_SECRET"...）曾被
// 当作凭据值提取并进入 IM 通知的 key 行；单行匹配含代码上下文字符必须拒绝。
func TestDetectRejectsCodeExpressionAsSecretValue(t *testing.T) {
	detector := testDetector(t, "unit-test-fingerprint-key-32-bytes", "")
	fragment := `client := util.GetFromEnv("ALIBABA_CLOUD_ACCESS_KEY_SECRET")`
	got := detector.Detect("aliyun-ak", SearchItem{
		Repository: "owner/repo", Path: "main.go", BlobSHA: strings.Repeat("b", 40),
		HTMLURL: "https://github.com/owner/repo/blob/main/main.go", Fragments: []string{fragment},
	})
	for _, c := range got {
		if strings.ContainsAny(c.SecretValue, "()\"") {
			t.Fatalf("代码表达式混入凭据值: %q", c.SecretValue)
		}
	}
}

// 值级精细分类（自上游移植）：环境变量/配置引用、哨兵说明值、标识符形态、
// 经典示例序列都不是凭据明文，赋值类命中必须全部拒绝。
func TestDetectorRejectsReferenceSentinelAndSymbolicValues(t *testing.T) {
	detector := testDetector(t, "unit-test-fingerprint-key-32-bytes", "")
	negatives := []string{
		`api_key=`,
		`api_key=""`,
		`api_key='   '`,
		`api_key=null`,
		`api_key=undefined`,
		`api_key="YOUR API KEY HERE"`,
		`api_key=TEST_API_KEY_123456789`,
		`api_key=FAKE_API_KEY_123456789`,
		`api_key=REDACTED_API_KEY_VALUE`,
		`api_key=MASKED_API_KEY_VALUE`,
		`api_key=INSERT_API_KEY_HERE`,
		`api_key=api-key-goes-here`,
		`api_key=__PRODUCTION_API_KEY__`,
		`api_key=PRODUCTION_API_KEY`,
		`api_key=getenv("OPENAI_API_KEY")`,
		`api_key=get_env("OPENAI_API_KEY")`,
		`api_key=ENV["OPENAI_API_KEY"]`,
		`api_key=ENV.fetch("OPENAI_API_KEY")`,
		`api_key=Deno.env.get("OPENAI_API_KEY")`,
		`api_key=Bun.env.OPENAI_API_KEY`,
		`api_key=import.meta.env.OPENAI_API_KEY`,
		`api_key=std::env::var("OPENAI_API_KEY")`,
		`api_key=System.getProperty("service.api.key")`,
		`api_key=configuration["OPENAI_API_KEY"]`,
		`api_key=.Values.openai.apiKey`,
		`api_key=loadConfig().openaiApiKey`,
		`api_key=flag.String("api-key", "", "OpenAI credential")`,
		`api_key=parser.add_argument("--api-key", default="")`,
		`api_key=getSecret("openai")`,
		`api_key=readFile("/run/secrets/openai")`,
		`api_key=data.aws_secretsmanager_secret_version.openai.secret_string`,
		`api_key=/run/secrets/openai_api_key`,
		`api_key=file:///run/secrets/api-key`,
		`api_key="<%= ENV.fetch('OPENAI_API_KEY') %>"`,
		`api_key=*openai_api_key_secret`,
		`api_key="0123456789abcdef"`,
	}
	for _, fragment := range negatives {
		t.Run(fragment, func(t *testing.T) {
			got := detector.Detect("api-key-negative", SearchItem{
				Repository: "owner/repo", Path: "config.txt", BlobSHA: strings.Repeat("f", 40),
				HTMLURL: "https://github.com/owner/repo/blob/main/config.txt", Fragments: []string{fragment},
			})
			if len(got) != 0 {
				t.Fatalf("placeholder/reference %q produced candidates: %+v", fragment, got)
			}
		})
	}
}

// 反例：真正的不透明随机值不能被新过滤器误杀。
func TestDetectorKeepsOpaqueAssignedValues(t *testing.T) {
	detector := testDetector(t, "unit-test-fingerprint-key-32-bytes", "")
	positives := []string{
		`api_key="ak_live_Q7v2Lm9_R4x8Nc6Wp3Za"`,     // gitleaks:allow -- 合成测试样本
		`api_key="aB3dE5fG7hJ9kL2mN4pQ6rS8tV0xY1zC"`, // gitleaks:allow -- 合成测试样本
		`api_key="secret_live_Ab9xQ7v2Lm9R4Nc6"`,     // gitleaks:allow -- 合成测试样本
		`api_key="Ab9/7Kp2_Qx4-Zm8+Rt6"`,             // gitleaks:allow -- 合成测试样本
	}
	for _, fragment := range positives {
		t.Run(fragment, func(t *testing.T) {
			got := detector.Detect("api-key-positive", SearchItem{
				Repository: "owner/repo", Path: "config.txt", BlobSHA: strings.Repeat("e", 40),
				HTMLURL: "https://github.com/owner/repo/blob/main/config.txt", Fragments: []string{fragment},
			})
			if len(got) != 1 || got[0].SecretType != "api_key" {
				t.Fatalf("opaque API key %q produced %+v", fragment, got)
			}
		})
	}
}

// 值形态闸：真实运营数据的高频误报类——值是代码表达式/配置路径/句子，而非凭据字面量。
func TestDetectorRejectsNonLiteralValues(t *testing.T) {
	detector := testDetector(t, "unit-test-fingerprint-key-32-bytes", "")
	negatives := []string{
		`api_key=value_as_string(`,
		`api_key=super().encryption(model.get('qianfan_sk'`,
		`api_key=("llm_providers"`,
		`api_key=/data/attributes/secret/access_key_secret`,
		`api_key=options?.QIANFAN_SK`,
		`api_key="some sentence with spaces"`,
		`api_key=cfg.items["x"]`,
		`api_key=<%= credentialValue %>`,
		`api_key=foo|bar`,
	}
	for _, fragment := range negatives {
		t.Run(fragment, func(t *testing.T) {
			got := detector.Detect("non-literal", SearchItem{
				Repository: "owner/repo", Path: "config.txt", BlobSHA: strings.Repeat("d", 40),
				HTMLURL: "https://github.com/owner/repo/blob/main/config.txt", Fragments: []string{fragment},
			})
			if len(got) != 0 {
				t.Fatalf("non-literal value %q produced candidates: %+v", fragment, got)
			}
		})
	}
}

// 标识符形态闸：i18n 翻译键/枚举映射表值（纯单一大小写+连接符、无数字）不是凭据。
// 真实运营误报回归：prowler UI 映射表 SERVICE_ACCOUNT_KEY: "service_account_key"。
func TestDetectorRejectsIdentifierShapeValues(t *testing.T) {
	detector := testDetector(t, "unit-test-fingerprint-key-32-bytes", "")
	negatives := []string{
		`SERVICE_ACCOUNT_KEY: "service_account_key"`, // prowler UI 字段映射表（真实误报）
		`SECRET_KEY: "some_translations_key_here"`,   // i18n 翻译键
		`CLIENT_SECRET: "client-secret-label-text"`,  // 文案标签
		`SIGNING_KEY: "SIGNING_KEY_ENUM_VALUE"`,      // 全大写枚举名（无凭据词汇故旧闸不拦）
		`SIGNING_KEY: "auth.signing.key.name.here"`,  // 配置属性路径
	}
	for _, fragment := range negatives {
		t.Run(fragment, func(t *testing.T) {
			got := detector.Detect("identifier-shape", SearchItem{
				Repository: "owner/repo", Path: "ui/fields.ts", BlobSHA: strings.Repeat("c", 40),
				HTMLURL: "https://github.com/owner/repo/blob/main/ui/fields.ts", Fragments: []string{fragment},
			})
			if len(got) != 0 {
				t.Fatalf("identifier-shape value %q produced candidates: %+v", fragment, got)
			}
		})
	}
	// 含数字或大小写混合的值不受影响——闸门只针对纯标识符形态。
	positives := []string{
		`SECRET_KEY="sec_Q7v2Lm9_R4x8Nc6Wp3Za"`, // gitleaks:allow -- 合成测试样本（大小写混合）
		`SECRET_KEY="serviceaccountkey2024"`,    // gitleaks:allow -- 合成测试样本（含数字）
	}
	for _, fragment := range positives {
		t.Run(fragment, func(t *testing.T) {
			got := detector.Detect("identifier-shape-positive", SearchItem{
				Repository: "owner/repo", Path: "config.txt", BlobSHA: strings.Repeat("b", 40),
				HTMLURL: "https://github.com/owner/repo/blob/main/config.txt", Fragments: []string{fragment},
			})
			if len(got) != 1 {
				t.Fatalf("opaque value %q was blocked by identifier gate: %+v", fragment, got)
			}
		})
	}
}

// 微信支付商户密钥族（mch_key/APIv3/partner_key）与小程序 session_key 分类
// （批次二：小程序 AK/SK 监控面）。支付密钥规范长度 32，按 high 处置。
func TestDetectorWeChatPayAndMiniappSessionKeyFamilies(t *testing.T) {
	detector := testDetector(t, "unit-test-fingerprint-key-32-bytes", "")
	tests := []struct {
		name, fragment, key, kind string
	}{
		{name: "mch key", fragment: `MCH_KEY = "Q7v2Lm9R4Nc6Wp3ZaB8dF2gH5jK7lM9x"`, key: "MCH_KEY", kind: "wechat_pay_secret"},
		{name: "api v3 key camel", fragment: `apiV3Key: "R8w3Nn6Qq2Xr7Yt5Vb9Gd2Fh6Jk8Lm1z"`, key: "apiV3Key", kind: "wechat_pay_secret"},
		{name: "partner key v2", fragment: `partner_key="S9x4Oo7Rr3Ys8Zu6Wc1He3Gi7Kl9Mn2a"`, key: "partner_key", kind: "wechat_pay_secret"},
		{name: "miniapp session key", fragment: `session_key = "T1y5Pp8Ss4Zt9Av7Xd2If4Hj8Lm1No3b"`, key: "session_key", kind: "generic_secret_assignment"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			candidates := detector.Detect("wechat-family", SearchItem{
				Repository: "owner/repo", Path: "wxpay.go", BlobSHA: strings.Repeat("c", 40),
				HTMLURL: "https://github.com/owner/repo/blob/main/wxpay.go", Fragments: []string{tc.fragment},
			})
			if len(candidates) != 1 || candidates[0].SecretType != tc.kind {
				t.Fatalf("candidates = %+v, want one %s", candidates, tc.kind)
			}
			if candidates[0].SecretKey != tc.key {
				t.Fatalf("SecretKey = %q, want %q", candidates[0].SecretKey, tc.key)
			}
		})
	}
	// 短于最小长度的支付密钥形态不产生候选。
	short := detector.Detect("wechat-family-negative", SearchItem{
		Repository: "owner/repo", Path: "wxpay.go", BlobSHA: strings.Repeat("d", 40),
		HTMLURL: "https://github.com/owner/repo/blob/main/wxpay.go", Fragments: []string{`MCH_KEY = "short123"`},
	})
	if len(short) != 0 {
		t.Fatalf("short mch key produced candidates: %+v", short)
	}
}

// 合法字面量（含 / 的 base64、bcrypt/argon2 哈希、PEM 块、连接串）不受形态闸影响。
func TestNonLiteralGateKeepsLegitimateLiterals(t *testing.T) {
	pem := "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA7xQ\n-----END RSA PRIVATE KEY-----" // gitleaks:allow -- 合成测试样本
	if isNonLiteralCredentialValue(pem) {
		t.Fatal("PEM 私钥块不应被形态闸拦截")
	}
	for _, v := range []string{
		"Ab9/7Kp2_Qx4-Zm8+Rt6",           // gitleaks:allow -- 合成测试样本
		"Qw9/Zm8+Rt6=abc",                // gitleaks:allow -- 合成测试样本
		"sv=2024-01-01&sig=AbCdEf123456", // gitleaks:allow -- 合成测试样本
		"$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy", // gitleaks:allow -- 合成测试样本
	} {
		if isNonLiteralCredentialValue(v) {
			t.Fatalf("合法字面量被形态闸误拦: %q", v)
		}
	}
}
