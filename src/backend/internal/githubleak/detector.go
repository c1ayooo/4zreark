package githubleak

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

type secretPattern struct {
	name       string
	re         *regexp.Regexp
	confidence string
	severity   string
	group      int // >0 时取正则子匹配（gitleaks secretGroup 语义）
}

type assignmentSpec struct {
	kind       string
	confidence string
	severity   string
	minLength  int
	minEntropy float64
	minClasses int
}

var strongSecretPatterns = []secretPattern{
	{name: "github_token", re: regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,255}\b`), confidence: "likely", severity: "critical"},
	{name: "github_fine_grained_token", re: regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{40,255}\b`), confidence: "likely", severity: "critical"},
	{name: "gitlab_token", re: regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,255}\b`), confidence: "likely", severity: "critical"},
	{name: "google_api_key", re: regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`), confidence: "likely", severity: "high"},
	{name: "slack_token", re: regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{20,250}\b`), confidence: "likely", severity: "high"},
	{name: "telegram_bot_token", re: regexp.MustCompile(`\b[1-9][0-9]{7,9}:AA[A-Za-z0-9_-]{33}\b`), confidence: "likely", severity: "high"},
	{name: "stripe_live_secret", re: regexp.MustCompile(`\bsk_live_[A-Za-z0-9]{16,255}\b`), confidence: "likely", severity: "critical"},
	{name: "sendgrid_api_key", re: regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b`), confidence: "likely", severity: "critical"},
	{name: "npm_token", re: regexp.MustCompile(`\bnpm_[A-Za-z0-9]{24,255}\b`), confidence: "likely", severity: "high"},
	{name: "pypi_token", re: regexp.MustCompile(`\bpypi-[A-Za-z0-9_-]{20,255}\b`), confidence: "likely", severity: "high"},
	{name: "docker_hub_pat", re: regexp.MustCompile(`\bdckr_pat_[A-Za-z0-9_-]{20,255}\b`), confidence: "likely", severity: "high"},
	// AWS AccessKey：AKIA(长期)/ASIA(临时)/ABIA/ACCA + 16 位。正则放宽到 [0-9A-Z]，
	// Base32 精确判定交给 vendor 闸门（违规降级 suspected，见 vendor.go strongPatternGates）；
	// 单 AK 无配对 Secret 由 pairingGates 降级。
	{name: "aws_access_key_id", re: regexp.MustCompile(`\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b`), confidence: "likely", severity: "critical"},
	// 中文云厂商主凭据（SRC/授权评估场景最高价值捕获类）：
	// 阿里云 AccessKey（LTAI 前缀 + 12~20 位）、腾讯云 SecretId（AKID 前缀，gitleaks 同款边界）
	{name: "aliyun_access_key", re: regexp.MustCompile(`\bLTAI[0-9A-Za-z]{12,20}\b`), confidence: "likely", severity: "critical"},
	{name: "tencentcloud_secret_id", re: regexp.MustCompile(`\bAKID[0-9A-Za-z]{13,40}\b`), confidence: "likely", severity: "high"},
	// LLM API key 值级强模式（R9.1 规格表：前缀独立的直接判定，不再依赖变量名关键词）。
	// OpenAI 新前缀（proj/svcacct/admin）：真实 key 总长 150+（文档 R8-1/R9.1 规格），
	// 短于 100 的几乎全是文档示例 / LLM 生成的假 key；旧版 sk-+48 与
	// DeepSeek/Moonshot/DashScope/SiliconFlow 共用 sk- 泛前缀无法唯一归属
	// → sk_style_api_key 疑似级单独一条。
	{name: "openai_api_key", re: regexp.MustCompile(`\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{100,}\b`), confidence: "likely", severity: "critical"},
	{name: "anthropic_api_key", re: regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{32,}\b`), confidence: "likely", severity: "critical"},
	{name: "sk_style_api_key", re: regexp.MustCompile(`\bsk-[A-Za-z0-9]{28,64}\b`), confidence: "suspected", severity: "high"},
	{name: "groq_api_key", re: regexp.MustCompile(`\bgsk_[A-Za-z0-9]{40,60}\b`), confidence: "likely", severity: "critical"},
	{name: "openrouter_api_key", re: regexp.MustCompile(`\bsk-or-v1-[A-Za-z0-9]{40,80}\b`), confidence: "likely", severity: "critical"},
	{name: "perplexity_api_key", re: regexp.MustCompile(`\bpplx-[A-Za-z0-9]{32,48}\b`), confidence: "likely", severity: "high"},
	// 智谱：id.secret 两段形态（32 位 hex + '.' + 16 位字母数字），sk- 规则覆盖不到
	{name: "zhipu_api_key", re: regexp.MustCompile(`\b[0-9a-f]{32}\.[A-Za-z0-9]{16}\b`), confidence: "likely", severity: "critical"},
	// 百度千帆 v2 认证形态（bce-v3/ALTAK-<ak>/<sk>）
	{name: "qianfan_api_key", re: regexp.MustCompile(`\bbce-v3/ALTAK-[A-Za-z0-9]{16,48}/[A-Za-z0-9]{16,64}\b`), confidence: "likely", severity: "critical"},
	// xAI（Grok）：xai- 独立前缀
	{name: "xai_api_key", re: regexp.MustCompile(`\bxai-[A-Za-z0-9]{20,}\b`), confidence: "likely", severity: "critical"},
	// HuggingFace 访问令牌（模型权重/数据集凭据）
	{name: "huggingface_token", re: regexp.MustCompile(`\bhf_[A-Za-z0-9]{34,40}\b`), confidence: "likely", severity: "medium"},
	// Discord Webhook（机器人推送入口，与 IM webhook 同级风险）
	{name: "discord_webhook", re: regexp.MustCompile(`(?i)discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_-]{60,68}`), confidence: "likely", severity: "medium"},
	// 国内 IM 机器人推送入口（企微/钉钉/飞书）：泄露即可向目标组织发消息，红队常用于权限维持
	{name: "im_bot_webhook", re: regexp.MustCompile(`(?i)\b(?:qyapi\.weixin\.qq\.com/cgi-bin/webhook/send\?key=[0-9a-f-]{32,36}|oapi\.dingtalk\.com/robot/send\?access_token=[0-9a-f]{64}|open\.feishu\.cn/open-apis/bot/v2/hook/[0-9a-f-]{30,40})`), confidence: "likely", severity: "medium"},
	// 带凭据的数据库/消息队列连接串（user:pass@ 形态，redis 允许 :pass@ 空用户）
	{name: "database_connection_string", re: regexp.MustCompile(`(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|clickhouse)://[^\s:'"<>()@]{0,64}:[^\s'"<>()@]{1,128}@[^\s'"<>()]+`), confidence: "likely", severity: "high"},
	{name: "private_key", re: regexp.MustCompile(`(?s)-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----[ \t]*(?:\r?\n|\\n|\\r\\n)(?:[A-Za-z0-9+/=]|\\/|\\r|\\n|\r|\n){32,}?(?:\r?\n|\\n|\\r\\n)-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----`), confidence: "likely", severity: "critical"},
}

var credentialAssignmentStartRE = regexp.MustCompile(`(?m)(?:^|[ \t{};,]|\[)(?:"([A-Za-z][A-Za-z0-9_.-]{1,127})"|'([A-Za-z][A-Za-z0-9_.-]{1,127})'|` + "`" + `([A-Za-z][A-Za-z0-9_.-]{1,127})` + "`" + `|([A-Za-z][A-Za-z0-9_.-]{1,127}))[ \t]*[:=][ \t]*`)

var (
	apiKeySpec            = assignmentSpec{kind: "api_key", confidence: "suspected", severity: "high", minLength: 16, minEntropy: 3.0, minClasses: 2}
	llmAPIKeySpec         = assignmentSpec{kind: "llm_api_key", confidence: "suspected", severity: "high", minLength: 16, minEntropy: 3.0, minClasses: 2}
	llmAccessKeySpec      = assignmentSpec{kind: "llm_access_key", confidence: "suspected", severity: "medium", minLength: 12, minEntropy: 2.8, minClasses: 2}
	llmSecretKeySpec      = assignmentSpec{kind: "llm_secret_key", confidence: "suspected", severity: "high", minLength: 16, minEntropy: 3.0, minClasses: 2}
	cloudAccessKeyIDSpec  = assignmentSpec{kind: "cloud_access_key_id", confidence: "suspected", severity: "medium", minLength: 12, minEntropy: 2.8, minClasses: 2}
	cloudSecretKeySpec    = assignmentSpec{kind: "cloud_secret_access_key", confidence: "suspected", severity: "high", minLength: 16, minEntropy: 3.0, minClasses: 2}
	oauthClientSecretSpec = assignmentSpec{kind: "oauth_client_secret", confidence: "suspected", severity: "high", minLength: 16, minEntropy: 3.0, minClasses: 2}
	// wechatPaySecretSpec 微信支付商户密钥族（mch_key/APIv3 密钥/partner_key，
	// 规范长度 32）：泄露可直接伪造支付回调签名，按 high 处置。
	wechatPaySecretSpec    = assignmentSpec{kind: "wechat_pay_secret", confidence: "suspected", severity: "high", minLength: 16, minEntropy: 3.0, minClasses: 2}
	webhookSecretSpec      = assignmentSpec{kind: "webhook_signing_secret", confidence: "suspected", severity: "high", minLength: 16, minEntropy: 3.0, minClasses: 2}
	authTokenSpec          = assignmentSpec{kind: "auth_token", confidence: "suspected", severity: "high", minLength: 16, minEntropy: 3.0, minClasses: 2}
	strictBareTokenSpec    = assignmentSpec{kind: "auth_token", confidence: "suspected", severity: "high", minLength: 24, minEntropy: 3.5, minClasses: 2}
	bearerTokenSpec        = assignmentSpec{kind: "bearer_token", confidence: "suspected", severity: "high", minLength: 16, minEntropy: 3.0, minClasses: 2}
	genericNamedSecretSpec = assignmentSpec{kind: "generic_secret_assignment", confidence: "suspected", severity: "medium", minLength: 16, minEntropy: 3.2, minClasses: 2}
	passwordSecretSpec     = assignmentSpec{kind: "generic_secret_assignment", confidence: "suspected", severity: "medium", minLength: 16, minEntropy: 3.3, minClasses: 3}
)

type Detector struct {
	hmacKey []byte
	dynamic []secretPattern // 运行时导入规则（gitleaks 等，ExtraRulesPath）
}

func NewDetector(settings Settings) (*Detector, error) {
	normalized, err := settings.Normalize()
	if err != nil {
		return nil, err
	}
	key := []byte(normalized.FingerprintKey)
	if len(normalized.FingerprintKey) >= 4 && strings.EqualFold(normalized.FingerprintKey[:4], "hex:") {
		encoded := normalized.FingerprintKey[4:]
		if len(encoded) != sha256.Size*2 {
			return nil, errors.New("hex fingerprint key must contain exactly 64 hexadecimal characters")
		}
		key, err = hex.DecodeString(encoded)
		if err != nil {
			return nil, errors.New("hex fingerprint key is invalid")
		}
	}
	if len(key) == 0 && normalized.Token != "" {
		digest := sha256.Sum256([]byte("4zreco/githubleak/fingerprint/v1\x00" + normalized.Token))
		key = digest[:]
	}
	if len(key) < 16 {
		return nil, errors.New("a GitHub token or fingerprint key is required for HMAC fingerprints")
	}
	detector := &Detector{hmacKey: append([]byte(nil), key...)}
	detector.loadDynamicRules(normalized.ExtraRulesPath)
	return detector, nil
}

// loadDynamicRules 加载运行时导入规则（JSON 数组：id/description/regex/secret_group/severity）。
// 文件不存在静默忽略；坏正则逐条跳过——动态规则是可选增强，任何异常不阻断监控启动。
func (d *Detector) loadDynamicRules(path string) {
	path = strings.TrimSpace(path)
	if path == "" {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var payload struct {
		Rules []struct {
			ID          string `json:"id"`
			Description string `json:"description"`
			Regex       string `json:"regex"`
			SecretGroup int    `json:"secret_group"`
			Severity    string `json:"severity"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return
	}
	loaded := 0
	for _, rule := range payload.Rules {
		id := strings.TrimSpace(rule.ID)
		expr := strings.TrimSpace(rule.Regex)
		if id == "" || expr == "" {
			continue
		}
		compiled, err := regexp.Compile(expr)
		if err != nil {
			continue
		}
		severity := strings.TrimSpace(rule.Severity)
		if severity == "" {
			severity = "medium"
		}
		d.dynamic = append(d.dynamic, secretPattern{
			name:       "gitleaks:" + id,
			re:         compiled,
			confidence: "likely",
			severity:   severity,
			group:      rule.SecretGroup,
		})
		loaded++
	}
}

// DynamicRuleCount 动态规则（gitleaks 导入产物）加载数量，供启动日志暴露——
// 规则加载失败当前是静默的，数量为 0 即提示接线问题（文档 R3 注意点 2）。
func (d *Detector) DynamicRuleCount() int {
	if d == nil {
		return 0
	}
	return len(d.dynamic)
}

// Detect returns only sanitized candidates. Raw matches remain local to this
// function and are never included in the returned value.
// rawMatch 检测中间态：明文只存活在本次调用内（Detect/RevealValues 均不持久化）。
type rawMatch struct {
	kind, confidence, severity, fingerprint, raw string
	line                                         int
	// key 赋值类命中(KEY = value)源码里的实际字段名;强特征命中(自带
	// 特征前缀的 token/私钥块)没有 key 概念,保持为空。
	key string
}

// Detect returns only sanitized candidates. Raw matches remain local to this
// function and are never included in the returned value.
func (d *Detector) Detect(keyword string, item SearchItem) []Candidate {
	matches := d.detectAll(item)
	results := make([]Candidate, 0, len(matches))
	for _, m := range matches {
		results = append(results, Candidate{
			Keyword: keyword, Repository: item.Repository, Path: item.Path,
			BlobSHA: item.BlobSHA, Line: m.line, SecretType: m.kind,
			Confidence: m.confidence, Severity: m.severity, Fingerprint: m.fingerprint,
			MaskedExcerpt: "<redacted:" + m.kind + ">",
			HTMLURL:       item.HTMLURL,
			SecretValue:   m.raw,
			SecretKey:     m.key,
		})
	}
	return results
}

// RevealValues 为已存命中找回原始明文：对给定内容重跑检测，返回与
// fingerprint 匹配的原文（一次调用即弃，调用方负责审计与不落库）。
func (d *Detector) RevealValues(item SearchItem) []rawMatch {
	return d.detectAll(item)
}

func (d *Detector) detectAll(item SearchItem) []rawMatch {
	if d == nil || len(d.hmacKey) == 0 {
		return nil
	}
	results := make([]rawMatch, 0)
	seen := map[string]struct{}{}
	line := lineNumberFromURL(item.HTMLURL)
	for _, fragment := range item.Fragments {
		if !utf8.ValidString(fragment) || len(fragment) > 64<<10 {
			continue
		}
		strongRanges := make([][2]int, 0)
		for _, pattern := range strongSecretPatterns {
			for _, loc := range pattern.re.FindAllStringIndex(fragment, -1) {
				if len(loc) != 2 || loc[0] < 0 || loc[1] <= loc[0] {
					continue
				}
				raw := fragment[loc[0]:loc[1]]
				if !credibleStrongSecret(raw) {
					continue
				}
				// 连接串二次校验：示例口令/本地服务名主机为教学样板
				if pattern.name == "database_connection_string" && !credibleDatabaseURL(raw) {
					continue
				}
				strongRanges = append(strongRanges, [2]int{loc[0], loc[1]})
				fingerprint := d.fingerprint(pattern.name, raw)
				seenKey := pattern.name + ":" + strconv.Itoa(line) + ":" + fingerprint
				if _, ok := seen[seenKey]; ok {
					continue
				}
				seen[seenKey] = struct{}{}
				confidence := pattern.confidence
				if gate, ok := strongPatternGates[pattern.name]; ok && gate(raw) {
					confidence = "suspected"
				}
				results = append(results, rawMatch{kind: pattern.name, confidence: confidence, severity: pattern.severity, fingerprint: fingerprint, raw: raw, line: line})
			}
		}
		for _, pattern := range d.dynamic {
			if pattern.group > 0 {
				for _, loc := range pattern.re.FindAllStringSubmatchIndex(fragment, -1) {
					if len(loc) < 2*(pattern.group+1) {
						continue
					}
					start, end := loc[2*pattern.group], loc[2*pattern.group+1]
					if start < 0 || end <= start {
						continue
					}
					raw := fragment[start:end]
					if !credibleStrongSecret(raw) {
						continue
					}
					fingerprint := d.fingerprint(pattern.name, raw)
					seenKey := pattern.name + ":" + strconv.Itoa(line) + ":" + fingerprint
					if _, ok := seen[seenKey]; ok {
						continue
					}
					seen[seenKey] = struct{}{}
					results = append(results, rawMatch{kind: pattern.name, confidence: pattern.confidence, severity: pattern.severity, fingerprint: fingerprint, raw: raw, line: line})
				}
				continue
			}
			for _, loc := range pattern.re.FindAllStringIndex(fragment, -1) {
				if len(loc) != 2 || loc[0] < 0 || loc[1] <= loc[0] {
					continue
				}
				raw := fragment[loc[0]:loc[1]]
				if !credibleStrongSecret(raw) {
					continue
				}
				fingerprint := d.fingerprint(pattern.name, raw)
				seenKey := pattern.name + ":" + strconv.Itoa(line) + ":" + fingerprint
				if _, ok := seen[seenKey]; ok {
					continue
				}
				seen[seenKey] = struct{}{}
				results = append(results, rawMatch{kind: pattern.name, confidence: pattern.confidence, severity: pattern.severity, fingerprint: fingerprint, raw: raw, line: line})
			}
		}
		for _, m := range d.scanDecodedChunks(fragment, line, seen) {
			results = append(results, m)
		}
		for _, assignment := range credentialAssignments(fragment) {
			if overlapsAny(assignment.valueStart, assignment.valueEnd, strongRanges) {
				continue
			}
			// Client IDs and cloud/LLM access-key IDs are public identifiers. They
			// may anchor a paired search, but never become findings on their own.
			if isPublicCredentialIdentifierKey(assignment.key) {
				continue
			}
			// 键名维度占位闸（数据驱动）：测试/示例变量名与布尔语义键是库存
			// 确定性最高的两类误报源，在解析值之前整条跳过。
			if isPlaceholderCredentialKey(assignment.key) {
				continue
			}
			spec := assignmentSpec{}
			if assignment.bearer {
				spec = bearerTokenSpec
			} else {
				var ok bool
				spec, ok = classifyCredentialKey(assignment.key)
				if !ok {
					continue
				}
			}
			raw := fragment[assignment.valueStart:assignment.valueEnd]
			allowJWT := isMinimaxCredentialKey(compactCredentialKey(assignment.key))
			if !credibleAssignedValue(raw, spec, allowJWT) {
				continue
			}
			// 自回显占位值（实测误报：access_token: accesstoken000001）——
			// 文档示例的"键名+编号"形态；真实随机凭据不会复述自己的变量名。
			if isSelfEchoValue(assignment.key, raw) {
				continue
			}
			// R8-1 厂商专属变量名精确规格：不符判假（详见 vendor.go）。
			if !vendorAssignmentFormatValid(compactCredentialKey(assignment.key), raw) {
				continue
			}
			fingerprint := d.fingerprint(spec.kind, raw)
			seenKey := spec.kind + ":" + strconv.Itoa(line) + ":" + fingerprint
			if _, ok := seen[seenKey]; ok {
				continue
			}
			seen[seenKey] = struct{}{}
			results = append(results, rawMatch{kind: spec.kind, confidence: spec.confidence, severity: spec.severity, fingerprint: fingerprint, raw: raw, line: line, key: assignment.key})
		}
	}
	// R8-2 配对完整性：跨全部片段统一后处理（AK 与 Secret 可能落在不同片段）。
	applyPairingGates(item.Fragments, results)
	return results
}
