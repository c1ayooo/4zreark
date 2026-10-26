package githubleak

import (
	"regexp"
	"strings"
)

// vendor.go — R8 静态闸门（docs/GitHub敏感信息监控改进建议.md R8-1/R8-2）：
// 厂商格式自检 + 配对完整性校验。纯值/上下文判定，零外呼。
//
// 两道闸门的处置语义不同，依据文档"必须避免误杀"的纪律分层：
//  1. 结构性字母表判断（AWS KeyID 的 Base32）证据强但不做硬杀——gitleaks 官方
//     规则 aws-access-token 用同一字母表 [A-Z2-7]{16}，但仍按"降级为 suspected"
//     处置：挡在待人工验证队列（高危推送/样板风暴白名单）之外，同时保留可观测性，
//     一旦字母表论断有例外也不丢真实凭据。
//  2. 厂商专属变量名 + 明确长度/字符集规格（AWS Secret 40 位、阿里云 30 位、
//     腾讯云 32 位、微信 AppSecret 32 位 hex）是稳定事实，不符直接判假（丢弃）。
//     只对变量名可唯一归属厂商的赋值命中生效，泛化变量名（如 appsecret）不 gating。

// strongPatternGates 强特征命中的厂商格式闸门：返回 true 表示值不符合厂商
// 公开规格（结构性判断），命中后置信度降为 suspected（不丢弃）。
var strongPatternGates = map[string]func(raw string) bool{
	"aws_access_key_id": func(raw string) bool {
		// AWS AccessKeyId：4 位前缀 + 16 位 Base32（A-Z + 2-7，不含 0 1 8 9）。
		// gitleaks aws-access-token 同款字母表；正则放宽到 [0-9A-Z] 以便
		// 违规值仍入库降级可观测，由本闸门做精确判定。
		body := raw[4:]
		if len(body) != 16 {
			return true
		}
		return !isBase32Alphabet(body)
	},
}

// pairingGates 配对完整性闸门（R8-2）：AK 型标识必须与配对 Secret 同文件成对
// 出现（变量名语义匹配的赋值形态）；只命中单个 AK 视为文档/日志转录/脱敏残留，
// 置信度降为 suspected。ASIA 临时凭据配 AWS_SESSION_TOKEN（缺失降级，文档 R2 配套）。
var pairingGates = map[string]func(raw string) []*regexp.Regexp{
	"aws_access_key_id": func(raw string) []*regexp.Regexp {
		if strings.HasPrefix(raw, "ASIA") {
			return []*regexp.Regexp{awsSessionTokenAssignRE}
		}
		return []*regexp.Regexp{awsSecretAccessKeyAssignRE}
	},
	"aliyun_access_key":      func(string) []*regexp.Regexp { return []*regexp.Regexp{aliyunSecretAssignRE} },
	"tencentcloud_secret_id": func(string) []*regexp.Regexp { return []*regexp.Regexp{tencentSecretAssignRE} },
}

// 配对变量名的赋值形态：名称后允许收尾引号/括号（os.environ["AWS_SECRET_ACCESS_KEY"]）
// 再接赋值符；纯提及（文档里写一遍变量名）不算成对。
var (
	awsSecretAccessKeyAssignRE = regexp.MustCompile(`(?i)\b(?:aws_?)?secret_?access_?key\b["'` + "`" + `\)\]]*[ \t]*[:=]`)
	awsSessionTokenAssignRE    = regexp.MustCompile(`(?i)\baws_?session_?token\b["'` + "`" + `\)\]]*[ \t]*[:=]`)
	aliyunSecretAssignRE       = regexp.MustCompile(`(?i)\b(?:aliyun_?|alibaba_?cloud_?)?access_?key_?secret\b["'` + "`" + `\)\]]*[ \t]*[:=]`)
	tencentSecretAssignRE      = regexp.MustCompile(`(?i)\b(?:tencent_?(?:cloud_?)?)?secret_?key\b["'` + "`" + `\)\]]*[ \t]*[:=]`)
)

func isBase32Alphabet(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
		case r >= '2' && r <= '7':
		default:
			return false
		}
	}
	return true
}

// applyPairingGates 配对降级后处理：对 item 全部片段查配对变量名，缺失则降级。
// 只降不升——配对满足不改变原有置信度。
func applyPairingGates(fragments []string, matches []rawMatch) {
	for i := range matches {
		gate, ok := pairingGates[matches[i].kind]
		if !ok || matches[i].confidence != "likely" {
			continue
		}
		paired := false
		for _, re := range gate(matches[i].raw) {
			for _, fragment := range fragments {
				if re.MatchString(fragment) {
					paired = true
					break
				}
			}
			if paired {
				break
			}
		}
		if !paired {
			matches[i].confidence = "suspected"
		}
	}
}

// assignmentVendorFormatGates 厂商专属变量名的精确规格（R8-1）：key 可唯一归属
// 厂商时，值必须满足公开规格，不符判假（返回 false 丢弃）。键为紧凑小写变量名。
var assignmentVendorFormatGates = []struct {
	match func(compact string) bool
	valid func(value string) bool
}{
	// AWS Secret AccessKey：固定 40 位 base64 字符集
	{match: func(c string) bool { return hasCredentialSuffix(c, "awssecretaccesskey", "awssecretkey") },
		valid: func(v string) bool { return len(v) == 40 && isBase64Charset(v) }},
	// 阿里云 AccessKeySecret：固定 30 位字母数字
	{match: func(c string) bool {
		return (strings.Contains(c, "aliyun") || strings.Contains(c, "alibabacloud")) &&
			hasCredentialSuffix(c, "accesskeysecret", "secretkey")
	},
		valid: func(v string) bool { return len(v) == 30 && isAlphaNum(v) }},
	// 腾讯云 SecretKey：固定 32 位字母数字
	{match: func(c string) bool {
		return strings.Contains(c, "tencent") && hasCredentialSuffix(c, "secretkey")
	},
		valid: func(v string) bool { return len(v) == 32 && isAlphaNum(v) }},
	// 微信 AppSecret：固定 32 位 hex（仅 wx/wechat/weixin 前缀的专属变量名）
	{match: func(c string) bool {
		return hasCredentialSuffix(c, "appsecret") &&
			(strings.HasPrefix(c, "wx") || strings.HasPrefix(c, "wechat") || strings.HasPrefix(c, "weixin"))
	},
		valid: func(v string) bool { return len(v) == 32 && isHexLower(v) }},
}

// vendorAssignmentFormatValid 厂商专属赋值命中精确判定。现有可信闸
// （credibleAssignedValue）通过后调用；返回 false 表示确定判假。
func vendorAssignmentFormatValid(compactKey, value string) bool {
	for _, gate := range assignmentVendorFormatGates {
		if gate.match(compactKey) {
			return gate.valid(strings.TrimSpace(value))
		}
	}
	return true
}

// isMinimaxCredentialKey MiniMax API key 为 JWT 形态（R9.1）：仅当变量名明确
// 指向 MiniMax 时豁免 isJWTShape 值级过滤，全局豁免会让 JWT 噪声整批回灌。
func isMinimaxCredentialKey(compactKey string) bool {
	return hasCredentialSuffix(compactKey, "minimaxapikey", "minimaxsecret", "minimaxtoken")
}

func isBase64Charset(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '+' || r == '/' || r == '=':
		default:
			return false
		}
	}
	return true
}

func isAlphaNum(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
}

func isHexLower(s string) bool {
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return true
}
