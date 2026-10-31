package webscan

// HaE（https://github.com/overspace-labs/HaE，Apache-2.0）规则库的内置
// 补充集：补齐平台默认集（结构强特征的云凭据/私钥）之外的中文场景泄露面
// ——手机号、内网拓扑、数据库连接串、认证头、键值对形态的敏感字段。
//
// 取舍记录（对照 HaE Rules.yml 全量 15 条）：
//   - 收录 6 条原版正则（RE2 兼容已验证），名字加 hae_ 前缀防撞名；
//   - 跳过 Email / Chinese IDCard（现有 email、id_card_cn 覆盖且边界更严谨）；
//   - 跳过 Cloud Key / Password Field（现有 api_key、client_secret、
//     password_field、alibaba_access_key 覆盖主要形态，双规则只会双报）；
//   - 跳过 Username Field（低价值高噪音：捕获组对任意值配对）；
//   - 剔除 Linkfinder / URL Schemes / ALL URL / MSEdge Plaintext——这四条
//     是「信息提取」语义（提 URL/文本），放进敏感信息扫描只会产出海量
//     噪音发现；接口提取由爬虫与 JS 审计链路承担。
//
// 依 Apache-2.0 要求保留原项目版权声明与出处标注。

// haeSensitivePatterns 返回 HaE 补充规则集（未编译）。
func haeSensitivePatterns() map[string]*SensitivePattern {
	return map[string]*SensitivePattern{
		"hae_mobile_cn": {
			// HaE「Chinese Mobile Number」：(+86/86 前缀可选) 1 开头 11 位，
			// 前后锚定非单词字符减少长数字串误命中。
			Name:     "hae_mobile_cn",
			Pattern:  `[^\w]((?:(?:\+|0{0,2})86)?1(?:(?:3[\d])|(?:4[5-79])|(?:5[0-35-9])|(?:6[5-7])|(?:7[0-8])|(?:8[\d])|(?:9[189]))\d{8})[^\w]`,
			Type:     "pii",
			Severity: "high",
		},
		"hae_internal_ip": {
			// HaE「Internal IP Address」：RFC1918 内网地址出现在公网响应里，
			// 暴露内网拓扑/后端真实地址。
			Name:     "hae_internal_ip",
			Pattern:  `[^0-9]((127\.0\.0\.1)|(10\.\d{1,3}\.\d{1,3}\.\d{1,3})|(172\.((1[6-9])|(2\d)|(3[01]))\.\d{1,3}\.\d{1,3})|(192\.168\.\d{1,3}\.\d{1,3}))`,
			Type:     "internal",
			Severity: "medium",
		},
		"hae_jdbc_connection": {
			// HaE「JDBC Connection」：与现有 connection_uri_with_credentials
			// 互补——那条要求带 user:pass@，这条连无凭据的连接串也命中
			//（数据库类型/主机/库名本身就是拓扑泄露）。
			Name:     "hae_jdbc_connection",
			Pattern:  `(jdbc:[a-z:]+://[a-z0-9.\-_:;=/@?,&]+)`,
			Type:     "internal",
			Severity: "medium",
		},
		"hae_auth_header": {
			// HaE「Authorization Header」：Basic/Bearer 凭证值明文出现在
			// 响应体或前端代码里，拿到即可直用。
			// 偏离原版：值字符类补大写字母——原版仅 [a-z0-9]，命中不了
			// 大小写混合的 base64 JWT/SAT（原版bug，意图显然是兜全凭证）。
			Name:     "hae_auth_header",
			Pattern:  `((basic [A-Za-z0-9=:_\+\/-]{5,100})|(bearer [A-Za-z0-9_.=:_\+\/-]{5,100}))`,
			Type:     "credential",
			Severity: "high",
		},
		"hae_sensitive_field": {
			// HaE「Sensitive Field」：key/secret/token/auth/admin 等键名与
			// 值成对出现（JSON/JS 赋值/jQuery val() 形态），比裸键名噪音低。
			Name:     "hae_sensitive_field",
			Pattern:  `(((|\\)(|'|")(|[\.\w]{1,32})(key|secret|token|config|auth|access|admin|ticket)(|[\.\w]{1,32})(|\\)(|'|")( |)(:|[=]{1,3}|![=]{1,2}|[\)]{0,1}\.val\()( |)(|\\)('|")([^'"]+?)(|\\)('|")(|,|\)))|((|\\)('|")([^'"]+?)(|\\)('|")(|\\)(|'|")( |)(:|[=]{1,3}|![=]{1,2})( |)(|[\.\w]{1,32})(key|secret|token|config|auth|access|admin|ticket)(|[\.\w]{1,32})(|\\)(|'|")))`,
			Type:     "sensitive",
			Severity: "medium",
		},
		"hae_mobile_field": {
			// HaE「Mobile Number Field」：mobile/phone 键名与值成对出现，
			// 比裸手机号（hae_mobile_cn）多一层字段语义佐证。
			Name:     "hae_mobile_field",
			Pattern:  `(((|\\)(|'|")(|[\.\w]{1,32})(mobile|phone|sjh|shoujihao|concat)(|[\.\w]{1,32})(|\\)(|'|")( |)(:|[=]{1,3}|![=]{1,2}|[\)]{0,1}\.val\()( |)(|\\)('|")([^'"]+?)(|\\)('|")(|,|\)))|((|\\)('|")([^'"]+?)(|\\)('|")(|\\)(|'|")( |)(:|[=]{1,3}|![=]{1,2})( |)(|[\.\w]{1,32})(mobile|phone|sjh|shoujihao|concat)(|[\.\w]{1,32})(|\\)(|'|")))`,
			Type:     "pii",
			Severity: "medium",
		},
	}
}
