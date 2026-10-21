package githubleak

import (
	"strings"
)

type credentialAssignment struct {
	key                  string
	valueStart, valueEnd int
	bearer               bool
}

func credentialAssignments(fragment string) []credentialAssignment {
	matches := credentialAssignmentStartRE.FindAllStringSubmatchIndex(fragment, -1)
	result := make([]credentialAssignment, 0, len(matches))
	for _, match := range matches {
		key := credentialAssignmentKey(fragment, match)
		if key == "" {
			continue
		}
		start, end, ok := 0, 0, false
		bearer := isAuthorizationKey(key)
		if bearer {
			start, end, ok = parseBearerToken(fragment, match[1])
		} else {
			start, end, ok = parseAssignmentValue(fragment, match[1])
		}
		if ok {
			assignment := credentialAssignment{key: key, valueStart: start, valueEnd: end, bearer: bearer}
			if len(result) > 0 && assignment.valueStart < result[len(result)-1].valueEnd {
				if assignment.valueEnd > result[len(result)-1].valueEnd {
					result[len(result)-1].valueEnd = assignment.valueEnd
				}
				continue
			}
			result = append(result, assignment)
		}
	}
	return result
}

// credentialAssignmentsForMasking is deliberately more greedy than the
// detector parser. Once an error names a sensitive field, masking an adjacent
// delimiter or message suffix is safer than retaining part of an unquoted or
// unterminated credential in logs.
func credentialAssignmentsForMasking(fragment string) []credentialAssignment {
	matches := credentialAssignmentStartRE.FindAllStringSubmatchIndex(fragment, -1)
	result := make([]credentialAssignment, 0, len(matches))
	for _, match := range matches {
		key := credentialAssignmentKey(fragment, match)
		if key == "" {
			continue
		}
		bearer := isAuthorizationKey(key)
		start, end, ok := 0, 0, false
		if bearer {
			start, end, ok = parseBearerTokenForMasking(fragment, match[1])
		} else {
			start, end, ok = parseAssignmentValueForMasking(fragment, match[1])
		}
		if ok {
			assignment := credentialAssignment{key: key, valueStart: start, valueEnd: end, bearer: bearer}
			if len(result) > 0 && assignment.valueStart < result[len(result)-1].valueEnd {
				if assignment.valueEnd > result[len(result)-1].valueEnd {
					result[len(result)-1].valueEnd = assignment.valueEnd
				}
				continue
			}
			result = append(result, assignment)
		}
	}
	return result
}

func credentialAssignmentKey(fragment string, match []int) string {
	if len(match) < 10 {
		return ""
	}
	for i := 2; i+1 < len(match); i += 2 {
		if match[i] >= 0 && match[i+1] > match[i] {
			return fragment[match[i]:match[i+1]]
		}
	}
	return ""
}

func parseAssignmentValue(fragment string, start int) (int, int, bool) {
	if start < 0 || start >= len(fragment) {
		return 0, 0, false
	}
	if quote := fragment[start]; quote == '\'' || quote == '"' || quote == '`' {
		valueStart, escaped := start+1, false
		for i := valueStart; i < len(fragment) && i-valueStart <= 512; i++ {
			if fragment[i] == '\r' || fragment[i] == '\n' {
				return 0, 0, false
			}
			if escaped {
				escaped = false
				continue
			}
			if fragment[i] == '\\' {
				escaped = true
				continue
			}
			if fragment[i] == quote {
				return valueStart, i, i > valueStart
			}
		}
		return 0, 0, false
	}
	end := start
	for end < len(fragment) && end-start <= 512 {
		switch fragment[end] {
		case ' ', '\t', '\r', '\n', ',', ';', '}', ']':
			return start, end, end > start
		}
		end++
	}
	return start, end, end > start && end-start <= 512
}

func parseAssignmentValueForMasking(fragment string, start int) (int, int, bool) {
	if start < 0 || start >= len(fragment) {
		return 0, 0, false
	}
	if quote := fragment[start]; quote == '\'' || quote == '"' || quote == '`' {
		valueStart, escaped := start+1, false
		limit := len(fragment)
		for i := valueStart; i < limit; i++ {
			if fragment[i] == '\r' || fragment[i] == '\n' {
				return valueStart, i, i > valueStart
			}
			if escaped {
				escaped = false
				continue
			}
			if fragment[i] == '\\' {
				escaped = true
				continue
			}
			if fragment[i] == quote {
				return valueStart, i, i > valueStart
			}
		}
		return valueStart, limit, limit > valueStart
	}
	end := start
	limit := len(fragment)
	for end < limit {
		switch fragment[end] {
		case ' ', '\t', '\r', '\n':
			return start, end, end > start
		}
		end++
	}
	return start, end, end > start
}

func parseBearerToken(fragment string, start int) (int, int, bool) {
	contentStart, contentEnd := start, start
	if start < len(fragment) && (fragment[start] == '\'' || fragment[start] == '"' || fragment[start] == '`') {
		var ok bool
		contentStart, contentEnd, ok = parseAssignmentValue(fragment, start)
		if !ok {
			return 0, 0, false
		}
	} else {
		for contentEnd < len(fragment) && contentEnd-start <= 520 {
			if strings.ContainsRune("\r\n,;}]", rune(fragment[contentEnd])) {
				break
			}
			contentEnd++
		}
	}
	content := fragment[contentStart:contentEnd]
	if len(content) < 7 || !strings.EqualFold(content[:6], "bearer") || (content[6] != ' ' && content[6] != '\t') {
		return 0, 0, false
	}
	offset := 6
	for offset < len(content) && (content[offset] == ' ' || content[offset] == '\t') {
		offset++
	}
	tokenStart := contentStart + offset
	tokenEnd := tokenStart
	for tokenEnd < contentEnd && fragment[tokenEnd] != ' ' && fragment[tokenEnd] != '\t' {
		tokenEnd++
	}
	return tokenStart, tokenEnd, tokenEnd > tokenStart
}

func parseBearerTokenForMasking(fragment string, start int) (int, int, bool) {
	if start < 0 || start >= len(fragment) {
		return 0, 0, false
	}
	if fragment[start] == '\'' || fragment[start] == '"' || fragment[start] == '`' {
		contentStart, contentEnd, ok := parseAssignmentValueForMasking(fragment, start)
		if !ok {
			return 0, 0, false
		}
		content := fragment[contentStart:contentEnd]
		if len(content) < 7 || !strings.EqualFold(content[:6], "bearer") || (content[6] != ' ' && content[6] != '\t') {
			return 0, 0, false
		}
		offset := 6
		for offset < len(content) && (content[offset] == ' ' || content[offset] == '\t') {
			offset++
		}
		return contentStart + offset, contentEnd, contentEnd > contentStart+offset
	}
	if len(fragment)-start < 7 || !strings.EqualFold(fragment[start:start+6], "bearer") ||
		(fragment[start+6] != ' ' && fragment[start+6] != '\t') {
		return 0, 0, false
	}
	tokenStart := start + 6
	for tokenStart < len(fragment) && (fragment[tokenStart] == ' ' || fragment[tokenStart] == '\t') {
		tokenStart++
	}
	tokenEnd := tokenStart
	limit := len(fragment)
	for tokenEnd < limit {
		switch fragment[tokenEnd] {
		case ' ', '\t', '\r', '\n':
			return tokenStart, tokenEnd, tokenEnd > tokenStart
		}
		tokenEnd++
	}
	return tokenStart, tokenEnd, tokenEnd > tokenStart
}

func isAuthorizationKey(key string) bool {
	id := compactCredentialKey(key)
	return id == "authorization" || id == "proxyauthorization"
}

func isClientIdentifierKey(key string) bool {
	id := compactCredentialKey(key)
	return id == "appid" || id == "oauthappid" || hasCredentialSuffix(id, "clientid", "oauthclientid")
}

func isPublicCredentialIdentifierKey(key string) bool {
	id := compactCredentialKey(key)
	if isClientIdentifierKey(key) {
		return true
	}
	return id == "accesskey" || hasCredentialSuffix(id,
		"accesskeyid", "qianfanak", "huaweicloudak", "tencentcloudsecretid",
		"twilioapikey", "twilioapisid", "twilioaccountsid",
	)
}

func classifyCredentialKey(key string) (assignmentSpec, bool) {
	id := compactCredentialKey(key)
	if id == "" {
		return assignmentSpec{}, false
	}
	if hasCredentialSuffix(id,
		"openaiapikey", "anthropicapikey", "deepseekapikey", "dashscopeapikey", "arkapikey",
		"moonshotapikey", "zhipuaiapikey", "zhipuapikey", "glmapikey", "qwenapikey",
		"qianfanapikey", "geminiapikey", "googleaiapikey", "mistralapikey", "groqapikey",
		"cohereapikey", "togetherapikey", "perplexityapikey", "openrouterapikey",
		"siliconflowapikey", "minimaxapikey", "doubaoapikey", "azureopenaiapikey",
		"googleapikey", "googlegenaiapikey", "googlegenerativeaiapikey", "xaiapikey", "fireworksapikey",
		"voyageapikey", "pineconeapikey", "weaviateapikey", "langsmithapikey", "langchainapikey",
		"heliconeapikey", "cloudflareaiapikey", "ollamaapikey", "bedrockapikey",
	) {
		return llmAPIKeySpec, true
	}
	if hasCredentialSuffix(id,
		"openaikey", "claudeapikey", "azureopenaikey",
		"replicateapitoken", "huggingfacehubapitoken", "hftoken",
	) {
		return llmAPIKeySpec, true
	}
	if hasCredentialSuffix(id, "qianfanak") {
		return llmAccessKeySpec, true
	}
	if hasCredentialSuffix(id, "qianfansk") {
		return llmSecretKeySpec, true
	}
	if hasCredentialSuffix(id, "clientsecret", "consumersecret") {
		return oauthClientSecretSpec, true
	}
	if hasCredentialSuffix(id, "mchkey", "apiv3key", "partnerkey") {
		return wechatPaySecretSpec, true
	}
	if hasCredentialSuffix(id, "webhooksecret", "signingsecret") {
		return webhookSecretSpec, true
	}
	if hasCredentialSuffix(id, "secretaccesskey", "accesskeysecret", "miniosecretkey") ||
		hasCredentialSuffix(id, "awssecretkey", "aliyunsecretkey", "alibabacloudsecretkey", "tencentcloudsecretkey", "huaweicloudsk") {
		return cloudSecretKeySpec, true
	}
	if id == "accesskey" || hasCredentialSuffix(id, "accesskeyid") || hasCredentialSuffix(id, "huaweicloudak") ||
		(strings.Contains(id, "tencentcloud") && hasCredentialSuffix(id, "secretid")) {
		return cloudAccessKeyIDSpec, true
	}
	if id == "apikey" || id == "xapikey" || hasCredentialSuffix(id, "apikey") {
		return apiKeySpec, true
	}
	if id == "bearertoken" || hasCredentialSuffix(id, "bearertoken") {
		return bearerTokenSpec, true
	}
	if id == "token" {
		return strictBareTokenSpec, true
	}
	if id == "idtoken" || id == "oidcidtoken" || hasCredentialSuffix(id,
		"accesstoken", "authtoken", "apitoken", "servicetoken", "bottoken",
		"webhooktoken", "refreshtoken", "oauthtoken", "sessiontoken", "sastoken",
		"githubtoken", "gitlabtoken", "ghtoken", "privatetoken", "deploytoken",
		"registrytoken", "personalaccesstoken",
	) {
		return authTokenSpec, true
	}
	if id == "secret" || hasCredentialSuffix(id,
		"apisecret", "apisecretkey", "appsecret", "corpsecret", "sharedsecret", "encryptionsecret",
		"jwtsecret", "sessionsecret", "cookiesecret", "secretkey", "signingkey",
		"encryptionkey", "masterkey", "privatekey", "serviceaccountkey", "sessionkey",
	) {
		return genericNamedSecretSpec, true
	}
	if id == "password" || id == "passwd" || hasCredentialSuffix(id,
		"dbpassword", "databasepassword", "redispassword", "cachepassword", "smtppassword",
		"ftppassword", "adminpassword", "servicepassword", "userpassword",
	) {
		return passwordSecretSpec, true
	}
	return assignmentSpec{}, false
}

func compactCredentialKey(value string) string {
	var b strings.Builder
	b.Grow(len(value))
	for _, r := range strings.ToLower(strings.TrimSpace(value)) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func hasCredentialSuffix(value string, suffixes ...string) bool {
	for _, suffix := range suffixes {
		if value == suffix || strings.HasSuffix(value, suffix) {
			return true
		}
	}
	return false
}
