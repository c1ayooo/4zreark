package llm

import "strings"

// EstimateTokens 是装箱用的粗略 token 估算：英文代码约 3.5 字符/token，
// 统一按 4 字符/token 折算。精确值以模型返回的 usage 为准（ResponseMeta.Usage），
// 估算只服务「装到 10k 就停」的预算控制。
func EstimateTokens(text string) int {
	if text == "" {
		return 0
	}
	return len(text)/4 + 1
}

// TruncateToBudget 把文本裁到预算内（按行裁，避免截断半个 hunk）。
func TruncateToBudget(text string, budgetTokens int) string {
	if budgetTokens <= 0 {
		return ""
	}
	maxBytes := budgetTokens * 4
	if len(text) <= maxBytes {
		return text
	}
	lines := strings.Split(text, "\n")
	var b strings.Builder
	used := 0
	for _, line := range lines {
		if used+len(line)+1 > maxBytes {
			break
		}
		b.WriteString(line)
		b.WriteByte('\n')
		used += len(line) + 1
	}
	return b.String()
}
