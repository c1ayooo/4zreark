// Package permute 主动子域候选派生（alterx 风格的简化纯 Go 实现）：
// 从已知子域提取词汇 token，套用 常见词/数字/年份 组合模式生成候选。
// 只产出"真候选"，不做词表全爆破——控制候选规模是硬约束（srcradar 教训：
// 泛解析 base + 无上限派生会把 DNS 阶段从分钟级拖到小时级）。
package permute

import (
	"fmt"
	"sort"
	"strings"
)

// 常见业务/环境/基础设施词表（精简高频集，全量词表交给测绘引擎）。
var commonWords = []string{
	"api", "dev", "test", "uat", "sit", "qa", "stage", "staging", "demo", "beta", "alpha",
	"pre", "preprod", "prod", "internal", "intranet", "corp", "office", "vpn", "mail", "smtp",
	"mx", "ns1", "ns2", "cdn", "img", "images", "static", "assets", "files", "download",
	"upload", "git", "gitlab", "jenkins", "ci", "cd", "admin", "manage", "manager", "console",
	"portal", "sso", "auth", "login", "oa", "crm", "erp", "hr", "shop", "mall", "m", "mobile",
	"app", "apps", "wx", "mini", "open", "gateway", "gw", "proxy", "lb", "db", "redis", "mysql",
	"kafka", "es", "zk", "mq", "monitor", "grafana", "prometheus", "kibana", "zabbix", "sonar",
	"wiki", "confluence", "jira", "svn", "ftp", "sftp", "backup", "bak", "old", "new", "cloud",
	"data", "bigdata", "ai", "iot", "pay", "payment", "bbs", "forum", "news", "shop-api", "docs",
	"help", "support", "id", "passport", "account", "user", "img2", "static2",
}

var digits = []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "01", "02", "03"}
var years = []string{"2019", "2020", "2021", "2022", "2023", "2024", "2025", "2026"}

// Generate 从已知子域派生候选。knownSubs 应为完整主机名（含 base 域）；
// base 为枚举主域。maxCandidates<=0 时按 20000 兜底。返回去重后的完整候选名
// （不含已知子域本身；单字符 token 派生直接丢弃——泛解析噪声，见 srcradar §八-1）。
func Generate(knownSubs []string, base string, maxCandidates int) []string {
	if maxCandidates <= 0 {
		maxCandidates = 20000
	}
	base = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(base), "."))
	if base == "" {
		return nil
	}
	knownSet := make(map[string]bool, len(knownSubs))
	words := make(map[string]bool)
	for _, sub := range knownSubs {
		sub = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(sub), "."))
		knownSet[sub] = true
		for _, w := range extractTokens(sub, base) {
			words[w] = true
		}
	}
	// 词序稳定：长词优先（信息量大），同长按字典序
	wordList := make([]string, 0, len(words))
	for w := range words {
		if len(w) < 2 || isAllDigits(w) {
			continue // 单字符/纯数字 token 派生价值趋零且制造泛解析噪声
		}
		wordList = append(wordList, w)
	}
	sort.Slice(wordList, func(i, j int) bool {
		if len(wordList[i]) != len(wordList[j]) {
			return len(wordList[i]) > len(wordList[j])
		}
		return wordList[i] < wordList[j]
	})

	candidates := make(map[string]bool)
	add := func(name string) bool {
		if len(candidates) >= maxCandidates {
			return false
		}
		name = strings.ToLower(strings.Trim(name, "-."))
		if name == "" || knownSet[name] || candidates[name] {
			return true // 不占预算
		}
		candidates[name] = true
		return true
	}
	outer := true
	for _, w := range wordList {
		if !outer {
			break
		}
		// token 自身作为独立子域
		if !add(w + "." + base) {
			outer = false
			break
		}
		for _, d := range digits {
			if !add(w + d + "." + base) {
				outer = false
				break
			}
		}
		if !outer {
			break
		}
		for _, y := range years {
			if !add(w + y + "." + base) {
				outer = false
				break
			}
		}
		if !outer {
			break
		}
		// 高频词组合：word-token / token-word（只与 commonWords 组合，避免 N² 爆炸）
		for _, cw := range commonWords {
			if cw == w {
				continue
			}
			if !add(cw + "-" + w + "." + base) {
				outer = false
				break
			}
			if !add(w + "-" + cw + "." + base) {
				outer = false
				break
			}
		}
	}
	out := make([]string, 0, len(candidates))
	for name := range candidates {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// extractTokens 把子域拆成候选词：去掉 base 域部分后按 . - _ 切分。
func extractTokens(sub, base string) []string {
	if sub == base {
		return nil
	}
	prefix := sub
	if strings.HasSuffix(sub, "."+base) {
		prefix = strings.TrimSuffix(sub, "."+base)
	} else if !strings.HasSuffix(sub, base) {
		return nil
	}
	if prefix == "" || prefix == "www" {
		return nil
	}
	splitFn := func(r rune) bool { return r == '.' || r == '-' || r == '_' }
	parts := strings.FieldsFunc(prefix, splitFn)
	tokens := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.ToLower(p)
		if p == "" || p == "www" {
			continue
		}
		tokens = append(tokens, p)
	}
	return tokens
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// Describe 返回词规模信息（日志/统计用）。
func Describe(knownSubs []string, base string) string {
	words := map[string]bool{}
	for _, sub := range knownSubs {
		for _, w := range extractTokens(strings.ToLower(sub), base) {
			words[w] = true
		}
	}
	return fmt.Sprintf("known=%d words=%d", len(knownSubs), len(words))
}
