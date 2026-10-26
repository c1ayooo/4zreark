package githubleak

import (
	"encoding/base64"
	"regexp"
	"strconv"
	"strings"
)

// base64ChunkRe Std/URL-safe 两种字母表（>=40 字符才尝试解码，控制成本）。
var base64ChunkRe = regexp.MustCompile(`[A-Za-z0-9+/_-]{40,}={0,2}`)

// decodeBase64Chunks 提取片段中的 base64 块并尝试解码；仅保留可打印占比 >=85%
// 且解码长度 >=16 的结果。上限 8 段/片段。
func decodeBase64Chunks(fragment string) []string {
	matches := base64ChunkRe.FindAllString(fragment, 8)
	out := make([]string, 0, len(matches))
	seen := map[string]struct{}{}
	for _, chunk := range matches {
		decoded := decodeBase64Try(chunk)
		if decoded == "" {
			continue
		}
		if _, ok := seen[decoded]; ok {
			continue
		}
		seen[decoded] = struct{}{}
		out = append(out, decoded)
	}
	return out
}

func decodeBase64Try(chunk string) string {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		data, err := enc.DecodeString(strings.TrimRight(chunk, "="))
		if err != nil || len(data) < 16 {
			continue
		}
		printable := 0
		for _, b := range data {
			if b >= 0x20 && b < 0x7f || b == '\n' || b == '\t' {
				printable++
			}
		}
		if float64(printable)/float64(len(data)) < 0.85 {
			continue
		}
		return string(data)
	}
	return ""
}

func overlapsAny(start, end int, ranges [][2]int) bool {
	for _, candidate := range ranges {
		if start < candidate[1] && end > candidate[0] {
			return true
		}
	}
	return false
}

// scanDecodedChunks base64 解码二次扫描：先编码后存储的密钥（编码块 ≥40 字符才
// 尝试解码，结果须 ≥85% 可打印，单片段最多 8 段）。只跑强特征+动态规则
// （赋值启发式在解码文本上噪声不可控）。共享 seen/line 与主扫描去重。
func (d *Detector) scanDecodedChunks(fragment string, line int, seen map[string]struct{}) []rawMatch {
	var results []rawMatch
	for _, decoded := range decodeBase64Chunks(fragment) {
		for _, pattern := range strongSecretPatterns {
			for _, loc := range pattern.re.FindAllStringIndex(decoded, -1) {
				if len(loc) != 2 || loc[1] <= loc[0] {
					continue
				}
				raw := decoded[loc[0]:loc[1]]
				if !credibleStrongSecret(raw) {
					continue
				}
				if pattern.name == "database_connection_string" && !credibleDatabaseURL(raw) {
					continue
				}
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
			for _, loc := range pattern.re.FindAllStringIndex(decoded, -1) {
				if len(loc) != 2 || loc[1] <= loc[0] {
					continue
				}
				raw := decoded[loc[0]:loc[1]]
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
	}
	return results
}
