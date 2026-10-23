package fingerprint

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// fingers 生态规则源的翻译适配器（翻译规则数据文件，不引运行时库——
// 与 wappalyzergo/dddd 适配器同一原则）。
//
// 数据来自 chainreactors/fingers 仓 resources/ 下的规范化 JSON（gzip）：
//   - ehole.json.gz   EHole 指纹（cms/method/location/keyword），多关键字 AND
//   - goby.json.gz    Goby 指纹（name/logic + 带 label 的 feature 子句）
//   - fingers_http.json.gz  fingers 自维护 HTTP 指纹（regexps/favicon/version）
//
// 上游语义对照（读 fingers 库实现确认）：
//   - ehole: keyword 多值全命中（AND）；location body/title 都按 body 匹配
//     （EHole 实现就是拿整个 body 匹 title）；header 按 header；
//     匹配内容统一转小写，因此 keyword 字面量翻译时转小写。
//   - goby: 无 location 字段，feature 按全响应（banner）包含匹配；
//     logic 是 label 的 &&/||/() 表达式，与本地 DSL 操作符一致，直接代换。
//   - fingers_http: rule 条目间 OR，条目内字段 AND，同字段多值 OR；
//     favicon.mmh3 → icon_hash==、favicon.md5 → icon_md5==。

// fingersPinnedCommit 规则数据钉在固定 commit，变更走手动升级。
const fingersPinnedCommit = "385e7d586d6f00630e235c1e2f7dc2b0e8f406f4"

// FingersResourceURLs 生成某个 fingers 资源文件的候选 URL（raw + jsdelivr）。
func FingersResourceURLs(file string) []string {
	base := "chainreactors/fingers/" + fingersPinnedCommit + "/resources/" + file
	return []string{
		"https://raw.githubusercontent.com/" + base,
		"https://cdn.jsdelivr.net/gh/" + base,
	}
}

// gunzipIfCompressed 适配 raw/jsdelivr 返回的 .json.gz：内容是 gzip 就解压。
func gunzipIfCompressed(data []byte) ([]byte, error) {
	if len(data) < 2 || data[0] != 0x1f || data[1] != 0x8b {
		return data, nil
	}
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("gzip 解压失败: %w", err)
	}
	defer zr.Close()
	return io.ReadAll(io.LimitReader(zr, 64<<20))
}

// quoteExprString DSL 字符串字面量转义（引号与反斜杠）。
func quoteExprString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

// ---------------------------------------------------------------------------
// EHole
// ---------------------------------------------------------------------------

type eholeFingerprint struct {
	Cms      string   `json:"cms"`
	Method   string   `json:"method"`
	Location string   `json:"location"`
	Keyword  []string `json:"keyword"`
}

type eholeData struct {
	Fingerprints []eholeFingerprint `json:"fingerprint"`
}

// ParseEHoleFinger 翻译 ehole.json.gz。
func ParseEHoleFinger(data []byte) ([]Rule, WappalyzerImportStats, error) {
	raw, err := gunzipIfCompressed(data)
	if err != nil {
		return nil, WappalyzerImportStats{}, err
	}
	var parsed eholeData
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, WappalyzerImportStats{}, fmt.Errorf("解析 ehole 指纹失败: %w", err)
	}
	stats := WappalyzerImportStats{}
	byName := map[string][]string{}
	for _, fp := range parsed.Fingerprints {
		if fp.Cms == "" || len(fp.Keyword) == 0 {
			stats.Skipped++
			continue
		}
		field := "body"
		if strings.EqualFold(fp.Location, "header") {
			field = "header"
		}
		op := "="
		if strings.EqualFold(fp.Method, "regular") {
			op = "~="
		}
		parts := make([]string, 0, len(fp.Keyword))
		for _, k := range fp.Keyword {
			lit := k
			if op == "=" {
				// ehole 对内容统一小写后匹配，字面量同步小写
				lit = strings.ToLower(k)
			}
			parts = append(parts, fmt.Sprintf("%s %s %s", field, op, quoteExprString(lit)))
		}
		// ehole 语义：同一条指纹的多个关键字全命中
		byName[fp.Cms] = append(byName[fp.Cms], "("+strings.Join(parts, " && ")+")")
	}
	return buildRulesFromOrGroups(SourceEHole, byName, &stats), stats, nil
}

// ---------------------------------------------------------------------------
// Goby
// ---------------------------------------------------------------------------

type gobyRuleItem struct {
	Label   string `json:"label"`
	Feature string `json:"feature"`
	IsEqual bool   `json:"is_equal"`
}

type gobyFingerprint struct {
	Name  string         `json:"name"`
	Logic string         `json:"logic"`
	Rule  []gobyRuleItem `json:"rule"`
}

var gobyLabelRe = regexp.MustCompile("[a-zA-Z][a-zA-Z0-9_]*")

// ParseGobyFinger 翻译 goby.json.gz：logic 表达式里的 label 原地代换成
// banner 子句。goby 的 feature 无位置信息，按全响应（banner）包含匹配。
func ParseGobyFinger(data []byte) ([]Rule, WappalyzerImportStats, error) {
	raw, err := gunzipIfCompressed(data)
	if err != nil {
		return nil, WappalyzerImportStats{}, err
	}
	var parsed []gobyFingerprint
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, WappalyzerImportStats{}, fmt.Errorf("解析 goby 指纹失败: %w", err)
	}
	stats := WappalyzerImportStats{}
	byName := map[string][]string{}
	for _, fp := range parsed {
		if fp.Name == "" || len(fp.Rule) == 0 {
			stats.Skipped++
			continue
		}
		clauses := map[string]string{}
		for _, r := range fp.Rule {
			if r.Label == "" || strings.TrimSpace(r.Feature) == "" {
				continue
			}
			clauses[r.Label] = fmt.Sprintf("(banner=%s)", quoteExprString(r.Feature))
		}
		logic := strings.TrimSpace(fp.Logic)
		if logic == "" && len(clauses) == 1 {
			for _, c := range clauses {
				logic = c
			}
		} else if logic != "" {
			logic = gobyLabelRe.ReplaceAllStringFunc(logic, func(m string) string {
				if c, ok := clauses[m]; ok {
					return c
				}
				return m
			})
		}
		if logic == "" {
			stats.Skipped++
			continue
		}
		byName[fp.Name] = append(byName[fp.Name], "("+logic+")")
	}
	return buildRulesFromOrGroups(SourceGoby, byName, &stats), stats, nil
}

// ---------------------------------------------------------------------------
// fingers_http（fingers 库自维护的 HTTP 指纹）
// ---------------------------------------------------------------------------

type fingersFavicon struct {
	MD5  []string `json:"md5"`
	MMH3 []string `json:"mmh3"`
}

type fingersHTTPRule struct {
	// Regexps 的值通常是 []string，但 favicon 键的值是对象——用 RawMessage 兼容
	Regexps map[string]json.RawMessage `json:"regexps"`
	Favicon *fingersFavicon            `json:"favicon"`
}

type fingersHTTPFingerprint struct {
	Name string            `json:"name"`
	Rule []fingersHTTPRule `json:"rule"`
}

// ParseFingersHTTP 翻译 fingers_http.json.gz。
// 条目间 OR；条目内字段 AND；同字段多值 OR。
func ParseFingersHTTP(data []byte) ([]Rule, WappalyzerImportStats, error) {
	raw, err := gunzipIfCompressed(data)
	if err != nil {
		return nil, WappalyzerImportStats{}, err
	}
	var parsed []fingersHTTPFingerprint
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, WappalyzerImportStats{}, fmt.Errorf("解析 fingers_http 指纹失败: %w", err)
	}
	stats := WappalyzerImportStats{}
	byName := map[string][]string{}
	for _, fp := range parsed {
		if fp.Name == "" || len(fp.Rule) == 0 {
			stats.Skipped++
			continue
		}
		for _, r := range fp.Rule {
			expr := fingersRuleExpr(r)
			if expr == "" {
				continue
			}
			byName[fp.Name] = append(byName[fp.Name], "("+expr+")")
		}
	}
	return buildRulesFromOrGroups(SourceFingers, byName, &stats), stats, nil
}

func fingersRuleExpr(r fingersHTTPRule) string {
	var andParts []string
	favicon := r.Favicon
	for _, field := range []string{"body", "header", "title"} {
		rawPats, ok := r.Regexps[field]
		if !ok {
			continue
		}
		var pats []string
		if err := json.Unmarshal(rawPats, &pats); err != nil || len(pats) == 0 {
			continue
		}
		ors := make([]string, 0, len(pats))
		for _, p := range pats {
			ors = append(ors, fmt.Sprintf("%s ~= %s", field, quoteExprString(p)))
		}
		andParts = append(andParts, "("+strings.Join(ors, " || ")+")")
	}
	// favicon 对象有时是 regexps 的一个键（上游数据两种形态都有）
	if rawFav, ok := r.Regexps["favicon"]; ok && favicon == nil {
		var fav fingersFavicon
		if err := json.Unmarshal(rawFav, &fav); err == nil {
			favicon = &fav
		}
	}
	if favicon != nil {
		if len(favicon.MMH3) > 0 {
			ors := make([]string, 0, len(favicon.MMH3))
			for _, h := range favicon.MMH3 {
				ors = append(ors, fmt.Sprintf("icon_hash == %s", quoteExprString(h)))
			}
			andParts = append(andParts, "("+strings.Join(ors, " || ")+")")
		}
		if len(favicon.MD5) > 0 {
			ors := make([]string, 0, len(favicon.MD5))
			for _, h := range favicon.MD5 {
				ors = append(ors, fmt.Sprintf("icon_md5 == %s", quoteExprString(h)))
			}
			andParts = append(andParts, "("+strings.Join(ors, " || ")+")")
		}
	}
	return strings.Join(andParts, " && ")
}

// buildRulesFromOrGroups 同名条目合并为 OR 表达式，并逐条做 DSL 校验。
func buildRulesFromOrGroups(source string, byName map[string][]string, stats *WappalyzerImportStats) []Rule {
	rules := make([]Rule, 0, len(byName))
	for name, groups := range byName {
		expr := strings.Join(groups, " || ")
		if _, err := ParseExpression(expr); err != nil {
			stats.Invalid++
			continue
		}
		rules = append(rules, Rule{
			Name:       name,
			Expression: expr,
			Enabled:    true,
			Source:     source,
		})
		stats.Imported++
	}
	return rules
}
