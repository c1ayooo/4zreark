package fingerprint

// webanalyze（rverton/webanalyze）上游指纹库（technologies.json，Wappalyzer 格式）
// → 本地 DSL 规则翻译器。
//
// 设计取舍：不引入 webanalyze 运行时——它自带 HTTP 抓取链路，会绕开本平台的
// 项目授权范围校验、重定向逐跳复验与统一出站代理；因此只把它当作"指纹库来源"，
// 翻译成本地表达式规则入库（source='webanalyze'），与本库 custom 规则共用同一
// 探测/匹配/授权链路。上游指纹随仓库更新（UpdateScript 哈希比对）自动重导入。
//
// 保真度说明：Wappalyzer 的版本捕获组（如 ([\d.]+)）在本地 DSL 中仅参与匹配、
// 不提取版本号；implies/requires 关系不翻译（按单条规则独立匹配）。
// RE2 不兼容的 pattern（先行/后顾断言、反向引用、占有量词）逐条跳过并计数，
// 只要有任一 pattern 可用该技术仍会导入。

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// wappalyzerFile technologies.json 顶层（兼容 {technologies:{...}} 包裹与裸 map）。
type wappalyzerFile struct {
	Technologies map[string]wappalyzerTech `json:"technologies"`
	Apps         map[string]wappalyzerTech `json:"apps"`
}

// wappalyzerTech 单条技术指纹。
type wappalyzerTech struct {
	Cats          []string                   `json:"cats"`
	CategoryNames []string                   `json:"category_names"`
	Cookies       map[string]wappalyzerValue `json:"cookies"`
	Headers       map[string]wappalyzerValue `json:"headers"`
	Meta          map[string]wappalyzerValue `json:"meta"`
	HTML          wappalyzerValue            `json:"html"`
	Scripts       wappalyzerValue            `json:"scripts"`
	URL           wappalyzerValue            `json:"url"`
	CSS           wappalyzerValue            `json:"css"`
	Website       string                     `json:"website"`
}

// wappalyzerValue 兼容 string / []string 两种 pattern 形态，并在入口统一剥离
// Wappalyzer 元数据后缀（;version:\1 等）。空字符串保留：headers/cookies/meta
// 的空 pattern 是"该键存在"语义（translateWappalyzerTech 有对应分支）。
type wappalyzerValue struct {
	Patterns []string
}

func (v *wappalyzerValue) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	var single string
	if err := json.Unmarshal(b, &single); err == nil {
		v.Patterns = []string{stripWappalyzerMeta(strings.TrimSpace(single))}
		return nil
	}
	var arr []string
	if err := json.Unmarshal(b, &arr); err != nil {
		return err
	}
	v.Patterns = make([]string, 0, len(arr))
	for _, p := range arr {
		v.Patterns = append(v.Patterns, stripWappalyzerMeta(strings.TrimSpace(p)))
	}
	return nil
}

// WappalyzerImportStats 一次翻译的统计（入库时随来源元数据落库）。
type WappalyzerImportStats struct {
	TechnologiesTotal   int      `json:"technologies_total"`
	TechnologiesSkipped int      `json:"technologies_skipped"`
	PatternsSkipped     int      `json:"patterns_skipped"`
	SkipSamples         []string `json:"skip_samples,omitempty"` // 前 5 条跳过原因（技术名+原因）
}

// ParseWappalyzerTechnologies 解析并翻译 technologies.json 为本地规则。
// 返回的规则全部通过 ParseExpression 校验，可直接入库。
func ParseWappalyzerTechnologies(data []byte) ([]Rule, WappalyzerImportStats, error) {
	var file wappalyzerFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, WappalyzerImportStats{}, fmt.Errorf("JSON 解析失败: %w", err)
	}
	techs := file.Technologies
	if techs == nil {
		techs = file.Apps
	}
	if len(techs) == 0 {
		return nil, WappalyzerImportStats{}, fmt.Errorf("指纹库为空或格式不符（缺少 technologies 段）")
	}
	stats := WappalyzerImportStats{TechnologiesTotal: len(techs), SkipSamples: []string{}}
	rules := make([]Rule, 0, len(techs))
	for name, tech := range techs {
		name = strings.TrimSpace(name)
		if name == "" {
			stats.TechnologiesSkipped++
			continue
		}
		expr, skipReason, patternSkipped := translateWappalyzerTech(tech)
		stats.PatternsSkipped += patternSkipped
		if skipReason != "" && expr == "" {
			stats.TechnologiesSkipped++
			stats.SkipSamples = appendSkipSample(stats.SkipSamples, name, skipReason)
			continue
		}
		if _, err := ParseExpression(expr); err != nil {
			stats.TechnologiesSkipped++
			stats.SkipSamples = appendSkipSample(stats.SkipSamples, name, "表达式解析失败: "+err.Error())
			continue
		}
		rules = append(rules, Rule{
			Name:       name,
			Category:   wappalyzerCategory(tech),
			Expression: expr,
			Enabled:    true,
			Source:     "webanalyze",
		})
	}
	return rules, stats, nil
}

func appendSkipSample(samples []string, name, reason string) []string {
	if len(samples) >= 5 {
		return samples
	}
	return append(samples, name+": "+reason)
}

func wappalyzerCategory(tech wappalyzerTech) string {
	names := make([]string, 0, 3)
	for _, n := range tech.CategoryNames {
		if n = strings.TrimSpace(n); n != "" {
			names = append(names, n)
		}
		if len(names) >= 3 {
			break
		}
	}
	if len(names) == 0 {
		return "webanalyze"
	}
	return strings.Join(names, "/")
}

// translateWappalyzerTech 把一条技术定义翻译为 DSL 表达式。
// 各部分（headers/cookies/meta/html/scripts/url/css）之间 AND，部分内多 pattern OR。
// 全部 pattern 不可用时返回 ("", 原因, patternsSkipped)；正常时 reason 为空。
func translateWappalyzerTech(tech wappalyzerTech) (string, string, int) {
	var conds []string
	patternSkipped := 0
	// joinOr 把一组 pattern 翻译为同字段的 OR 条件并追加；pattern 编译失败（RE2
	// 不兼容）的逐条跳过，由调用方按技术级统计。列表字段（html/scripts/css/url）
	// 的空 pattern 无"存在"语义，跳过以防 body~="" 全匹配。
	joinOr := func(field string, patterns []string) {
		var ok []string
		for _, pat := range patterns {
			if pat == "" {
				continue
			}
			if _, err := compileRegexp(pat); err != nil {
				patternSkipped++
				continue
			}
			ok = append(ok, field+`~="`+dslEscape(pat)+`"`)
		}
		if len(ok) == 0 {
			return
		}
		if len(ok) == 1 {
			conds = append(conds, ok[0])
			return
		}
		conds = append(conds, "("+strings.Join(ok, " || ")+")")
	}

	// headers：HeaderText 行格式为 "key: value\n"，键已小写（编译期忽略大小写兜底）。
	// header 行序不定（Go map 遍历），锚定必须带 (?m) 多行标志；pattern 内顶层 |
	// 会破坏拼接语义，一律包 (?:...) 后再拼进上下文。
	// 空 pattern = 仅检测 header 存在（Wappalyzer 语义）。
	for key, val := range tech.Headers {
		pats := make([]string, 0, len(val.Patterns))
		for _, pat := range val.Patterns {
			var anchored string
			switch {
			case pat == "":
				anchored = `(?im)^` + regexp.QuoteMeta(strings.ToLower(key)) + `:`
			case strings.HasPrefix(pat, "^"):
				// pattern 锚定值开头：^key: 后紧跟模式
				anchored = `(?im)^` + regexp.QuoteMeta(strings.ToLower(key)) + `:\s*(?:` + strings.TrimPrefix(pat, "^") + `)`
			default:
				anchored = `(?im)^` + regexp.QuoteMeta(strings.ToLower(key)) + `:[^\n]*(?:` + pat + `)`
			}
			if _, err := compileRegexp(anchored); err != nil {
				patternSkipped++
				continue
			}
			pats = append(pats, anchored)
		}
		joinOr("header", pats)
	}

	for name, val := range tech.Cookies {
		pats := make([]string, 0, len(val.Patterns))
		for _, pat := range val.Patterns {
			if pat == "" {
				pats = append(pats, regexp.QuoteMeta(name)+`\s*=`)
				continue
			}
			pats = append(pats, regexp.QuoteMeta(name)+`\s*=[^\n]*(?:`+pat+`)`)
		}
		joinOr("cookie", pats)
	}

	for name, val := range tech.Meta {
		var pats []string
		for _, pat := range val.Patterns {
			nameLit := regexp.QuoteMeta(name)
			var metaPat string
			if pat == "" {
				metaPat = `<meta[^>]*\bname\s*=\s*["']?` + nameLit + `(?:["']|[\s>/])`
			} else {
				// content 属性可在 name 前/后两种属性顺序，正则内单 | 交替
				metaPat = `<meta[^>]*name\s*=\s*["']?` + nameLit + `["'][^>]*content\s*=\s*["'][^"']*(?:` + pat + `)` +
					`|<meta[^>]*content\s*=\s*["'][^"']*(?:` + pat + `)["'][^>]*name\s*=\s*["']?` + nameLit + `["']`
			}
			pats = append(pats, metaPat)
		}
		joinOr("body", pats)
	}

	joinOr("body", tech.HTML.Patterns)
	joinOr("body", tech.Scripts.Patterns)
	joinOr("body", tech.CSS.Patterns)
	joinOr("path", tech.URL.Patterns)

	if len(conds) == 0 {
		return "", "无可用 pattern（全部 RE2 不兼容或为空）", patternSkipped
	}
	if len(conds) == 1 {
		return conds[0], "", patternSkipped
	}
	return strings.Join(conds, " && "), "", patternSkipped
}

// dslEscape 把 pattern 嵌入 DSL 字符串字面量：tokenizer 对 \X 吃掉反斜杠，
// 因此字面反斜杠翻倍、引号转义。
func dslEscape(pattern string) string {
	pattern = strings.ReplaceAll(pattern, `\`, `\\`)
	return strings.ReplaceAll(pattern, `"`, `\"`)
}

// stripWappalyzerMeta 剥掉 Wappalyzer 在 pattern 尾部附加的元数据段
// （如 `\;version:\1;confidence:100`），其中的 \1 反向引用会让 RE2 编译失败。
// 元数据与正则主体之间用 `\;` 或 `;` 分隔（webanalyze 转换后的文件两者都出现），
// 从尾部向前剥离 version:/confidence: 段；只动尾部，正则主体一字不改。
func stripWappalyzerMeta(pattern string) string {
	for {
		trimmed := false
		for _, sep := range []string{`\;`, `;`} {
			i := strings.LastIndex(pattern, sep)
			if i < 0 {
				continue
			}
			rest := pattern[i+len(sep):]
			if strings.HasPrefix(rest, "version:") || strings.HasPrefix(rest, "confidence:") {
				pattern = pattern[:i]
				trimmed = true
				break
			}
		}
		if !trimmed {
			return pattern
		}
	}
}
