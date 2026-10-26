package fingerprint

// SleepingBag945/dddd 上游指纹库（common/config/finger.yaml）→ 本地 DSL 规则翻译器。
//
// 与 wappalyzergo/webanalyze 翻译器同一取舍：不引入 dddd 运行时（自带扫描链路，
// 会绕开平台授权/代理链路），只把它当作"指纹库来源"，翻译成本地表达式规则入库
// （source='dddd'），共用同一探测/匹配/授权链路。
//
// dddd 规则天然贴近本平台 DSL：flat map（产品名 → 表达式列表），字段 body/title/
// header/banner/server/cert/icon_hash/protocol/port/status/cookie/path 与操作符
// =/!=/==/~/=/&&/||/! 括号全部在 knownFields/parser 支持范围内，翻译只需两步：
//  1. 反斜杠预转义（ddddPreescape）：tokenizer 把字面量内 \X 还原为 X，源文本的
//     正则转义（\b \. \d…）必须翻倍才能原样到达正则引擎；引号转义 \" 是 tokenizer
//     原生语法，保持单反斜杠不动（dddd 语料中前者 ~110 处、后者 7400+ 处）。
//  2. 同产品多条表达式 (e1) || (e2) 合并为一条规则（语义即"任一命中"）。

import (
	_ "embed"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// ddddSnapshotYAML 内置出厂快照（snapshots/dddd-finger.yaml，与上游字节一致）：
// 上游全部候选不可达时的初始化兜底，见 update.go importSnapshot。
//
//go:embed snapshots/dddd-finger.yaml
var ddddSnapshotYAML []byte

// ParseDdddFinger 解析并翻译 dddd finger.yaml 为本地规则。
// 返回的规则全部通过 ParseExpression 校验，可直接入库。
func ParseDdddFinger(data []byte) ([]Rule, WappalyzerImportStats, error) {
	var raw map[string][]string
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, WappalyzerImportStats{}, fmt.Errorf("YAML 解析失败: %w", err)
	}
	if len(raw) == 0 {
		return nil, WappalyzerImportStats{}, fmt.Errorf("指纹库为空或格式不符（缺少产品条目）")
	}
	stats := WappalyzerImportStats{TechnologiesTotal: len(raw), SkipSamples: []string{}}
	rules := make([]Rule, 0, len(raw))
	for name, exprs := range raw {
		name = strings.TrimSpace(name)
		if name == "" || len(exprs) == 0 {
			stats.TechnologiesSkipped++
			continue
		}
		var conds []string
		for _, e := range exprs {
			e = strings.TrimSpace(e)
			if e == "" {
				continue
			}
			escaped := ddddPreescape(e)
			if _, err := ParseExpression(escaped); err != nil {
				stats.PatternsSkipped++
				stats.SkipSamples = appendSkipSample(stats.SkipSamples, name, "表达式解析失败: "+err.Error())
				continue
			}
			conds = append(conds, "("+escaped+")")
		}
		if len(conds) == 0 {
			stats.TechnologiesSkipped++
			continue
		}
		rules = append(rules, Rule{
			Name:       name,
			Category:   SourceDddd,
			Expression: strings.Join(conds, " || "),
			Enabled:    true,
			Source:     SourceDddd,
		})
	}
	return rules, stats, nil
}

// ddddPreescape 表达式内反斜杠预转义：正则转义翻倍以穿过 tokenizer（\b→\\b，
// 解析后值中仍为 \b）；引号转义 \" \' 是 tokenizer 原生语法原样保留。只处理带
// 引号字面量内部，取词/引号开闭规则与 tokenizer 一致。
func ddddPreescape(expr string) string {
	if !strings.ContainsRune(expr, '\\') {
		return expr
	}
	var b strings.Builder
	b.Grow(len(expr) + 8)
	inQuote := byte(0)
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		if inQuote == 0 {
			if c == '"' || c == '\'' {
				inQuote = c
			}
			b.WriteByte(c)
			continue
		}
		if c == '\\' && i+1 < len(expr) {
			next := expr[i+1]
			if next == '"' || next == '\'' {
				b.WriteByte(c)
				b.WriteByte(next)
			} else {
				b.WriteByte(c)
				b.WriteByte(c)
				b.WriteByte(next)
			}
			i++
			continue
		}
		if c == inQuote {
			inQuote = 0
		}
		b.WriteByte(c)
	}
	return b.String()
}
