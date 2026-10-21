package fingerprint

// projectdiscovery/wappalyzergo 上游指纹库（fingerprints_data.json，Wappalyzer
// 数据的 PD 维护版）→ 本地 DSL 规则翻译器。
//
// 与 webanalyze 翻译器同一取舍：不引入 wappalyzergo 运行时（它自带 HTTP 抓取
// 链路，会绕开平台授权/代理链路），只把它当作"指纹库来源"，翻译成本地表达式
// 规则入库（source='wappalyzergo'），共用同一探测/匹配/授权链路。
//
// 与 webanalyze technologies.json 的结构差异：
//   - apps 以 {"apps": {名称: 指纹}} 包裹，cats 是数字 id（名称查 categories_data.json）
//   - 脚本指纹字段叫 scriptSrc（webanalyze 叫 scripts）
//   - js 字段（浏览器 JS 全局变量检测）无法用 HTTP 响应正则可靠复现，逐条跳过计数，
//     只有 js 指纹的技术整条跳过，避免 body 正则匹配全局变量名带来的误报。

import (
	"encoding/json"
	"fmt"
	"strings"
)

// wappalyzergoFile fingerprints_data.json 顶层。
type wappalyzergoFile struct {
	Apps map[string]wappalyzergoApp `json:"apps"`
}

// wappalyzergoApp 单条技术指纹（与 wappalyzerTech 字段对齐以便复用翻译核心）。
type wappalyzergoApp struct {
	Cats      []int                      `json:"cats"`
	Cookies   map[string]wappalyzerValue `json:"cookies"`
	Headers   map[string]wappalyzerValue `json:"headers"`
	Meta      map[string]wappalyzerValue `json:"meta"`
	HTML      wappalyzerValue            `json:"html"`
	ScriptSrc wappalyzerValue            `json:"scriptSrc"`
	Scripts   wappalyzerValue            `json:"scripts"`
	CSS       wappalyzerValue            `json:"css"`
	URL       wappalyzerValue            `json:"url"`
	JS        map[string]wappalyzerValue `json:"js"`
}

// wappalyzergoCategories categories_data.json：id → 技术类别名。
func wappalyzergoCategories(data []byte) map[string]string {
	var raw map[string]struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}
	out := make(map[string]string, len(raw))
	for id, cat := range raw {
		out[id] = cat.Name
	}
	return out
}

// wappalyzergoCategory cats 数字 id → 类别名（最多 3 个拼接，风格与 webanalyze 一致）。
func wappalyzergoCategory(cats []int, names map[string]string) string {
	picked := make([]string, 0, 3)
	for _, id := range cats {
		if n := strings.TrimSpace(names[fmt.Sprint(id)]); n != "" {
			picked = append(picked, n)
		}
		if len(picked) >= 3 {
			break
		}
	}
	if len(picked) == 0 {
		return "wappalyzergo"
	}
	return strings.Join(picked, "/")
}

// ParseWappalyzergoFingerprints 解析并翻译 fingerprints_data.json 为本地规则。
// catNames 为 categories_data.json 解析结果（可为 nil，类别退化为 wappalyzergo）。
// 返回的规则全部通过 ParseExpression 校验，可直接入库。
func ParseWappalyzergoFingerprints(data []byte, catNames map[string]string) ([]Rule, WappalyzerImportStats, error) {
	var file wappalyzergoFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, WappalyzerImportStats{}, fmt.Errorf("JSON 解析失败: %w", err)
	}
	if len(file.Apps) == 0 {
		return nil, WappalyzerImportStats{}, fmt.Errorf("指纹库为空或格式不符（缺少 apps 段）")
	}
	stats := WappalyzerImportStats{TechnologiesTotal: len(file.Apps), SkipSamples: []string{}}
	rules := make([]Rule, 0, len(file.Apps))
	for name, app := range file.Apps {
		name = strings.TrimSpace(name)
		if name == "" {
			stats.TechnologiesSkipped++
			continue
		}
		tech := wappalyzerTech{
			Cookies: app.Cookies,
			Headers: app.Headers,
			Meta:    app.Meta,
			HTML:    app.HTML,
			Scripts: app.ScriptSrc,
			URL:     app.URL,
			CSS:     app.CSS,
		}
		tech.Scripts.Patterns = append(tech.Scripts.Patterns, app.Scripts.Patterns...)
		expr, skipReason, patternSkipped := translateWappalyzerTech(tech)
		// js 全局变量检测：HTTP 响应正则无法可靠复现，计为跳过 pattern
		jsSkipped := 0
		for _, val := range app.JS {
			jsSkipped += len(val.Patterns)
		}
		stats.PatternsSkipped += patternSkipped + jsSkipped
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
			Category:   wappalyzergoCategory(app.Cats, catNames),
			Expression: expr,
			Enabled:    true,
			Source:     "wappalyzergo",
		})
	}
	return rules, stats, nil
}
