package componentprofile

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// SourceNucleiCVE 离线 CVE 边来源：nuclei 模板索引的 cves[]。
const SourceNucleiCVE = "nuclei-cve"

// TemplateIndexEntry 是模板索引里 J4 需要的最小字段子集。
// 索引由外部脚本从 nuclei 模板生成，字段形如：
//
//	{"templates":[{"id":"CVE-2024-1","tech":"apache tomcat","cves":["CVE-2024-1"]}]}
type TemplateIndexEntry struct {
	ID   string   `json:"id"`
	Tech string   `json:"tech"`
	CVEs []string `json:"cves"`
}

// ParseTemplateIndex 解析模板索引 JSON。
func ParseTemplateIndex(raw []byte) ([]TemplateIndexEntry, error) {
	var doc struct {
		Templates []TemplateIndexEntry `json:"templates"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("解析模板索引失败: %w", err)
	}
	return doc.Templates, nil
}

// MineCVEEdges 从模板索引建立「组件 -> CVE」边。
// 只使用纯函数与传入的组件档案，不依赖数据库；调用方负责把结果落库。
func MineCVEEdges(templates []TemplateIndexEntry, profiles []Profile) []Edge {
	type acc struct {
		score     float64
		templates map[string]bool
	}
	edges := map[string]*acc{} // product\x00CVE
	for _, t := range templates {
		tech := strings.ToLower(strings.TrimSpace(t.Tech))
		if tech == "" || t.ID == "" {
			continue
		}
		techTokens := Tokens(Normalize(tech))
		if len(techTokens) == 0 {
			continue
		}
		cves := normalizeCVEs(t.CVEs)
		if len(cves) == 0 {
			continue
		}
		for _, p := range profiles {
			product := strings.TrimSpace(p.Product)
			if product == "" {
				continue
			}
			tokens := p.Tokens
			if len(tokens) == 0 {
				tokens = Tokens(Normalize(product))
			}
			if !tokensIntersect(tokens, techTokens) {
				continue
			}
			for _, cve := range cves {
				key := product + "\x00" + cve
				a := edges[key]
				if a == nil {
					a = &acc{score: 0.8, templates: map[string]bool{}}
					edges[key] = a
				}
				a.templates[t.ID] = true
			}
		}
	}

	out := make([]Edge, 0, len(edges))
	for key, a := range edges {
		parts := strings.SplitN(key, "\x00", 2)
		ids := make([]string, 0, len(a.templates))
		for id := range a.templates {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		out = append(out, Edge{
			Product:  parts[0],
			Kind:     KindCVE,
			Target:   parts[1],
			Score:    a.score,
			Source:   SourceNucleiCVE,
			Evidence: "templates: " + strings.Join(ids, ","),
			Review:   ReviewAuto,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Product != out[j].Product {
			return out[i].Product < out[j].Product
		}
		return out[i].Target < out[j].Target
	})
	return out
}

func normalizeCVEs(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.ToUpper(strings.TrimSpace(v))
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func tokensIntersect(a, b []string) bool {
	set := make(map[string]bool, len(a))
	for _, t := range a {
		set[strings.ToLower(t)] = true
	}
	for _, t := range b {
		if set[strings.ToLower(t)] {
			return true
		}
	}
	return false
}
