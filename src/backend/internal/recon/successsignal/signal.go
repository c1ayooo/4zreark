// Package successsignal 高产路径先验表（对标 AutoHunter SUCCESS_SIGNALS 移植项 #2）。
//
// 「历史上出洞多的路径族 → 先验分」：资产上观测到这些路径族（后台入口、上传点、
// API 文档、调试端点等）时，在测绘评分上叠加先验分（上限 successSignalCap），
// 派单按 P0-P4 优先级自然前置。
//
// 与六维观测评分的关系：观测维度回答「这资产暴露了什么」，先验表回答「这类入口
// 历史上是不是高频出洞」——对从没出过洞的资产和历史上高产的同款系统不再同分。
//
// 词表刻意保持通用企业语境（不含 /prod-api、tduck-api 这类强绑定教育行业的 tag，
// 见对标文档 §九）；条目可由 configs/success-signals.yaml 覆盖与扩充。
package successsignal

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// successSignalCap 先验分上限（对标口径：命中即最多 +10 分，
// 只抬排序不越级压过漏洞实证/高危端口等硬证据）。
const successSignalCap = 10

// Family 一个路径族：name 汇报用；patterns 为小写子串，命中任一即算该族。
type Family struct {
	Name     string   `yaml:"name"`
	Points   int      `yaml:"points"`
	Patterns []string `yaml:"patterns"`
}

// builtin 内置先验表：分值档位=该族历史出洞频率与平均危害的综合经验值。
var builtin = []Family{
	{Name: "admin-console", Points: 6, Patterns: []string{
		"/admin", "/manager/html", "/console", "/backstage", "/manage", "后台登录", "管理系统"}},
	{Name: "file-upload", Points: 5, Patterns: []string{
		"/upload", "/file/upload", "/attachment/upload", "/import", "ueditor", "kindeditor", "fckeditor"}},
	{Name: "api-docs", Points: 5, Patterns: []string{
		"swagger", "api-docs", "openapi.json", "/graphql", "graphiql", "apifox"}},
	{Name: "debug-endpoint", Points: 6, Patterns: []string{
		"/actuator", "jolokia", "pprof", "/debug/", "/druid", "/trace", "/heapdump"}},
	{Name: "auth-entry", Points: 3, Patterns: []string{
		"/login", "/sso", "/passport", "/oauth", "/cas/login", "/signin"}},
	{Name: "file-download", Points: 3, Patterns: []string{
		"/download", "/export", "readfile", "getfile", "/getFile"}},
	{Name: "user-center", Points: 2, Patterns: []string{
		"/user/profile", "/account", "/member", "/personal"}},
	{Name: "backup-leak", Points: 4, Patterns: []string{
		".sql", ".bak", ".git/", ".svn/", "web.config", ".env"}},
}

var (
	overrideMu   sync.RWMutex
	overridden   []Family
	overrideOnce bool
)

// Families 当前生效的路径族表（override 优先，未加载时内置表）。
func Families() []Family {
	overrideMu.RLock()
	defer overrideMu.RUnlock()
	if overrideOnce {
		return overridden
	}
	return builtin
}

// overridesFile configs/success-signals.yaml 的形状。
type overridesFile struct {
	Families []Family `yaml:"families"`
}

// LoadOverridesFile 加载运维覆盖表：同 name 覆盖内置族，新 name 追加，
// 未出现的内置族保留。返回生效族数。文件不存在返回 (0, nil)（内置表兜底）。
// 同名重复以最后一条为准。
func LoadOverridesFile(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	var f overridesFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return 0, fmt.Errorf("success-signals yaml: %w", err)
	}
	merged := make([]Family, 0, len(builtin)+len(f.Families))
	replaced := map[string]bool{}
	for i := range f.Families {
		fam := f.Families[i]
		if fam.Name == "" || fam.Points <= 0 || len(fam.Patterns) == 0 {
			continue
		}
		replaced[strings.ToLower(fam.Name)] = true
		merged = append(merged, Family{Name: fam.Name, Points: fam.Points, Patterns: lowerAll(fam.Patterns)})
	}
	for _, b := range builtin {
		if replaced[strings.ToLower(b.Name)] {
			continue
		}
		merged = append(merged, b)
	}
	overrideMu.Lock()
	overridden = merged
	overrideOnce = true
	overrideMu.Unlock()
	return len(merged), nil
}

// Match 对一组观测路径（URL path，取小写子串匹配）返回（先验分, 命中族名）。
// 分值为去重族之和，封顶 successSignalCap；无命中返回 (0, nil)。
func Match(paths []string) (int, []string) {
	if len(paths) == 0 {
		return 0, nil
	}
	joined := make([]string, 0, len(paths))
	for _, p := range paths {
		if p = strings.ToLower(strings.TrimSpace(p)); p != "" {
			joined = append(joined, p)
		}
	}
	if len(joined) == 0 {
		return 0, nil
	}
	hay := "\n" + strings.Join(joined, "\n") + "\n"
	pts := 0
	var hits []string
	for _, fam := range Families() {
		for _, pat := range fam.Patterns {
			if strings.Contains(hay, pat) {
				pts += fam.Points
				hits = append(hits, fam.Name)
				break // 族内去重：一个族只计一次
			}
		}
	}
	if len(hits) == 0 {
		return 0, nil
	}
	sort.Strings(hits)
	if pts > successSignalCap {
		pts = successSignalCap
	}
	return pts, hits
}

func lowerAll(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s = strings.ToLower(strings.TrimSpace(s)); s != "" {
			out = append(out, s)
		}
	}
	return out
}
