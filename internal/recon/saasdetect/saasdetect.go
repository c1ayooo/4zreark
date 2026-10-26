// Package saasdetect SaaS 域名特征识别（对标 Desinter_scan site_metadata §5.3）：
// 用内置规则表（configs/saas-domains.yaml）匹配主/子域名，识别其使用的第三方
// SaaS 服务。纯函数 + 可注入规则；识别结论供攻防两端消费（打点面 + 供应链判断）。
package saasdetect

import (
	_ "embed"
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed saas-domains.yaml
var builtinYAMLData []byte

// Service 一条 SaaS 识别规则。
type Service struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Label    string   `json:"label,omitempty"`
	Category string   `json:"category,omitempty"`
	Patterns []string `json:"patterns"` // 原始正则（配置持久化形式）
}

// CompiledService 编译后的服务规则（Match 消费）。
type CompiledService struct {
	Service
	res []*regexp.Regexp
}

// Match 一条命中结论。
type Match struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Label    string `json:"label,omitempty"`
	Category string `json:"category,omitempty"`
}

// Matcher 编译后的 SaaS 识别器。
type Matcher struct {
	services []*CompiledService
}

// builtinYAML is the legacy default path; LoadBuiltin uses the embedded copy.
var builtinYAML = "configs/saas-domains.yaml"

// fileRules 顶层结构。
type ruleFile struct {
	Version  int       `yaml:"version"`
	Services []Service `yaml:"services"`
}

// LoadFromFile 从 YAML 加载并编译规则。文件不存在时返回错误（内置表缺失 = 程序错误，
// 不静默降级——识别面缺表比无识别更危险）。
func LoadFromFile(path string) (*Matcher, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("saasdetect: 读规则文件失败: %w", err)
	}
	return parseRules(data, path)
}

// parseRules 编译 YAML 内容；name 仅用于错误信息。
func parseRules(data []byte, name string) (*Matcher, error) {
	var f ruleFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("saasdetect: %s 解析失败: %w", name, err)
	}
	if len(f.Services) == 0 {
		return nil, fmt.Errorf("saasdetect: %s 无规则条目", name)
	}
	m := &Matcher{}
	for _, s := range f.Services {
		cs := &CompiledService{Service: s}
		for _, p := range s.Patterns {
			re, rerr := regexp.Compile("(?i)^" + p)
			if rerr != nil {
				continue // 表内字面量错误是 bug：容忍跳过该正则，避免整表起不来
			}
			cs.res = append(cs.res, re)
		}
		if len(cs.res) == 0 {
			continue // 该服务所有正则都非法：整条跳过
		}
		m.services = append(m.services, cs)
	}
	if len(m.services) == 0 {
		return nil, fmt.Errorf("saasdetect: %s 无可编译规则", name)
	}
	return m, nil
}

// LoadBuiltin 从内置（嵌入）规则表加载，不依赖当前工作目录。
func LoadBuiltin() (*Matcher, error) { return parseRules(builtinYAMLData, "builtin:saas-domains.yaml") }

// Match 对域名做 SaaS 识别：首条命中规则返回其结论。输入容忍大小写/尾部点/协议前缀。
func (m *Matcher) Match(host string) (Match, bool) {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "www.")
	if host == "" {
		return Match{}, false
	}
	for _, s := range m.services {
		for _, re := range s.res {
			if re.MatchString(host) {
				return Match{ID: s.ID, Name: s.Name, Label: s.Label, Category: s.Category}, true
			}
		}
	}
	return Match{}, false
}

// Services 返回全部已编译服务（报告/调试用）。
func (m *Matcher) Services() []Service {
	out := make([]Service, 0, len(m.services))
	for _, s := range m.services {
		out = append(out, s.Service)
	}
	return out
}
