package nuclei

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// TemplateMeta 是模板索引里的一条元数据（解析自 YAML，不含执行体）。
// 情报流水线生成模板后先过 ParseTemplateYAML，保证入库的东西能被索引接受。
type TemplateMeta struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Severity    string   `json:"severity"`
	Tags        []string `json:"tags,omitempty"`
	CVE         []string `json:"cve,omitempty"`
	Type        string   `json:"type"`
	Path        string   `json:"path"`
	Source      string   `json:"source"` // official | custom
	Author      string   `json:"author,omitempty"`
	Description string   `json:"description,omitempty"`
}

type templateDoc struct {
	ID   string `yaml:"id"`
	Info struct {
		Name           string     `yaml:"name"`
		Author         string     `yaml:"author"`
		Severity       string     `yaml:"severity"`
		Description    string     `yaml:"description"`
		Tags           stringList `yaml:"tags"`
		Classification struct {
			CVEID stringList `yaml:"cve-id"`
		} `yaml:"classification"`
	} `yaml:"info"`
	HTTP       any `yaml:"http"`
	DNS        any `yaml:"dns"`
	TCP        any `yaml:"tcp"`
	File       any `yaml:"file"`
	Headless   any `yaml:"headless"`
	Code       any `yaml:"code"`
	JavaScript any `yaml:"javascript"`
	SSL        any `yaml:"ssl"`
	Websocket  any `yaml:"websocket"`
	Whois      any `yaml:"whois"`
	Workflows  any `yaml:"workflows"`
}

// ParseTemplateYAML 解析并校验一段 nuclei 模板 YAML。
func ParseTemplateYAML(b []byte) (TemplateMeta, error) {
	if len(b) == 0 {
		return TemplateMeta{}, fmt.Errorf("模板内容为空")
	}
	if len(b) > 1<<20 {
		return TemplateMeta{}, fmt.Errorf("模板超过 1MB 上限")
	}
	var doc templateDoc
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return TemplateMeta{}, fmt.Errorf("YAML 解析失败: %w", err)
	}
	id := strings.TrimSpace(doc.ID)
	name := strings.TrimSpace(doc.Info.Name)
	if id == "" {
		return TemplateMeta{}, fmt.Errorf("模板缺少 id")
	}
	if name == "" {
		return TemplateMeta{}, fmt.Errorf("模板缺少 info.name")
	}
	if !validTemplateID(id) {
		return TemplateMeta{}, fmt.Errorf("模板 id 只能包含字母、数字、点、下划线和短横线: %s", id)
	}
	typ := templateType(doc)
	if typ == "unknown" {
		return TemplateMeta{}, fmt.Errorf("模板缺少协议段（http/dns/tcp/file/headless/code/javascript/ssl/websocket/whois/workflows）")
	}
	severity := strings.ToLower(strings.TrimSpace(doc.Info.Severity))
	if severity == "" {
		severity = "unknown"
	}
	return TemplateMeta{
		ID:          id,
		Name:        name,
		Severity:    severity,
		Tags:        doc.Info.Tags,
		CVE:         doc.Info.Classification.CVEID,
		Type:        typ,
		Author:      strings.TrimSpace(doc.Info.Author),
		Description: strings.TrimSpace(doc.Info.Description),
	}, nil
}

func validTemplateID(id string) bool {
	if id == "" {
		return false
	}
	for _, r := range id {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			r == '.' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func templateType(d templateDoc) string {
	switch {
	case d.HTTP != nil:
		return "http"
	case d.DNS != nil:
		return "dns"
	case d.TCP != nil:
		return "tcp"
	case d.File != nil:
		return "file"
	case d.Headless != nil:
		return "headless"
	case d.Code != nil:
		return "code"
	case d.JavaScript != nil:
		return "javascript"
	case d.SSL != nil:
		return "ssl"
	case d.Websocket != nil:
		return "websocket"
	case d.Whois != nil:
		return "whois"
	case d.Workflows != nil:
		return "workflow"
	default:
		return "unknown"
	}
}

// stringList 兼容 nuclei 模板里 tags/cve-id 的两种写法：
//
//	tags: cve,rce
//	tags: [cve, rce]
type stringList []string

func (s *stringList) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		var raw string
		if err := value.Decode(&raw); err != nil {
			return err
		}
		for _, p := range strings.Split(raw, ",") {
			if p = strings.TrimSpace(p); p != "" {
				*s = append(*s, p)
			}
		}
	case yaml.SequenceNode:
		for _, node := range value.Content {
			var raw string
			if err := node.Decode(&raw); err == nil {
				if raw = strings.TrimSpace(raw); raw != "" {
					*s = append(*s, raw)
				}
			}
		}
	}
	return nil
}
