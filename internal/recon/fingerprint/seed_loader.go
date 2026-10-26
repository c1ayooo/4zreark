package fingerprint

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// seedFS embeds the bundled seed rules so DefaultRules works from any working
// directory (library use, tests, containers).
//
//go:embed seeds/*.yaml
var seedFS embed.FS

// loadEmbeddedSeedRules loads the embedded seeds. It mirrors
// loadSeedRulesFromDir: a broken single file is reported and skipped.
func loadEmbeddedSeedRules() ([]Rule, []error) {
	entries, err := fs.ReadDir(seedFS, "seeds")
	if err != nil {
		return nil, []error{fmt.Errorf("fingerprint seed: 读取内置目录失败: %w", err)}
	}
	var rules []Rule
	var errs []error
	for _, e := range entries {
		if e.IsDir() || !(strings.HasSuffix(e.Name(), ".yaml") || strings.HasSuffix(e.Name(), ".yml")) {
			continue
		}
		data, err := seedFS.ReadFile("seeds/" + e.Name())
		if err != nil {
			errs = append(errs, fmt.Errorf("fingerprint seed: 读取内置文件 %s 失败: %w", e.Name(), err))
			continue
		}
		rs, err := parseSeedRuleBytes(data, "seeds/"+e.Name())
		if err != nil {
			errs = append(errs, err)
			continue
		}
		rules = append(rules, rs...)
	}
	return rules, errs
}

// seedRuleFile 指纹种子文件顶层结构:rules 列表。
// note 仅作人类可读说明,加载时丢弃;source 固定 custom。
type seedRuleFile struct {
	Rules []struct {
		Name       string `yaml:"name"`
		Category   string `yaml:"category"`
		Expression string `yaml:"expression"`
		Enabled    *bool  `yaml:"enabled"`
		Note       string `yaml:"note"`
	} `yaml:"rules"`
}

// loadSeedRulesFromDir 加载 configs/fingerprint-seeds/*.yaml 为内存规则。
// 目录不存在返回空(种子是可选资产);单文件失败记错误并跳过,不阻断。
// 每条表达式经 ParseExpression 校验。
func loadSeedRulesFromDir(dir string) ([]Rule, []error) {
	if strings.TrimSpace(dir) == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, []error{fmt.Errorf("fingerprint seed: 读取目录失败 %s: %w", dir, err)}
	}
	var rules []Rule
	var errs []error
	for _, e := range entries {
		if e.IsDir() || !(strings.HasSuffix(e.Name(), ".yaml") || strings.HasSuffix(e.Name(), ".yml")) {
			continue
		}
		rs, err := loadSeedRuleFile(filepath.Join(dir, e.Name()))
		if err != nil {
			errs = append(errs, err)
			continue
		}
		rules = append(rules, rs...)
	}
	return rules, errs
}

// loadSeedRuleFile 处理单个种子文件。
func loadSeedRuleFile(path string) ([]Rule, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("fingerprint seed: 读取失败 %s: %w", path, err)
	}
	return parseSeedRuleBytes(b, path)
}

// parseSeedRuleBytes 解析种子文件内容;path 仅用于错误信息。
func parseSeedRuleBytes(b []byte, path string) ([]Rule, error) {
	var f seedRuleFile
	if err := yaml.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("fingerprint seed: YAML 解析失败 %s: %w", path, err)
	}
	rules := make([]Rule, 0, len(f.Rules))
	for i, r := range f.Rules {
		name := strings.TrimSpace(r.Name)
		expr := strings.TrimSpace(r.Expression)
		if name == "" || expr == "" {
			return nil, fmt.Errorf("fingerprint seed: %s 第 %d 条规则缺 name/expression", path, i+1)
		}
		if _, err := ParseExpression(expr); err != nil {
			return nil, fmt.Errorf("fingerprint seed: %s 第 %d 条(name=%s)表达式无效: %w", path, i+1, name, err)
		}
		enabled := true
		if r.Enabled != nil {
			enabled = *r.Enabled
		}
		category := strings.TrimSpace(r.Category)
		if category == "" {
			category = "seed"
		}
		rules = append(rules, Rule{
			Name:       name,
			Category:   category,
			Expression: expr,
			Enabled:    enabled,
			Source:     SourceCustom,
		})
	}
	return rules, nil
}
