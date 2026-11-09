package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// 技能导入：把「别人写好的检查清单」变成库里的技能。
//
// 支持三种格式，覆盖实际会遇到的情况：
//   - .json          单个对象或对象数组（对接脚本、批量迁移）
//   - .yaml / .yml   字段式声明
//   - .md / .txt     front-matter（可选）+ 正文；没有 front-matter 就认第一个 # 标题
//
// 导入一律生成新的 custom-xxx id：文件里的 id 若指向内置技能，直接沿用会覆盖内置内容，
// 而导入的语义是「新增一份」，不是「替换」。

// ParseSkillFile 按扩展名解析技能文件。
func ParseSkillFile(filename string, data []byte) ([]SentinelSkillInput, error) {
	body := strings.TrimSpace(string(data))
	if body == "" {
		return nil, errors.New("文件内容为空")
	}
	switch ext := strings.ToLower(filepath.Ext(filename)); ext {
	case ".json":
		return parseSkillJSON([]byte(body))
	case ".yaml", ".yml":
		return parseSkillYAML([]byte(body))
	case ".md", ".markdown", ".txt", "":
		return validateSkillInputs([]SentinelSkillInput{parseSkillMarkdown(filename, body)})
	default:
		return nil, fmt.Errorf("不支持的文件类型 %s，可用：.json / .yaml / .md / .txt", ext)
	}
}

func parseSkillJSON(raw []byte) ([]SentinelSkillInput, error) {
	var arr []SentinelSkillInput
	if err := json.Unmarshal(raw, &arr); err == nil && len(arr) > 0 {
		return validateSkillInputs(arr)
	}
	var wrapper struct {
		Skills []SentinelSkillInput `json:"skills"`
	}
	if err := json.Unmarshal(raw, &wrapper); err == nil && len(wrapper.Skills) > 0 {
		return validateSkillInputs(wrapper.Skills)
	}
	var one SentinelSkillInput
	if err := json.Unmarshal(raw, &one); err == nil && (one.Name != "" || one.Prompt != "") {
		return validateSkillInputs([]SentinelSkillInput{one})
	}
	return nil, errors.New("JSON 里没有可识别的技能（需要 name 与 prompt 字段）")
}

func parseSkillYAML(raw []byte) ([]SentinelSkillInput, error) {
	var one SentinelSkillInput
	if err := yaml.Unmarshal(raw, &one); err == nil && (one.Name != "" || one.Prompt != "") {
		return validateSkillInputs([]SentinelSkillInput{one})
	}
	var arr []SentinelSkillInput
	if err := yaml.Unmarshal(raw, &arr); err == nil && len(arr) > 0 {
		return validateSkillInputs(arr)
	}
	return nil, errors.New("YAML 里没有可识别的技能（需要 name 与 prompt 字段）")
}

// parseSkillMarkdown 支持：
//
//	---
//	name: 前端 XSS 审计
//	version: v1.0
//	---
//	# 检查顺序
//	1. ...
//
// 以及没有 front-matter 的「# 名称 + 正文」写法。
func parseSkillMarkdown(filename, body string) SentinelSkillInput {
	in := SentinelSkillInput{}
	content := body

	if strings.HasPrefix(content, "---") {
		rest := strings.TrimPrefix(content, "---")
		if idx := strings.Index(rest, "\n---"); idx >= 0 {
			_ = yaml.Unmarshal([]byte(rest[:idx]), &in)
			content = strings.TrimSpace(rest[idx+4:])
		}
	}

	if in.Name == "" {
		lines := strings.Split(content, "\n")
		for i, l := range lines {
			t := strings.TrimSpace(l)
			if strings.HasPrefix(t, "#") {
				in.Name = strings.TrimSpace(strings.TrimLeft(t, "#"))
				content = strings.TrimSpace(strings.Join(append(append([]string{}, lines[:i]...), lines[i+1:]...), "\n"))
				break
			}
		}
	}
	if in.Name == "" {
		base := filepath.Base(filename)
		in.Name = strings.TrimSuffix(base, filepath.Ext(base))
	}
	in.Prompt = strings.TrimSpace(content)
	return in
}

func validateSkillInputs(items []SentinelSkillInput) ([]SentinelSkillInput, error) {
	out := make([]SentinelSkillInput, 0, len(items))
	for i, in := range items {
		in.Name = strings.TrimSpace(in.Name)
		in.Prompt = strings.TrimSpace(in.Prompt)
		if in.Name == "" {
			return nil, fmt.Errorf("第 %d 个技能缺少 name", i+1)
		}
		if in.Prompt == "" {
			return nil, fmt.Errorf("技能「%s」缺少检查项（prompt / 正文）", in.Name)
		}
		if in.Version == "" {
			in.Version = "v1.0"
		}
		out = append(out, in)
	}
	if len(out) == 0 {
		return nil, errors.New("没有解析到技能")
	}
	return out, nil
}

// ImportSentinelSkills 解析文件并逐条入库，返回成功的技能与失败原因（部分成功也返回已成功的）。
func ImportSentinelSkills(ctx context.Context, filename string, data []byte) ([]SentinelSkill, []string, error) {
	inputs, err := ParseSkillFile(filename, data)
	if err != nil {
		return nil, nil, err
	}
	saved := make([]SentinelSkill, 0, len(inputs))
	failed := make([]string, 0)
	for _, in := range inputs {
		in.ID = "" // 导入始终新建，避免覆盖内置技能
		item, err := UpsertSentinelSkill(ctx, in)
		if err != nil {
			failed = append(failed, in.Name+": "+err.Error())
			continue
		}
		saved = append(saved, *item)
	}
	if len(saved) == 0 {
		return nil, failed, errors.New("全部导入失败")
	}
	return saved, failed, nil
}
