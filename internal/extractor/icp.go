// Package extractor 从采集到的页面内容里提取结构化资产情报。
// 本文件：工信部 ICP 备案/许可证号。
package extractor

import (
	"regexp"
	"strings"
)

// icpPattern 匹配备案号全文形态：
//
//	粤ICP备09111111号 / 京ICP证022187号 / 京ICP备2021038876号-1
//	沪ICP备14006631号-2（允许号后缀与空格变体）
//
// 省份用单字简称字符类；备/证两类都收。页面常见变体是全角括号包裹或
// 「备案号：」前缀，正则只锚定核心串，避免误伤上下文。
var icpPattern = regexp.MustCompile(
	`([京津冀晋蒙辽吉黑沪苏浙皖闽赣鲁豫鄂湘粤桂琼渝川贵云藏陕甘青宁新])ICP([备证])\s*([0-9]{6,})\s*号(\s*-\s*[0-9]{1,3})?`)

// ExtractICPNumbers 提取页面正文里的 ICP 备案/许可证号，去重且保持出现顺序。
// 返回归一化形态（去内部空格），如「粤ICP备09111111号-1」。
// 注意 FindAllStringSubmatch 的 n=-1 才是全部匹配，0 会返回空。
func ExtractICPNumbers(body string) []string {
	if body == "" {
		return nil
	}
	matches := icpPattern.FindAllStringSubmatch(body, -1)
	if len(matches) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(matches))
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		normalized := strings.Join([]string{m[1], "ICP", m[2], m[3], "号"}, "")
		if suffix := strings.TrimSpace(m[4]); suffix != "" {
			normalized += strings.ReplaceAll(suffix, " ", "")
		}
		if seen[normalized] {
			continue
		}
		seen[normalized] = true
		out = append(out, normalized)
	}
	return out
}
