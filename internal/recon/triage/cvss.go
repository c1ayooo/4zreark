package triage

import (
	"strings"
)

// CVSSMetrics 解析后的 CVSS 向量：大写指标名 → 大写取值。
// 解析失败时返回空 M（不抛错），调用方按“缺指标不贡献分数”处理。
type CVSSMetrics struct {
	Version string            // "2.0" / "3.0" / "3.1" / "4.0"；向量未声明版本时按指标推断
	M       map[string]string // 如 AV:N / AC:L / PR:H / AT:P / AU:M / E:POC
}

// Get 取指标值，未声明返回空串
func (m CVSSMetrics) Get(k string) string { return m.M[k] }

var (
	metricKeyRe   = compileStrict(`^[A-Z]{1,3}$`)
	metricValueRe = compileStrict(`^[A-Z0-9]{1,4}$`)
)

// ParseCVSS 兼容 CVSS v2 / v3.x / v4.0 原始向量串。
// 任何一段不合法都整体判为解析失败，返回空指标集（绝不 panic / error）。
func ParseCVSS(vector string) CVSSMetrics {
	out := CVSSMetrics{M: map[string]string{}}
	v := strings.TrimSpace(vector)
	if v == "" {
		return out
	}
	if strings.HasPrefix(strings.ToUpper(v), "CVSS:") {
		parts := strings.SplitN(v, "/", 2)
		out.Version = strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(parts[0])), "CVSS:")
		if len(parts) == 1 {
			return out
		}
		v = parts[1]
	}
	for _, seg := range strings.Split(v, "/") {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		kv := strings.SplitN(seg, ":", 2)
		if len(kv) != 2 {
			return CVSSMetrics{M: map[string]string{}}
		}
		k := strings.ToUpper(strings.TrimSpace(kv[0]))
		val := strings.ToUpper(strings.TrimSpace(kv[1]))
		if !metricKeyRe.MatchString(k) || !metricValueRe.MatchString(val) {
			return CVSSMetrics{M: map[string]string{}}
		}
		out.M[k] = val
	}
	if len(out.M) == 0 {
		return CVSSMetrics{M: map[string]string{}}
	}
	if out.Version == "" {
		switch {
		case out.Get("AT") != "" || out.Get("VC") != "":
			out.Version = "4.0"
		case out.Get("AU") != "":
			out.Version = "2.0"
		default:
			out.Version = "3.x"
		}
	}
	return out
}

// perfectStorm 完美风暴：AV:N + AC:L + (AT:N 或无此项) + PR:N(v2 为 Au:N) + (UI:N 或 v2 无此项)
// —— 无需认证、无交互、低复杂度的远程利用，武器化成本最低。
func perfectStorm(m CVSSMetrics) bool {
	prNone := m.Get("PR") == "N" || m.Get("AU") == "N"
	uiNone := m.Get("UI") == "N" || m.Get("UI") == "" // v2 没有 UI 指标
	atNone := m.Get("AT") == "N" || m.Get("AT") == ""
	return m.Get("AV") == "N" && m.Get("AC") == "L" && atNone && prNone && uiNone
}
