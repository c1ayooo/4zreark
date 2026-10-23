package toolruntime

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// version 形如 major.minor.patch[-pre]，pre 存在时视为低于同号的正式版。
type version struct {
	major, minor, patch int
	pre                 string
}

var versionRe = regexp.MustCompile(`v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?`)

// parseVersion 从任意输出（tag、"v1.2.3"、工具 --version 的多行文本）中
// 提取第一个 semver。找不到返回错误。
func parseVersion(s string) (version, error) {
	m := versionRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return version{}, fmt.Errorf("未找到版本号: %q", s)
	}
	var v version
	v.major, _ = strconv.Atoi(m[1])
	v.minor, _ = strconv.Atoi(m[2])
	v.patch, _ = strconv.Atoi(m[3])
	v.pre = m[4]
	return v, nil
}

func (v version) String() string {
	if v.pre != "" {
		return fmt.Sprintf("%d.%d.%d-%s", v.major, v.minor, v.patch, v.pre)
	}
	return fmt.Sprintf("%d.%d.%d", v.major, v.minor, v.patch)
}

func (v version) less(o version) bool {
	if v.major != o.major {
		return v.major < o.major
	}
	if v.minor != o.minor {
		return v.minor < o.minor
	}
	if v.patch != o.patch {
		return v.patch < o.patch
	}
	// 无 pre 的正式版 > 有 pre 的同号版
	switch {
	case v.pre == "" && o.pre != "":
		return false
	case v.pre != "" && o.pre == "":
		return true
	default:
		return v.pre < o.pre
	}
}

// compareVersion 比较两个版本字符串（允许 "v" 前缀与杂乱输出）。
// 返回 -1/0/1；解析失败返回错误。
func compareVersion(a, b string) (int, error) {
	va, err := parseVersion(a)
	if err != nil {
		return 0, fmt.Errorf("版本 %q: %w", a, err)
	}
	vb, err := parseVersion(b)
	if err != nil {
		return 0, fmt.Errorf("版本 %q: %w", b, err)
	}
	switch {
	case va.less(vb):
		return -1, nil
	case vb.less(va):
		return 1, nil
	default:
		return 0, nil
	}
}
