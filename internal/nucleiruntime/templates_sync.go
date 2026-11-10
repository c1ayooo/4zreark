package nucleiruntime

// 官方模板同步的版本与增量记录（对齐 ARL-Next 的「社区模板版本对比」思路）。
//
// nuclei -update-templates 不会落版本文件，模板库版本只能从命令输出里解析。
// 这里在每次模板更新前后各走一遍目录快照（文件名集合），diff 出新增/移除
// 条目数，连同解析出的上游版本一起存进设置（nuclei.templates_sync），状态
// 接口透出给面板。

import (
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"
)

// SettingTemplatesSync 记录最近一次模板同步的版本与增量。
const SettingTemplatesSync = "nuclei.templates_sync"

// TemplateSyncInfo 是一次官方模板同步的观测结果。
type TemplateSyncInfo struct {
	Version string `json:"version,omitempty"` // 上游模板库版本（从更新输出解析，可能为空）
	Total   int    `json:"total"`             // 同步后的模板文件总数
	Added   int    `json:"added"`             // 相比上次新增的模板数
	Removed int    `json:"removed"`           // 相比上次移除的模板数
	SyncedAt string `json:"synced_at"`        // 同步完成时间（RFC3339）
}

// templatesSyncVersionRe 从 nuclei -update-templates 输出解析版本号。
var templatesSyncVersionRe = regexp.MustCompile(`(?i)(?:templates?[^v\n]*|version)\s*v?(\d+\.\d+\.\d+)`)

// snapshotTemplates 走模板目录，返回模板文件相对路径集合。
func snapshotTemplates(dir string) map[string]struct{} {
	out := map[string]struct{}{}
	if strings.TrimSpace(dir) == "" {
		return out
	}
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return nil
		}
		out[rel] = struct{}{}
		return nil
	})
	return out
}

// diffTemplateSnapshots 计算两个快照间的增删条数。
func diffTemplateSnapshots(before, after map[string]struct{}) (added, removed int) {
	for p := range after {
		if _, ok := before[p]; !ok {
			added++
		}
	}
	for p := range before {
		if _, ok := after[p]; !ok {
			removed++
		}
	}
	return added, removed
}

// parseTemplatesVersion 从 nuclei -update-templates 的输出解析模板库版本。
func parseTemplatesVersion(output string) string {
	m := templatesSyncVersionRe.FindStringSubmatch(output)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}
