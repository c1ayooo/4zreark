package service

import (
	"fmt"
	"strings"

	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/internal/toolruntime"
)

// CollectionEnv 是信息收集执行前的环境快照。判定全部走规则，AI 不参与。
type CollectionEnv struct {
	Stage   bool
	Reasons []string
	Tools   map[string]bool
}

// EvaluateCollectionEnv 决定走单链还是分阶段：
//   - 用户显式 full/staged 优先；
//   - auto 下目标过大、关键工具缺失时切 staged；
//   - 工具可用性读统一工具目录，与实际执行保持一致。
func EvaluateCollectionEnv(targets int) CollectionEnv {
	cfg := config.GetConfig().Collection
	env := CollectionEnv{Tools: make(map[string]bool)}
	for _, name := range []string{"gogo", "naabu", "katana", "spray", "httpx", "nuclei"} {
		env.Tools[name] = strings.TrimSpace(toolruntime.Default().ResolveToolPath(name)) != ""
	}

	switch cfg.Mode {
	case "full":
		return env
	case "staged":
		env.Stage = true
		env.Reasons = append(env.Reasons, "用户显式选择 staged")
		return env
	}

	if targets > cfg.MaxTargetsForFull {
		env.Stage = true
		env.Reasons = append(env.Reasons, fmt.Sprintf("目标数 %d 超过单链阈值 %d", targets, cfg.MaxTargetsForFull))
	}
	if !env.Tools["katana"] {
		env.Stage = true
		env.Reasons = append(env.Reasons, "katana 不可用")
	}
	if !env.Tools["gogo"] && !env.Tools["naabu"] {
		env.Stage = true
		env.Reasons = append(env.Reasons, "gogo/naabu 均不可用，端口阶段需要纯 Go 兜底并降档")
	}
	if !env.Tools["httpx"] && !env.Tools["gogo"] && !env.Tools["naabu"] {
		env.Stage = true
		env.Reasons = append(env.Reasons, "探活工具全部缺失")
	}
	return env
}

// filterStageByTools 按工具可用性裁剪阶段模块，返回裁剪后的 spec 与跳过原因。
// 返回空 scanTypes 表示整个阶段应标记 skipped。
func filterStageByTools(spec collectionStageSpec) (collectionStageSpec, string) {
	var kept []string
	var missing []string
	for _, st := range spec.scanTypes {
		switch st {
		case "crawler":
			if !toolAvailable("katana") {
				missing = append(missing, "katana")
				continue
			}
		case "js_audit":
			if !toolAvailable("nuclei") {
				missing = append(missing, "nuclei")
				continue
			}
		case "dir_scan":
			if !toolAvailable("spray") {
				missing = append(missing, "spray")
				continue
			}
		}
		kept = append(kept, st)
	}
	spec.scanTypes = kept
	reason := ""
	if len(missing) > 0 {
		reason = "工具不可用，已跳过模块: " + strings.Join(missing, ",")
	}
	return spec, reason
}

func toolAvailable(name string) bool {
	return strings.TrimSpace(toolruntime.Default().ResolveToolPath(name)) != ""
}
