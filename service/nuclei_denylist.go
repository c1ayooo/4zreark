package service

// nuclei 误报黑名单：平台侧可管理的 template-id 排除清单。
//
// 存储两层：
//   - app_settings 的 nuclei.deny_template_ids（KV 设置，前端可增删，即时生效）；
//   - config.yaml 的 scanner.nuclei_deny_template_ids（兜底，master/worker 一致）。
//
// 合并语义：两层取并集去重。任务创建时把生效值盖章进 task.Config.deny_template_ids，
// worker 不连数据库，只消费随任务下发的清单。

import (
	"context"
	"errors"
	"sort"
	"strings"

	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/repo"
)

const settingKeyNucleiDenyTemplateIDs = "nuclei.deny_template_ids"

// errRepoUnavailable 是 repo.Default() 为 nil（DB 未就绪/worker 侧）时的统一错误。
var errRepoUnavailable = errors.New("数据库未就绪")

// mergeDenyTemplateIDs 合并去重并排序，保证盖章值稳定。
func mergeDenyTemplateIDs(lists ...[]string) []string {
	seen := make(map[string]struct{})
	for _, list := range lists {
		for _, id := range list {
			id = strings.TrimSpace(id)
			if id == "" {
				continue
			}
			seen[id] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// GetNucleiDenyTemplateIDs 读 KV 设置层的黑名单（不含 config 兜底）。
func GetNucleiDenyTemplateIDs(ctx context.Context) ([]string, bool, error) {
	r := repo.Default()
	if r == nil {
		return nil, false, nil
	}
	var ids []string
	found, err := r.Settings().Get(ctx, settingKeyNucleiDenyTemplateIDs, &ids)
	if err != nil || !found {
		return nil, found, err
	}
	return ids, true, nil
}

// SaveNucleiDenyTemplateIDs 覆盖 KV 设置层的黑名单。
func SaveNucleiDenyTemplateIDs(ctx context.Context, ids []string) error {
	r := repo.Default()
	if r == nil {
		return errRepoUnavailable
	}
	return r.Settings().Set(ctx, settingKeyNucleiDenyTemplateIDs, mergeDenyTemplateIDs(ids))
}

// ResolveNucleiDenyTemplateIDs 返回全局生效黑名单（KV 设置 ∪ config 兜底）。
// DB 不可用时只回落 config——worker 侧就是靠这条路兜底的。
func ResolveNucleiDenyTemplateIDs(ctx context.Context) []string {
	var kv []string
	if ids, found, err := GetNucleiDenyTemplateIDs(ctx); err == nil && found {
		kv = ids
	}
	var fileCfg []string
	if c := config.Loaded(); c != nil {
		fileCfg = c.Scanner.NucleiDenyTemplateIDs
	}
	return mergeDenyTemplateIDs(kv, fileCfg)
}
