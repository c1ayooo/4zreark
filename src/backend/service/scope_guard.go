package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/scanner/scope"
)

// checkTargetScope 用项目种子作为授权边界（fail-closed）。
// 自动验证与工具箱里的凭据验证/差分探测共用这一道闸。
func checkTargetScope(ctx context.Context, projectID int64, target string) error {
	if projectID <= 0 {
		return fmt.Errorf("项目 ID 无效")
	}
	r := repo.Default()
	if r == nil {
		return fmt.Errorf("数据库未就绪")
	}
	seeds, err := r.Seeds().ListSeeds(ctx, projectID)
	if err != nil {
		return fmt.Errorf("读取项目种子失败: %w", err)
	}
	targets := make([]string, 0, len(seeds))
	for _, seed := range seeds {
		if seed != nil && strings.TrimSpace(seed.Value) != "" {
			targets = append(targets, seed.Value)
		}
	}
	if len(targets) == 0 {
		return fmt.Errorf("项目 %d 没有授权种子，拒绝执行", projectID)
	}
	if !scope.New(targets).AllowsURL(target) {
		return fmt.Errorf("目标 %s 不在项目 %d 的授权范围内", target, projectID)
	}
	return nil
}
