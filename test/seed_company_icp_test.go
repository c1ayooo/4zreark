package test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
)

// 公司种子 live 展开走官方 ICP（无测绘 Key 时的默认路径）。
// 真实官方站，MIIT_LIVE=1 打开。
func TestSeedCompanyOfficialICP(t *testing.T) {
	if os.Getenv("MIIT_LIVE") != "1" {
		t.Skip("跳过官方 ICP 种子展开：设置 MIIT_LIVE=1 打开")
	}
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	code := fmt.Sprintf("seed-icp-%d", time.Now().UnixNano())
	var projectID int64
	if err := r.Pool().QueryRow(ctx,
		`INSERT INTO projects (code,name) VALUES ($1,$2) RETURNING id`, code, code).Scan(&projectID); err != nil {
		t.Fatalf("建项目失败: %v", err)
	}
	t.Cleanup(func() {
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM projects WHERE id=$1`, projectID)
	})

	svc := service.NewCycleService()
	res, err := svc.ExpandSeed(ctx, &repo.Seed{
		ProjectID: projectID, Kind: "company",
		Value:      "深圳市腾讯计算机系统有限公司",
		Capability: map[string]any{"live": true, "max_domains": 5},
	}, true, 20, 20)
	if err != nil {
		t.Fatalf("公司种子展开失败: %v", err)
	}
	if res.Total == 0 {
		t.Fatalf("官方 ICP 未展开出目标: %+v", res)
	}
	joined := strings.Join(res.Warnings, " | ")
	if !strings.Contains(joined, "icp_official") && !strings.Contains(joined, "官方 ICP") {
		t.Fatalf("应走官方 ICP 路径，warnings=%s", joined)
	}
	t.Logf("targets=%d warnings=%s", res.Total, joined)
}
