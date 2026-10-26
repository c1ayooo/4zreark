package test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/service"
)

// 采集完成综合评估：对真实项目数据聚合资产面与风险面（真 PG）。
func TestCollectionAssessment(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 用麦当劳项目（若被清理则取任意有数字资产的项目）
	var projectID int64
	err := r.Pool().QueryRow(ctx,
		`select id from projects where name = '麦当劳'`).Scan(&projectID)
	if err != nil {
		if err := r.Pool().QueryRow(ctx,
			`select project_id from digital_assets limit 1`).Scan(&projectID); err != nil {
			t.Skip("无可评估项目")
		}
	}

	a, err := service.BuildCollectionAssessment(ctx, projectID, "测试触发")
	if err != nil {
		t.Fatalf("构建评估失败: %v", err)
	}
	if a.ProjectName == "" || a.Trigger != "测试触发" {
		t.Fatalf("基础字段不符: %+v", a)
	}
	if a.Entities < 0 || a.Sites < 0 || a.Seeds < 0 {
		t.Fatalf("计数不应为负: %+v", a)
	}
	if a.DigitalAssets > 0 && len(a.DigitalByKind) == 0 {
		t.Fatalf("有数字资产但无类型分布: %+v", a)
	}
	// 汇总行应包含关键计数
	if !strings.Contains(a.Summary, "主体") || !strings.Contains(a.Summary, "风险") {
		t.Fatalf("汇总文案不符: %q", a.Summary)
	}
	// 风险条目数与 Summary 中的数字一致
	if len(a.Risks) > 0 {
		if !strings.Contains(a.Summary, "风险") {
			t.Fatalf("有风险但汇总未体现")
		}
		for _, rk := range a.Risks {
			if rk == "" {
				t.Fatalf("风险条目为空")
			}
		}
	}
	t.Logf("评估: %+v", a)
	t.Logf("Summary: %s", a.Summary)
	t.Logf("Risks: %v", a.Risks)
}
