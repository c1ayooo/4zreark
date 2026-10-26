package test

import (
	"context"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/oid"
	"github.com/c1ayooo/4zreark/service"
)

// 漏洞复核工作流：流转校验、复核记录、历史、字段回写。
func TestVulnReviewWorkflow(t *testing.T) {
	r := openTestRepo(t)
	_ = r

	name := "复核测试漏洞-" + time.Now().Format("150405.000000")
	vuln := &models.Vulnerability{
		WorkspaceID: oid.NewObjectID(),
		Name:        name,
		Severity:    models.VulnSeverityHigh,
		Type:        "rce",
		Target:      "http://review-test.example.com/api",
		Scanner:     "test",
	}
	vulnSvc := service.NewVulnService()
	if err := vulnSvc.CreateVulnerability(vuln); err != nil {
		t.Fatalf("创建漏洞失败: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = r.Pool().Exec(bg, `DELETE FROM vuln_reviews WHERE vuln_id = $1`, vuln.ID.Hex())
		_, _ = r.Pool().Exec(bg, `DELETE FROM vulnerabilities WHERE id = $1`, vuln.ID.Hex())
	})

	id := vuln.ID.Hex()

	// 1) 新漏洞缺意见直接拒绝：复核必须说明理由。
	if _, _, err := vulnSvc.ReviewVuln(service.ReviewVulnInput{
		VulnID: id, ToStatus: models.VulnStatusConfirmed, Reviewer: "alice",
	}); err == nil {
		t.Error("缺复核意见应被拒绝")
	}

	// 2) 非法目标状态拒绝。
	if _, _, err := vulnSvc.ReviewVuln(service.ReviewVulnInput{
		VulnID: id, ToStatus: models.VulnStatus("reopened"), Note: "重开", Reviewer: "alice",
	}); err == nil {
		t.Error("非法目标状态应被拒绝")
	}

	// 3) new -> confirmed 合法，复核人/意见/计数落库。
	updated, review, err := vulnSvc.ReviewVuln(service.ReviewVulnInput{
		VulnID: id, ToStatus: models.VulnStatusConfirmed,
		Note: "手工复测命令可执行", Reviewer: "alice",
	})
	if err != nil {
		t.Fatalf("复核失败: %v", err)
	}
	if review.FromStatus != models.VulnStatusNew || review.ToStatus != models.VulnStatusConfirmed {
		t.Errorf("复核记录流转 = %s -> %s", review.FromStatus, review.ToStatus)
	}
	if review.Reviewer != "alice" {
		t.Errorf("复核人 = %q", review.Reviewer)
	}
	if updated.Status != models.VulnStatusConfirmed {
		t.Errorf("漏洞状态 = %q，期望 confirmed", updated.Status)
	}
	if updated.Reviewer != "alice" || updated.ReviewNote == "" {
		t.Errorf("复核字段未回写: reviewer=%q note=%q", updated.Reviewer, updated.ReviewNote)
	}
	if updated.ReviewCount != 1 || updated.ReviewedAt == nil {
		t.Errorf("复核计数/时间错误: count=%d at=%v", updated.ReviewCount, updated.ReviewedAt)
	}

	// 4) 非法流转拒绝：confirmed -> confirmed、fixed -> false_positive。
	if _, _, err := vulnSvc.ReviewVuln(service.ReviewVulnInput{
		VulnID: id, ToStatus: models.VulnStatusConfirmed, Note: "重复确认", Reviewer: "alice",
	}); err == nil {
		t.Error("confirmed -> confirmed 应被拒绝")
	}

	// 5) confirmed -> fixed 合法，且补写 fixed_at / fixed_by。
	fixed, _, err := vulnSvc.ReviewVuln(service.ReviewVulnInput{
		VulnID: id, ToStatus: models.VulnStatusFixed, Note: "厂商已修复", Reviewer: "bob",
	})
	if err != nil {
		t.Fatalf("复核为已修复失败: %v", err)
	}
	if fixed.FixedBy != "bob" || fixed.FixedAt.IsZero() {
		t.Errorf("fixed_at/fixed_by 未写: by=%q at=%v", fixed.FixedBy, fixed.FixedAt)
	}
	if fixed.ReviewCount != 2 {
		t.Errorf("复核计数 = %d，期望 2", fixed.ReviewCount)
	}

	// 6) 终态互转拒绝：fixed -> false_positive。
	if _, _, err := vulnSvc.ReviewVuln(service.ReviewVulnInput{
		VulnID: id, ToStatus: models.VulnStatusFalse, Note: "改主意", Reviewer: "bob",
	}); err == nil {
		t.Error("fixed -> false_positive 应被拒绝")
	}

	// 7) 历史按时间正序，两条记录。
	reviews, err := vulnSvc.ListVulnReviews(id)
	if err != nil {
		t.Fatalf("查询历史失败: %v", err)
	}
	if len(reviews) != 2 {
		t.Fatalf("复核历史应有 2 条，实际 %d", len(reviews))
	}
	if reviews[0].ToStatus != models.VulnStatusConfirmed || reviews[1].ToStatus != models.VulnStatusFixed {
		t.Errorf("历史顺序错误: %s -> %s", reviews[0].ToStatus, reviews[1].ToStatus)
	}

	// 8) 批量复核：跳过非法流转，不整批失败。
	other := &models.Vulnerability{
		WorkspaceID: vuln.WorkspaceID, Name: name + "-b", Severity: models.VulnSeverityMedium,
		Type: "xss", Target: "http://review-test.example.com/b", Scanner: "test",
	}
	if err := vulnSvc.CreateVulnerability(other); err != nil {
		t.Fatalf("创建第二个漏洞失败: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = r.Pool().Exec(bg, `DELETE FROM vuln_reviews WHERE vuln_id = $1`, other.ID.Hex())
		_, _ = r.Pool().Exec(bg, `DELETE FROM vulnerabilities WHERE id = $1`, other.ID.Hex())
	})

	// 目标是 confirmed：第一条（已 fixed）会被跳过，第二条（new）通过。
	updated2, skipped, err := vulnSvc.BatchReview(
		[]string{vuln.ID.Hex(), other.ID.Hex(), "invalid-id"},
		models.VulnStatusConfirmed, "批量复核", "alice")
	if err != nil {
		t.Fatalf("批量复核失败: %v", err)
	}
	if updated2 != 1 {
		t.Errorf("批量复核应更新 1 条，实际 %d", updated2)
	}
	if skipped != 2 {
		t.Errorf("批量复核应跳过 2 条，实际 %d", skipped)
	}
}

// 复核分布统计。
func TestVulnReviewStats(t *testing.T) {
	_ = openTestRepo(t)
	vulnSvc := service.NewVulnService()
	stats, err := vulnSvc.ReviewStats("")
	if err != nil {
		t.Fatalf("统计复核分布失败: %v", err)
	}
	if stats.ByStatus == nil {
		t.Fatal("ByStatus 不应为空")
	}
	if _, ok := stats.ByStatus[models.VulnStatusConfirmed]; !ok && stats.Reviewed > 0 {
		t.Error("存在已复核漏洞时应有 confirmed 计数")
	}
}
