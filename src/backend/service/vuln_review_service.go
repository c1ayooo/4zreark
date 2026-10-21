package service

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service/notify"
)

// 复核工作流（P2）。
//
// 原来的状态变更（fixed / ignored / false_positive / verify）都是直接 UPDATE，
// 没有任何流转校验和痕迹：误报能被改成已修复，也说不清是谁、什么时候、为什么改的。
// 现在统一走 ReviewVuln：
//
//	Reviewer（复核人）+ ToStatus（目标状态）+ Note（复核意见）
//	  -> 校验流转合法性（models.VulnTransitionAllowed）
//	  -> vuln_reviews 追加一条记录
//	  -> vulnerabilities 同步 status / reviewer / review_note / reviewed_at / review_count
//	  -> 非 auto 的复核推送一条通知
//
// auto=true 供系统链路（自动 nuclei 验证）复用，不推通知、不强制 note。

const maxReviewNoteLen = 2000

// ReviewVulnInput 是一次复核的入参。
type ReviewVulnInput struct {
	VulnID   string            `json:"vuln_id"`
	ToStatus models.VulnStatus `json:"to_status"`
	Note     string            `json:"note"`
	Reviewer string            `json:"-"`
	Auto     bool              `json:"-"`
}

// ReviewVuln 执行一次复核并返回复核后的漏洞。
func (s *VulnService) ReviewVuln(in ReviewVulnInput) (*models.Vulnerability, *models.VulnReview, error) {
	vulnID := strings.TrimSpace(in.VulnID)
	if !repo.ValidID(vulnID) {
		return nil, nil, errors.New("无效的漏洞ID")
	}
	to := models.VulnStatus(strings.ToLower(strings.TrimSpace(string(in.ToStatus))))
	if !models.ValidVulnStatus(to) {
		return nil, nil, errors.New("非法的目标状态")
	}
	note := strings.TrimSpace(in.Note)
	if len([]rune(note)) > maxReviewNoteLen {
		return nil, nil, errors.New("复核意见过长（上限 2000 字）")
	}
	if !in.Auto && note == "" {
		return nil, nil, errors.New("复核必须填写意见（为什么是这个结论）")
	}
	reviewer := strings.TrimSpace(in.Reviewer)
	if !in.Auto && reviewer == "" {
		return nil, nil, errors.New("缺少复核人")
	}

	store, err := s.store()
	if err != nil {
		return nil, nil, err
	}
	ctx, cancel := dbCtx()
	defer cancel()

	vuln, err := store.GetByID(ctx, vulnID)
	if err != nil {
		return nil, nil, errors.New("漏洞不存在")
	}
	if !models.VulnTransitionAllowed(vuln.Status, to) {
		return nil, nil, errors.New("不允许从「" + models.VulnStatusLabel(vuln.Status) + "」改为「" + models.VulnStatusLabel(to) + "」")
	}

	review := &models.VulnReview{
		VulnID:      vulnID,
		WorkspaceID: vuln.WorkspaceID.Hex(),
		FromStatus:  vuln.Status,
		ToStatus:    to,
		Reviewer:    reviewer,
		Note:        note,
		Auto:        in.Auto,
	}
	if err := store.AddReviewWithCount(ctx, review, to, vuln.ReviewCount+1); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			return nil, nil, errors.New("漏洞不存在")
		}
		return nil, nil, errors.New("写入复核记录失败")
	}

	// 已修复沿用原有 fixed_at / fixed_by 字段，报告与筛选仍按它们取值。
	if to == models.VulnStatusFixed {
		by := reviewer
		if by == "" {
			by = "system"
		}
		if err := store.UpdateFields(ctx, vulnID, map[string]any{
			"fixed_at": time.Now(),
			"fixed_by": by,
		}); err != nil {
			return nil, nil, err
		}
	}
	// 已确认漏洞按既有钩子沉淀 POC（默认不启用）。
	if to == models.VulnStatusConfirmed {
		s.harvestPOC(ctx, vulnID)
	}

	updated, err := store.GetByID(ctx, vulnID)
	if err != nil {
		return nil, nil, err
	}
	if !in.Auto {
		pushVulnReviewNotify(vuln, review)
	}
	return updated, review, nil
}

// ListVulnReviews 返回复核历史（最早在前）。
// BatchReview 对一组漏洞做同一结论的复核。逐条校验流转：
// 不合法的跳过并计数，不因为一条终态记录让整批失败。
func (s *VulnService) BatchReview(ids []string, to models.VulnStatus, note, reviewer string) (updated, skipped int, err error) {
	if len(ids) == 0 {
		return 0, 0, errors.New("请选择要复核的漏洞")
	}
	if !models.ValidVulnStatus(to) {
		return 0, 0, errors.New("非法的目标状态")
	}
	note = strings.TrimSpace(note)
	if note == "" {
		note = "批量复核：标记为「" + models.VulnStatusLabel(to) + "」"
	}
	if len([]rune(note)) > maxReviewNoteLen {
		return 0, 0, errors.New("复核意见过长（上限 2000 字）")
	}
	store, err := s.store()
	if err != nil {
		return 0, 0, err
	}
	ctx, cancel := dbCtx()
	defer cancel()

	for _, id := range ids {
		if !repo.ValidID(id) {
			skipped++
			continue
		}
		v, gerr := store.GetByID(ctx, id)
		if gerr != nil {
			skipped++
			continue
		}
		if !models.VulnTransitionAllowed(v.Status, to) {
			skipped++
			continue
		}
		review := &models.VulnReview{
			VulnID:      id,
			WorkspaceID: v.WorkspaceID.Hex(),
			FromStatus:  v.Status,
			ToStatus:    to,
			Reviewer:    reviewer,
			Note:        note,
		}
		if aerr := store.AddReviewWithCount(ctx, review, to, v.ReviewCount+1); aerr != nil {
			skipped++
			continue
		}
		if to == models.VulnStatusFixed {
			by := reviewer
			if by == "" {
				by = "system"
			}
			_ = store.UpdateFields(ctx, id, map[string]any{"fixed_at": time.Now(), "fixed_by": by})
		}
		if to == models.VulnStatusConfirmed {
			s.harvestPOC(ctx, id)
		}
		updated++
	}
	return updated, skipped, nil
}

func (s *VulnService) ListVulnReviews(vulnID string) ([]*models.VulnReview, error) {
	if !repo.ValidID(vulnID) {
		return nil, errors.New("无效的漏洞ID")
	}
	store, err := s.store()
	if err != nil {
		return nil, err
	}
	ctx, cancel := dbCtx()
	defer cancel()

	reviews, err := store.ListReviews(ctx, vulnID)
	if err != nil {
		return nil, errors.New("查询复核历史失败")
	}
	return reviews, nil
}

// ReviewStats 返回复核分布。
func (s *VulnService) ReviewStats(workspaceID string) (*models.VulnReviewStats, error) {
	store, err := s.store()
	if err != nil {
		return nil, err
	}
	ctx, cancel := dbCtx()
	defer cancel()

	st, err := store.ReviewStats(ctx, workspaceID)
	if err != nil {
		return nil, fmt.Errorf("统计复核分布失败: %w", err)
	}
	return st, nil
}

// pushVulnReviewNotify 复核结论推一条通知：终态结论值得让人知道，
// 但级别按结论分档——误报/忽略只是信息，确认与已修复才需要跟进。
func pushVulnReviewNotify(vuln *models.Vulnerability, review *models.VulnReview) {
	m := notify.GetGlobalManager()
	if m == nil {
		return
	}
	level := notify.NotifyLevelInfo
	switch review.ToStatus {
	case models.VulnStatusConfirmed:
		level = notify.NotifyLevelWarning
	case models.VulnStatusFixed:
		level = notify.NotifyLevelInfo
	}
	content := "漏洞：" + vuln.Name + "\n目标：" + vuln.Target +
		"\n复核人：" + review.Reviewer +
		"\n结论：" + models.VulnStatusLabel(review.FromStatus) + " → " + models.VulnStatusLabel(review.ToStatus)
	if review.Note != "" {
		content += "\n意见：" + review.Note
	}
	m.SendAsync(&notify.NotifyMessage{
		Level:   level,
		Title:   "漏洞复核：" + models.VulnStatusLabel(review.ToStatus),
		Content: content,
		Source:  "vuln-review",
	})
}
