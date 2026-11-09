package service

import (
	"context"
	"strings"

	"github.com/c1ayooo/4zreark/repo"
)

// 技能调用记录：为什么单独记一份。
//
// 对话里的 skill.loaded 事件只是渲染用的中间态，会被前端裁剪、也会随消息删除而消失。
// 「这个技能被用了多少次、失败率多少、平均耗时、吃多少 token」是运维问题，
// 需要独立于会话生命周期存在，所以每次注入都落一行 skill_usage。

// StartSkillUsage 落一条「运行中」的记录，返回记录 id（失败返回空，不阻断对话）。
func StartSkillUsage(ctx context.Context, skill SentinelSkill, convID, userID, source, model string) string {
	if strings.TrimSpace(skill.ID) == "" {
		return ""
	}
	rec := &repo.SkillUsageRecord{
		SkillID:        skill.ID,
		SkillName:      skill.Name,
		SkillVersion:   skill.Version,
		ConversationID: convID,
		UserID:         userID,
		Source:         source,
		Model:          model,
		Status:         "running",
	}
	if err := repo.Default().Chat().CreateSkillUsage(ctx, rec); err != nil {
		return ""
	}
	return rec.ID
}

// FinishSkillUsage 回填结果。用 context.Background()：调用点常在 defers 里，
// 此时请求 ctx 可能已经取消，用取消的 ctx 写库会静默失败。
func FinishSkillUsage(id, status string, tokensIn, tokensOut, durationMS int, errMsg, model string) {
	if strings.TrimSpace(id) == "" {
		return
	}
	if status == "" {
		status = "finished"
	}
	_ = repo.Default().Chat().FinishSkillUsage(context.Background(), &repo.SkillUsageRecord{
		ID:         id,
		Status:     status,
		TokensIn:   tokensIn,
		TokensOut:  tokensOut,
		DurationMS: durationMS,
		Error:      strings.TrimSpace(errMsg),
		Model:      model,
	})
}

// SkillUsageQuery 是调用记录列表的查询参数。
type SkillUsageQuery struct {
	SkillID  string `form:"skill_id"`
	Status   string `form:"status"`
	Page     int    `form:"page"`
	PageSize int    `form:"page_size"`
	// ScopeUserID 非空时只返回该用户的记录（普通成员只能看自己的）。
	ScopeUserID string `form:"-"`
}

// SkillUsagePage 是列表返回：记录 + 总数 + 顶部汇总。
type SkillUsagePage struct {
	Items    []repo.SkillUsageRecord `json:"items"`
	Total    int                     `json:"total"`
	Page     int                     `json:"page"`
	PageSize int                     `json:"page_size"`
	Summary  *repo.SkillUsageSummary `json:"summary"`
}

// ListSkillUsage 返回分页记录与汇总。汇总同样按 scope 过滤，避免普通成员看到全局用量。
func ListSkillUsage(ctx context.Context, q SkillUsageQuery) (*SkillUsagePage, error) {
	if q.Page <= 0 {
		q.Page = 1
	}
	if q.PageSize <= 0 || q.PageSize > 100 {
		q.PageSize = 20
	}
	f := repo.SkillUsageFilter{
		SkillID: strings.TrimSpace(q.SkillID),
		Status:  strings.TrimSpace(q.Status),
		UserID:  strings.TrimSpace(q.ScopeUserID),
		Limit:   q.PageSize,
		Offset:  (q.Page - 1) * q.PageSize,
	}
	items, total, err := repo.Default().Chat().ListSkillUsage(ctx, f)
	if err != nil {
		return nil, err
	}
	summary, err := repo.Default().Chat().SkillUsageSummary(ctx, f)
	if err != nil {
		return nil, err
	}
	return &SkillUsagePage{
		Items:    items,
		Total:    total,
		Page:     q.Page,
		PageSize: q.PageSize,
		Summary:  summary,
	}, nil
}
