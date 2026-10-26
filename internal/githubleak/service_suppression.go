package githubleak

import (
	"context"
	"errors"
	"fmt"

	"github.com/c1ayooo/4zreark/internal/lz"

	)

// ResetWaterline 重置规则水位线（query 空=全部）→ 下一轮强制全量（历史回扫）。
// 存储不支持时返回不可用错误（测试 fake 场景）。
func (s *Service) ResetWaterline(ctx context.Context, query string) (int64, error) {
	if s == nil || s.store == nil {
		return 0, errors.New("存储不可用")
	}
	src, ok := s.store.(interface {
		ResetWaterline(context.Context, string) (int64, error)
	})
	if !ok {
		return 0, errors.New("存储不支持水位线重置")
	}
	return src.ResetWaterline(ctx, query)
}

// RulePrecisionStats 规则精确率运营视图。
func (s *Service) RulePrecisionStats(ctx context.Context) ([]RulePrecision, error) {
	if s == nil || s.store == nil {
		return nil, nil
	}
	src, ok := s.store.(interface {
		RulePrecisionStats(context.Context) ([]RulePrecision, error)
	})
	if !ok {
		return nil, nil
	}
	return src.RulePrecisionStats(ctx)
}

// --- 规则自净（R7-1）---

const (
	// selfCleanMinJudged 自动停用判定所需的最少"已研判"样本（new 状态不计入——
	// 没人看过的命中不能证明规则失效；小样本宁漏停不错停）。
	selfCleanMinJudged = 8
	// selfCleanFPThreshold 误报占比阈值（文档 R7 建议 80%）。
	selfCleanFPThreshold = 0.8
)

// ruleSuppressionWriter 可选接口：静默清单写入（*Store 实现；测试 fake 可实现）。
type ruleSuppressionWriter interface {
	AddSuppression(context.Context, string, string, string, string) (bool, error)
}

// autoDisableNoisyRules 规则自净：误报占比超阈的启用中规则自动写入 rule 维度
// 静默清单（等效禁用；清单可删除恢复，不回写 config.yaml），每条新停用规则
// 通知一次。每轮 run 收尾时调用。
func (s *Service) autoDisableNoisyRules(ctx context.Context) {
	if s == nil || s.store == nil {
		return
	}
	stats, err := s.RulePrecisionStats(ctx)
	if err != nil || len(stats) == 0 {
		return
	}
	writer, ok := s.store.(ruleSuppressionWriter)
	if !ok {
		return
	}
	s.mu.Lock()
	enabled := map[string]bool{}
	for _, r := range s.settings.Rules {
		if r.Enabled {
			enabled[r.Name] = true
		}
	}
	s.mu.Unlock()
	for _, st := range stats {
		if !enabled[st.RuleName] {
			continue
		}
		judged := st.Confirmed + st.FalsePositive + st.Ignored
		if judged < selfCleanMinJudged || judged <= 0 {
			continue
		}
		ratio := float64(st.FalsePositive) / float64(judged)
		if ratio < selfCleanFPThreshold {
			continue
		}
		note := fmt.Sprintf("规则自净：已研判 %d 条中误报 %d 条（占比 %.0f%%），自动停用；如需恢复请从静默清单删除本条", judged, st.FalsePositive, ratio*100)
		added, err := writer.AddSuppression(ctx, SuppressionRule, st.RuleName, note, "auto-selfclean")
		if err != nil {
			s.logger.Warn("GitHub leak monitor 规则自净写入静默失败", lz.String("rule", st.RuleName), lz.Error(err))
			continue
		}
		if !added {
			continue // 已在清单中（幂等），不重复通知
		}
		if s.logger != nil {
			s.logger.Info("GitHub leak monitor 规则自净停用高误报规则",
				lz.String("rule", st.RuleName), lz.Int("judged", judged), lz.Int("false_positive", st.FalsePositive))
		}
		s.notifySelfClean(st, judged, ratio)
	}
}

// notifySelfClean 规则自净停用的一次性 IM 通知。
func (s *Service) notifySelfClean(st RulePrecision, judged int, ratio float64) {
	s.mu.Lock()
	publish := s.notify
	s.mu.Unlock()
	if publish == nil {
		return
	}
	publish(Event{
		Kind:      KindGithubLeakRuleDisabled,
		Level:     "medium",
		Title:     "GitHub 泄露监控规则自动停用",
		Summary:   fmt.Sprintf("规则「%s」误报占比 %.0f%%（已研判 %d / 误报 %d），已自动写入静默清单；如误停请到静默清单恢复", st.RuleName, ratio*100, judged, st.FalsePositive),
		Footer:    "处置入口：资产管理 → 信息收集 → GitHub 泄露监控 → 静默清单",
		DedupKey:  "githubleak:selfclean:" + st.RuleName,
		Broadcast: true,
	})
}

// --- 静默清单管理（供 REST API）---

// ListSuppressions 返回静默清单（store 不支持时返回空表）。
func (s *Service) ListSuppressions(ctx context.Context) ([]Suppression, error) {
	if s == nil || s.store == nil {
		return nil, nil
	}
	if src, ok := s.store.(suppressionSource); ok {
		return src.ListSuppressions(ctx)
	}
	return nil, nil
}

// AddSuppression 新增静默规则（幂等）。返回是否真正新增。
func (s *Service) AddSuppression(ctx context.Context, patternType, pattern, note, createdBy string) (bool, error) {
	if s == nil || s.store == nil {
		return false, errors.New("静默清单存储不可用")
	}
	src, ok := s.store.(suppressionSource)
	if !ok {
		return false, errors.New("静默清单存储不可用")
	}
	store, ok := src.(*Store)
	if !ok {
		return false, errors.New("静默清单存储不可用")
	}
	return store.AddSuppression(ctx, patternType, pattern, note, createdBy)
}

// DeleteSuppression 删除静默规则。
func (s *Service) DeleteSuppression(ctx context.Context, id string) (bool, error) {
	if s == nil || s.store == nil {
		return false, errors.New("静默清单存储不可用")
	}
	src, ok := s.store.(suppressionSource)
	if !ok {
		return false, errors.New("静默清单存储不可用")
	}
	store, ok := src.(*Store)
	if !ok {
		return false, errors.New("静默清单存储不可用")
	}
	return store.DeleteSuppression(ctx, id)
}
