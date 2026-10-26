package githubleak

import (
	"context"
	"errors"
	"strings"

	"github.com/c1ayooo/4zreark/internal/lz"
)

// filterBoilerplateStorm 样板风暴识别（误报治理第二层）：
// 同一 path+检测类型在单轮内命中 ≥ threshold 个不同仓库时，判定为框架/脚手架
// 样板复制——每个仓库里的"密钥"各不相同（指纹不同，入库去重拦不住）但同为演示值。
// 只降重 suspected（赋值启发式）级候选；likely（强特征：真实 token 结构）不受影响。
func (s *Service) filterBoilerplateStorm(ruleName string, candidates []Candidate, threshold int) ([]Candidate, int) {
	if threshold <= 0 || len(candidates) == 0 {
		return candidates, 0
	}
	type groupKey struct{ path, kind string }
	repos := map[groupKey]map[string]struct{}{}
	for _, c := range candidates {
		if c.Confidence != "suspected" {
			continue
		}
		k := groupKey{strings.ToLower(c.Path), c.SecretType}
		if repos[k] == nil {
			repos[k] = map[string]struct{}{}
		}
		repos[k][c.Repository] = struct{}{}
	}
	storm := map[groupKey]bool{}
	for k, set := range repos {
		if len(set) >= threshold {
			storm[k] = true
		}
	}
	if len(storm) == 0 {
		return candidates, 0
	}
	kept := make([]Candidate, 0, len(candidates))
	dropped := 0
	for _, c := range candidates {
		k := groupKey{strings.ToLower(c.Path), c.SecretType}
		if storm[k] {
			dropped++
			continue
		}
		kept = append(kept, c)
	}
	if dropped > 0 && s.logger != nil {
		s.logger.Info("GitHub leak monitor 样板风暴降重",
			lz.String("rule", ruleName), lz.Int("dropped", dropped),
			lz.Int("groups", len(storm)), lz.Int("threshold", threshold))
	}
	return kept, dropped
}

// filterValueStorm 值级频次抑制（误报治理第三层，R8 静态闸门之三）：
// 同一密钥值（HMAC 指纹）在单规则单轮内命中 ≥ threshold 个不同仓库时，判定为
// 教学/样板/二次搬运——各类 "leaked keys / config 合集" 仓库里的值几乎全为转发。
// 整组降级：likely → suspected（保留可观测，退出高危队列与即时推送优先级），
// suspected → 丢弃。阈值与样板风暴共用 boilerplate_repos 配置；丢弃计数并入
// FilteredBoilerplate（同属样板抑制，不新增 schema）。
func (s *Service) filterValueStorm(ruleName string, candidates []Candidate, threshold int) ([]Candidate, int) {
	if threshold <= 0 || len(candidates) == 0 {
		return candidates, 0
	}
	type groupKey struct{ kind, fingerprint string }
	repos := map[groupKey]map[string]struct{}{}
	for _, c := range candidates {
		k := groupKey{c.SecretType, c.Fingerprint}
		if repos[k] == nil {
			repos[k] = map[string]struct{}{}
		}
		repos[k][c.Repository] = struct{}{}
	}
	storm := map[groupKey]bool{}
	for k, set := range repos {
		if len(set) >= threshold {
			storm[k] = true
		}
	}
	if len(storm) == 0 {
		return candidates, 0
	}
	kept := make([]Candidate, 0, len(candidates))
	dropped := 0
	for _, c := range candidates {
		k := groupKey{c.SecretType, c.Fingerprint}
		if !storm[k] {
			kept = append(kept, c)
			continue
		}
		if c.Confidence == "likely" {
			c.Confidence = "suspected"
			kept = append(kept, c)
			continue
		}
		dropped++
	}
	if s.logger != nil {
		s.logger.Info("GitHub leak monitor 值级频次抑制",
			lz.String("rule", ruleName), lz.Int("dropped", dropped),
			lz.Int("groups", len(storm)), lz.Int("threshold", threshold))
	}
	return kept, dropped
}

// CleanupNoiseFindings 历史误报清洗（apply=false 预览；true 删除）。
func (s *Service) CleanupNoiseFindings(ctx context.Context, apply bool) (CleanupReport, error) {
	if s == nil || s.store == nil {
		return CleanupReport{}, errors.New("存储不可用")
	}
	src, ok := s.store.(interface {
		CleanupNoiseFindings(context.Context, bool) (CleanupReport, error)
	})
	if !ok {
		return CleanupReport{}, errors.New("存储不支持清洗")
	}
	return src.CleanupNoiseFindings(ctx, apply)
}
