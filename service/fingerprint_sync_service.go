package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	reconfp "github.com/c1ayooo/4zreark/internal/recon/fingerprint"
	"github.com/c1ayooo/4zreark/repo"
)

// T10：指纹规则同步。
//
// 当前内置规则集（dddd 快照 + 种子）已经随二进制发布，这里把它落进
// fingerprint_rules.expression / rule_hash，供治理域与后续上游同步共用。
// 网络拉取（wappalyzergo / webanalyze）留出同一入口，不在本轮开启。
//
// 来源隔离：
//   - dddd 快照 -> source='dddd'
//   - 内置种子 -> source='seed'
//   - 用户 custom / 旧版导入的规则永远不会被覆盖或删除（repo 的 upsert
//     只更新同 source 的行，清理也只删当前 source）。

type FpSyncStats struct {
	Source   string `json:"source"`
	Rules    int    `json:"rules"`    // 合并后的规则数
	Imported int    `json:"imported"` // 实际写入/更新的行数
	Skipped  int    `json:"skipped"`
	Merged   int    `json:"merged"` // 同名规则合并数
}

type fpSyncGroup struct {
	source      string
	upstreamURL string
	contentHash string
	skipped     int
	rules       []repo.FpSyncRule
	merged      int
}

type FingerprintSyncService struct{}

func NewFingerprintSyncService() *FingerprintSyncService { return &FingerprintSyncService{} }

// SyncEmbedded 把内置规则集写入 PG。幂等：重复执行只更新同源规则。
func (s *FingerprintSyncService) SyncEmbedded(ctx context.Context) ([]FpSyncStats, error) {
	r := repo.Default()
	if r == nil {
		return nil, errors.New("数据层未初始化")
	}
	groups := groupEmbeddedRules(reconfp.DefaultRuleSet())

	out := make([]FpSyncStats, 0, len(groups))
	syncRepo := r.FingerprintSync()
	for _, g := range groups {
		imported, err := syncRepo.ImportUpstream(ctx, g.source, g.upstreamURL, g.contentHash, g.rules, g.skipped)
		if err != nil {
			return out, err
		}
		out = append(out, FpSyncStats{
			Source:   g.source,
			Rules:    len(g.rules),
			Imported: imported,
			Skipped:  g.skipped,
			Merged:   g.merged,
		})
	}
	// 治理域规则缓存 60s TTL，同步后立即失效。
	NewFingerprintService().Invalidate()
	return out, nil
}

// groupEmbeddedRules 按来源分组并按 name 合并表达式。
// 同名的多条规则合并成一条 OR 表达式，避免 fingerprint_rules.name 唯一约束
// 让后面的规则被静默丢弃。
func groupEmbeddedRules(raw []reconfp.Rule) []fpSyncGroup {
	const (
		sourceDddd = "dddd"
		sourceSeed = "seed"
	)

	order := []string{sourceDddd, sourceSeed}
	index := map[string]*fpSyncGroup{
		sourceDddd: {source: sourceDddd, upstreamURL: "embedded://dddd-snapshot"},
		sourceSeed: {source: sourceSeed, upstreamURL: "embedded://fingerprint-seeds"},
	}
	seen := map[string]map[string]bool{
		sourceDddd: {},
		sourceSeed: {},
	}

	for _, r := range raw {
		if !r.Enabled {
			continue
		}
		src := sourceSeed
		if r.Source == reconfp.SourceDddd {
			src = sourceDddd
		}
		g := index[src]

		name := strings.TrimSpace(r.Name)
		expr := strings.TrimSpace(r.Expression)
		if name == "" || expr == "" {
			g.skipped++
			continue
		}
		// rule_hash 对 name 做了小写归一，合并也必须按大小写不敏感来分组，
		// 否则 "FastSpring" 与 "fastspring" 会撞 fingerprint_rule_hash_uq。
		nameKey := strings.ToLower(name)

		if seen[src][nameKey] {
			// 同名：把新表达式 OR 进已有规则
			for i := range g.rules {
				if strings.EqualFold(g.rules[i].Name, name) {
					g.rules[i].Expression = "(" + g.rules[i].Expression + ") || (" + expr + ")"
					g.rules[i].RuleHash = fpRuleHash(g.rules[i].Name, g.rules[i].Expression)
					break
				}
			}
			g.merged++
			continue
		}
		seen[src][nameKey] = true
		g.rules = append(g.rules, repo.FpSyncRule{
			Name:       name,
			Category:   r.Category,
			Expression: expr,
			RuleHash:   fpRuleHash(name, expr),
		})
	}

	out := make([]fpSyncGroup, 0, len(order))
	for _, src := range order {
		g := index[src]
		if len(g.rules) == 0 {
			continue
		}
		g.contentHash = fpContentHash(g.rules)
		out = append(out, *g)
	}
	return out
}

func fpRuleHash(name, expression string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(name)) + "\x00" + strings.TrimSpace(expression)))
	return hex.EncodeToString(sum[:])
}

func fpContentHash(rules []repo.FpSyncRule) string {
	h := sha256.New()
	for _, r := range rules {
		h.Write([]byte(r.RuleHash))
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}
