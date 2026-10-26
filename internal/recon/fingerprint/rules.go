package fingerprint

import (
	"log"
	"strings"
	"sync"
)

// 来源标识(与上游同步版本的语义一致;本仓库 v1 只有内置快照与种子)。
const (
	SourceWappalyzergo = "wappalyzergo"
	SourceWebanalyze   = "webanalyze"
	SourceDddd         = "dddd"
	SourceCustom       = "custom"
	// fingers 生态（chainreactors/fingers resources/ 的规范化数据翻译）
	SourceEHole   = "ehole"
	SourceGoby    = "goby"
	SourceFingers = "fingers"
)

// Rule 一条指纹规则(未编译形态,来源解析/种子的产物)。
type Rule struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Category   string `json:"category"`
	Expression string `json:"expression"`
	Enabled    bool   `json:"enabled"`
	Source     string `json:"source"`
	RuleHash   string `json:"rule_hash"`
	CreatedAt  string `json:"created_at,omitempty"`
	UpdatedAt  string `json:"updated_at,omitempty"`
}

// DefaultSeedsDir is kept for callers that want to load extra seed rules from a
// directory (see LoadSeedRulesDir). DefaultRules itself uses the embedded seeds,
// so it works from any working directory.
const DefaultSeedsDir = "configs/fingerprint-seeds"

// LoadSeedRulesDir loads extra seed rules from dir. It is optional; the bundled
// seeds are already embedded and loaded by DefaultRules.
func LoadSeedRulesDir(dir string) ([]Rule, []error) { return loadSeedRulesFromDir(dir) }

var (
	defaultOnce    sync.Once
	defaultRules   []CompiledRule
	defaultRuleSet []Rule
	defaultInfo    string
)

// DefaultRules 内置规则集:dddd 出厂快照(7,587 条)+ 内置种子,进程内
// 一次编译常驻。匹配是纯内存计算,数千条规则对一次观测在毫秒级。
func DefaultRules() []CompiledRule {
	defaultOnce.Do(loadDefaultRules)
	return defaultRules
}

// DefaultRuleSet 返回未编译的内置规则集（落库/审计/同步用）。
// 返回的是副本，调用方可以按 name 合并或改 Source，不会污染匹配用的编译缓存。
func DefaultRuleSet() []Rule {
	defaultOnce.Do(loadDefaultRules)
	out := make([]Rule, len(defaultRuleSet))
	copy(out, defaultRuleSet)
	return out
}

// DefaultRulesInfo 规则集描述(日志/状态展示用)。
func DefaultRulesInfo() string {
	defaultOnce.Do(loadDefaultRules)
	return defaultInfo
}

func loadDefaultRules() {
	var rules []Rule
	rules, stats, err := ParseDdddFinger(ddddSnapshotYAML)
	if err != nil {
		log.Printf("[fingerprint] 快照解析失败: %v", err)
		rules = nil
	}
	seedRules, seedErrs := loadEmbeddedSeedRules()
	rules = append(rules, seedRules...)
	for _, e := range seedErrs {
		log.Printf("[fingerprint] %v", e)
	}
	defaultRuleSet = append([]Rule(nil), rules...)

	compiled := make([]CompiledRule, 0, len(rules))
	skipped := 0
	for _, r := range rules {
		if !r.Enabled && r.Source == SourceCustom {
			continue
		}
		expr, err := ParseExpression(r.Expression)
		if err != nil {
			skipped++
			continue
		}
		compiled = append(compiled, CompiledRule{
			ID:         r.ID,
			Name:       r.Name,
			Category:   r.Category,
			Expression: r.Expression,
			Expr:       expr,
		})
	}
	defaultRules = compiled
	defaultInfo = "dddd 快照 " + itoa(len(rules)-len(seedRules)) + " 条(跳过 " +
		itoa(stats.PatternsSkipped) + ") + 种子 " + itoa(len(seedRules)) + " 条,编译生效 " +
		itoa(len(compiled)) + " 条"
	log.Printf("[fingerprint] 规则集就绪: %s", defaultInfo)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// isBlankSeedName 空名判断的语义别名(种子加载用)。
func isBlankSeedName(s string) bool { return strings.TrimSpace(s) == "" }
