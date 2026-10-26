// Package githubleak monitors GitHub code search for likely credential leaks.
// Findings carry masked excerpts by default; in authorized engagements the
// matched plaintext is additionally persisted for triage (see
// docs/zh-CN/github-leak-monitor.md for the storage policy).
package githubleak

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	MinIntervalSeconds     = 31
	DefaultIntervalSeconds = 60
	DefaultTimeoutSeconds  = 45
	DefaultPollSeconds     = 7200
	DefaultMaxResults      = 100
	MaxRules               = 48
	MaxKeywords            = 6
	maxKeywordBytes        = 200
	maxRuleNameBytes       = 100
	maxQueryLiteralBytes   = 256
	maxRuleQueryBytes      = 512
	DefaultLookbackDays    = 365
	MaxLookbackDays        = 3650
)

var (
	ErrBusy         = errors.New("github leak monitor is already running")
	ErrUnconfigured = errors.New("github leak monitor is not configured")
	ErrUnavailable  = errors.New("github leak monitor worker is not running")
	ErrNotFound     = errors.New("github leak finding not found")
)

// Settings is intentionally independent of the application config package.
// Callers may map their persisted configuration onto this type.
type Settings struct {
	Enabled               bool     `json:"enabled"`
	Token                 string   `json:"-"`
	FingerprintKey        string   `json:"-"`
	Keywords              []string `json:"keywords"`
	Rules                 []Rule   `json:"rules,omitempty"`
	IntervalSeconds       int      `json:"interval_seconds"`
	RequestTimeoutSeconds int      `json:"request_timeout_seconds"`
	PollIntervalSeconds   int      `json:"poll_interval_seconds,omitempty"`
	MaxResultsPerKeyword  int      `json:"max_results_per_keyword,omitempty"`
	// RepoMaxAgeDays 仓库时效过滤：只入库最近 N 天有 push 的公开仓库。
	// 0=关闭；负值视为 0。默认建议 365，避免多年前的陈旧仓库反复进入监控列表。
	RepoMaxAgeDays int `json:"repo_max_age_days,omitempty"`
	// ExcludeForks 跳过 fork 仓库的命中（fork 内容多为上游复制，重复且陈旧）。默认 true。
	ExcludeForks *bool `json:"exclude_forks,omitempty"`
	// ExcludeNoisePaths 跳过测试/示例/文档路径（test*/examples/docs/vendor 等）。
	// 误报治理主开关。默认 true。
	ExcludeNoisePaths *bool `json:"exclude_noise_paths,omitempty"`
	// BoilerplateRepos 样板风暴识别阈值：同一 path+检测类型在单轮命中 ≥N 个不同
	// 仓库时，判定为框架/脚手架样板复制（非 fork 也拦不住的批量误报），suspected
	// 级候选整组丢弃（likely 强特征不受影响）。默认 5；0=关闭。
	BoilerplateRepos int `json:"boilerplate_repos,omitempty"`
	// BlobRescan 漏检补扫：text_matches 片段可能截断跨边界的密钥——对通过过滤
	// 但零命中的 item 回读 blob 全文重跑检测。默认开。
	BlobRescan *bool `json:"blob_rescan,omitempty"`
	// MaxBlobRescansPerRule 单规则单轮 blob 补扫上限（core 桶配额保护）。默认 10。
	MaxBlobRescansPerRule int `json:"max_blob_rescans_per_rule,omitempty"`
	// ExtraRulesPath 动态规则 JSON（gitleaks 社区规则导入产物，见
	// scripts/import_gitleaks_rules.py）。文件不存在时忽略；坏正则逐条跳过。
	ExtraRulesPath string `json:"extra_rules_path,omitempty"`
	// NotifyEnabled 新命中 IM 通知开关（notifier 统一漏斗 → 机器人广播）。默认开。
	NotifyEnabled *bool `json:"notify_enabled,omitempty"`
	// RetentionDays 处置完结 findings 的保留天数：false_positive/ignored/fixed
	// 超过 N 天自动清理。未配置(0)=默认 180；负数=关闭。
	RetentionDays int `json:"retention_days,omitempty"`
	// LookbackDays 路径时效回溯窗口（天）：检测命中后查该文件最近一次提交时间，
	// 早于窗口的陈旧代码不入库（GitHub Code Search 无日期限定，靠元数据请求兜底）。
	// 未配置(0)=默认 365；范围 1-3650。
	LookbackDays int `json:"lookback_days,omitempty"`
}

// ResolveLookbackDays 路径时效回溯窗口生效值（默认 365；越界回落默认值）。
func (s Settings) ResolveLookbackDays() int {
	if s.LookbackDays < 1 || s.LookbackDays > MaxLookbackDays {
		return DefaultLookbackDays
	}
	return s.LookbackDays
}

// ResolveRetentionDays 保留天数生效值（默认 180；负数=关闭）。
// ResolveNotifyEnabled 通知生效值（未配置默认开）。
func (s Settings) ResolveNotifyEnabled() bool {
	return s.NotifyEnabled == nil || *s.NotifyEnabled
}

func (s Settings) ResolveRetentionDays() int {
	if s.RetentionDays == 0 {
		return 180
	}
	return s.RetentionDays
}

// ResolveBlobRescan 补扫生效值（未配置默认开）。
func (s Settings) ResolveBlobRescan() bool {
	return s.BlobRescan == nil || *s.BlobRescan
}

// ResolveBoilerplateRepos 样板风暴阈值生效值（未配置默认 5；显式 0=关闭）。
func (s Settings) ResolveBoilerplateRepos() int {
	if s.BoilerplateRepos == 0 {
		return 5
	}
	if s.BoilerplateRepos < 0 {
		return 0
	}
	return s.BoilerplateRepos
}

// ResolveMaxBlobRescans 补扫上限生效值（默认 10，负值视为 0）。
func (s Settings) ResolveMaxBlobRescans() int {
	if s.MaxBlobRescansPerRule == 0 {
		return 10
	}
	if s.MaxBlobRescansPerRule < 0 {
		return 0
	}
	return s.MaxBlobRescansPerRule
}

// ResolveExcludeForks fork 过滤生效值（未配置默认 true）。
func (s Settings) ResolveExcludeForks() bool {
	return s.ExcludeForks == nil || *s.ExcludeForks
}

// ResolveExcludeNoisePaths 噪声路径过滤生效值（未配置默认 true）。
func (s Settings) ResolveExcludeNoisePaths() bool {
	return s.ExcludeNoisePaths == nil || *s.ExcludeNoisePaths
}

// Normalize validates settings and applies conservative defaults. The request
// interval is a hard safety boundary and can never be configured below 31s.
func (s Settings) Normalize() (Settings, error) {
	s.Token = strings.TrimSpace(s.Token)
	s.FingerprintKey = strings.TrimSpace(s.FingerprintKey)
	if s.IntervalSeconds == 0 {
		s.IntervalSeconds = DefaultIntervalSeconds
	}
	if s.IntervalSeconds < MinIntervalSeconds {
		return Settings{}, fmt.Errorf("interval_seconds must be at least %d", MinIntervalSeconds)
	}
	if s.RequestTimeoutSeconds == 0 {
		s.RequestTimeoutSeconds = DefaultTimeoutSeconds
	}
	if s.RequestTimeoutSeconds < 1 || s.RequestTimeoutSeconds > 300 {
		return Settings{}, errors.New("request_timeout_seconds must be between 1 and 300")
	}
	if s.PollIntervalSeconds == 0 {
		s.PollIntervalSeconds = DefaultPollSeconds
	}
	if s.PollIntervalSeconds < s.IntervalSeconds {
		s.PollIntervalSeconds = s.IntervalSeconds
	}
	if s.MaxResultsPerKeyword == 0 {
		s.MaxResultsPerKeyword = DefaultMaxResults
	}
	// A single request per AND rule keeps ETag semantics unambiguous and avoids
	// accidentally walking GitHub's capped search result window.
	if s.MaxResultsPerKeyword < 1 || s.MaxResultsPerKeyword > 100 {
		return Settings{}, errors.New("max_results_per_keyword must be between 1 and 100")
	}
	if s.LookbackDays == 0 {
		s.LookbackDays = DefaultLookbackDays
	}
	if s.LookbackDays < 1 || s.LookbackDays > MaxLookbackDays {
		return Settings{}, fmt.Errorf("lookback_days must be between 1 and %d", MaxLookbackDays)
	}
	// Named rules take precedence. Clearing the legacy field prevents an old
	// keywords value from becoming a hidden extra request after rules are added.
	if len(s.Rules) > 0 {
		s.Keywords = nil
	}
	normalized, err := canonicalKeywords(s.Keywords)
	if err != nil {
		return Settings{}, err
	}
	s.Keywords = normalized
	if err = validateAndNormalizeRules(&s); err != nil {
		return Settings{}, err
	}
	return s, nil
}

// Rule is one independently executed exact AND search. Rules are kept in
// configuration order so operators can control the deterministic request
// sequence. The legacy Settings.Keywords field is represented as "legacy".
type Rule struct {
	Enabled  bool     `json:"enabled" yaml:"enabled"`
	Name     string   `json:"name" yaml:"name"`
	Keywords []string `json:"keywords" yaml:"keywords"`
}

func validateAndNormalizeRules(settings *Settings) error {
	if settings == nil {
		return errors.New("github leak settings are required")
	}
	total := len(settings.Rules)
	if len(settings.Rules) == 0 && len(settings.Keywords) > 0 {
		total++
		if _, err := newKeywordRule(settings.Keywords); err != nil {
			return err
		}
	}
	if total > MaxRules {
		return fmt.Errorf("at most %d GitHub leak rules are allowed", MaxRules)
	}

	seenNames := make(map[string]struct{}, total)
	seenQueries := make(map[string]string, total)
	if len(settings.Rules) == 0 && len(settings.Keywords) > 0 {
		seenNames["legacy"] = struct{}{}
		legacy, _ := newKeywordRule(settings.Keywords)
		seenQueries[strings.ToLower(legacy.Query)] = "legacy"
	}
	for i := range settings.Rules {
		rule := settings.Rules[i]
		name, err := normalizeRuleName(rule.Name)
		if err != nil {
			return fmt.Errorf("rule %d: %w", i+1, err)
		}
		foldedName := strings.ToLower(name)
		if _, exists := seenNames[foldedName]; exists {
			return fmt.Errorf("duplicate GitHub leak rule name %q", name)
		}
		seenNames[foldedName] = struct{}{}
		compiled, err := newKeywordRule(rule.Keywords)
		if err != nil {
			return fmt.Errorf("rule %q: %w", name, err)
		}
		queryKey := strings.ToLower(compiled.Query)
		if previous, exists := seenQueries[queryKey]; exists {
			return fmt.Errorf("rules %q and %q have the same canonical query", previous, name)
		}
		seenQueries[queryKey] = name
		rule.Name = name
		rule.Keywords = compiled.Keywords
		settings.Rules[i] = rule
	}
	return nil
}

func normalizeRuleName(value string) (string, error) {
	value = strings.TrimSpace(value)
	if !utf8.ValidString(value) || len(value) < 1 || len(value) > maxRuleNameBytes {
		return "", errors.New("GitHub leak rule name must be 1-100 bytes of single-line UTF-8 text")
	}
	for _, r := range value {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			return "", errors.New("GitHub leak rule name must be 1-100 bytes of single-line UTF-8 text")
		}
	}
	return value, nil
}

func canonicalKeywords(values []string) ([]string, error) {
	if len(values) > MaxKeywords {
		return nil, fmt.Errorf("at most %d keywords are allowed", MaxKeywords)
	}
	byFoldedValue := make(map[string]string, len(values))
	for _, raw := range values {
		keyword, err := normalizeKeyword(raw)
		if err != nil {
			return nil, err
		}
		folded := strings.ToLower(keyword)
		current, ok := byFoldedValue[folded]
		if !ok || keyword == folded || (current != folded && keyword < current) {
			byFoldedValue[folded] = keyword
		}
	}
	normalized := make([]string, 0, len(byFoldedValue))
	for _, keyword := range byFoldedValue {
		normalized = append(normalized, keyword)
	}
	sort.Slice(normalized, func(i, j int) bool {
		left, right := strings.ToLower(normalized[i]), strings.ToLower(normalized[j])
		if left == right {
			return normalized[i] < normalized[j]
		}
		return left < right
	})
	return normalized, nil
}

func normalizeKeyword(value string) (string, error) {
	value = strings.TrimSpace(value)
	if !utf8.ValidString(value) || len(value) < 2 || len(value) > maxKeywordBytes {
		return "", errors.New("github leak keyword must be 2-200 bytes of single-line UTF-8 text")
	}
	for _, r := range value {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			return "", errors.New("github leak keyword must be 2-200 bytes of single-line UTF-8 text")
		}
	}
	return value, nil
}

type keywordRule struct {
	Name     string
	Enabled  bool
	Keywords []string
	Query    string
}

func newKeywordRule(values []string) (keywordRule, error) {
	keywords, err := canonicalKeywords(values)
	if err != nil {
		return keywordRule{}, err
	}
	if len(keywords) == 0 {
		return keywordRule{}, ErrUnconfigured
	}
	terms := make([]string, 0, len(keywords))
	literalBytes := 0
	for _, keyword := range keywords {
		escaped := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(keyword)
		literalBytes += len(escaped) + 2 // quoted phrase; operators/qualifier are excluded
		if literalBytes > maxQueryLiteralBytes {
			return keywordRule{}, fmt.Errorf("combined GitHub leak literals must not exceed %d bytes", maxQueryLiteralBytes)
		}
		terms = append(terms, `"`+escaped+`"`)
	}
	query := strings.Join(terms, " AND ") + " in:file"
	if len(query) > maxRuleQueryBytes {
		return keywordRule{}, errors.New("combined GitHub leak query is too long")
	}
	return keywordRule{Keywords: keywords, Query: query}, nil
}

func compiledRules(settings Settings, includeDisabled bool) ([]keywordRule, error) {
	rules := make([]keywordRule, 0, len(settings.Rules)+1)
	if len(settings.Rules) == 0 && len(settings.Keywords) > 0 {
		legacy, err := newKeywordRule(settings.Keywords)
		if err != nil {
			return nil, err
		}
		legacy.Name, legacy.Enabled = "legacy", true
		rules = append(rules, legacy)
	}
	for _, configured := range settings.Rules {
		if !includeDisabled && !configured.Enabled {
			continue
		}
		compiled, err := newKeywordRule(configured.Keywords)
		if err != nil {
			return nil, err
		}
		compiled.Name, compiled.Enabled = configured.Name, configured.Enabled
		rules = append(rules, compiled)
	}
	return rules, nil
}

func normalizeRuleQuery(value string) (string, error) {
	value = strings.TrimSpace(value)
	if !utf8.ValidString(value) || len(value) < 2 || len(value) > maxRuleQueryBytes || !strings.HasSuffix(value, " in:file") {
		return "", errors.New("invalid GitHub leak AND rule query")
	}
	for _, r := range value {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			return "", errors.New("invalid GitHub leak AND rule query")
		}
	}
	return value, nil
}

func (s Settings) Configured() bool {
	if strings.TrimSpace(s.Token) == "" {
		return false
	}
	if len(s.Rules) > 0 {
		for _, rule := range s.Rules {
			if rule.Enabled && len(rule.Keywords) > 0 {
				return true
			}
		}
		return false
	}
	return len(s.Keywords) > 0
}

func (s Settings) interval() time.Duration { return time.Duration(s.IntervalSeconds) * time.Second }
func (s Settings) timeout() time.Duration {
	return time.Duration(s.RequestTimeoutSeconds) * time.Second
}
func (s Settings) pollInterval() time.Duration {
	return time.Duration(s.PollIntervalSeconds) * time.Second
}

const (
	StatusNew           = "new"
	StatusTriaged       = "triaged"
	StatusFalsePositive = "false_positive"
	StatusResolved      = "resolved"
)

func ValidStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case StatusNew, StatusTriaged, StatusFalsePositive, StatusResolved:
		return true
	default:
		return false
	}
}

type Finding struct {
	ID            string `json:"id"`
	Status        string `json:"status"`
	RuleName      string `json:"rule_name"`
	Keyword       string `json:"keyword"`
	Repository    string `json:"repository"`
	Path          string `json:"path"`
	BlobSHA       string `json:"-"`
	Line          int    `json:"line"`
	SecretType    string `json:"secret_type"`
	Confidence    string `json:"confidence"`
	Severity      string `json:"severity"`
	Fingerprint   string `json:"fingerprint"`
	MaskedExcerpt string `json:"masked_excerpt"`
	HTMLURL       string `json:"html_url"`
	// SecretValue 命中的明文凭据（平台授权环境下直接展示研判；服务日志不打该字段）。
	SecretValue string `json:"secret_value,omitempty"`
	// VerifyStatus 验证结论（valid/invalid/restricted/unverifiable，检测→验证闭环落库）；
	// VerifyEvidence 为脱敏证据摘要（厂商错误码/账号归属），均由「验证」入口/Agent 回写。
	VerifyStatus   string `json:"verify_status,omitempty"`
	VerifyEvidence string `json:"verify_evidence,omitempty"`
	// SecretKey 赋值类命中源码里的实际字段名（如 ALIYUN_AK），与明文成对展示；
	// 强特征命中无 key，序列化时省略。
	SecretKey string `json:"secret_key,omitempty"`
	// SourceUpdatedAt 命中文件在默认分支上最近一次提交时间（路径时效校验产物）。
	SourceUpdatedAt *time.Time `json:"source_updated_at,omitempty"`
	FirstSeenAt     time.Time  `json:"first_seen_at"`
	LastSeenAt      time.Time  `json:"last_seen_at"`
}

// Candidate 由检测层产出，GitHub 原始响应不进入候选对象；明文经脏值过滤后
// 与指纹、脱敏摘要一起进入 Upsert（SourceUpdatedAt 由时效校验填充）。
type Candidate struct {
	RuleName        string
	Keyword         string
	Repository      string
	Path            string
	BlobSHA         string
	Line            int
	SecretType      string
	Confidence      string
	Severity        string
	Fingerprint     string
	MaskedExcerpt   string
	HTMLURL         string
	SecretValue     string `json:"-"`
	SecretKey       string
	SourceUpdatedAt time.Time
}

type ListFilter struct {
	Query    string
	Status   string
	Keyword  string
	Page     int
	PageSize int
	// RuleNames 项目过滤（4zreark 迁移）：规则名带项目名前缀，按本项目规则名集合圈定。
	RuleNames []string
	// SourceUpdatedAfter 非空时只返回路径提交时间在窗口内的命中（服务层按
	// lookback_days 注入；存量 NULL 行放行）。
	SourceUpdatedAfter *time.Time
}

func (f *ListFilter) Validate() error {
	f.Query = strings.TrimSpace(f.Query)
	f.Keyword = strings.TrimSpace(f.Keyword)
	f.Status = strings.ToLower(strings.TrimSpace(f.Status))
	if len(f.Query) > 200 || len(f.Keyword) > maxRuleQueryBytes {
		return errors.New("query or rule filter is too long")
	}
	if f.Status != "" && !ValidStatus(f.Status) {
		return errors.New("invalid finding status")
	}
	if f.Page == 0 {
		f.Page = 1
	}
	if f.PageSize == 0 {
		f.PageSize = 25
	}
	if f.Page < 1 || f.Page > 100000 || f.PageSize < 1 || f.PageSize > 100 {
		return errors.New("invalid pagination")
	}
	return nil
}

type ListResult struct {
	Items      []Finding `json:"items"`
	Total      int       `json:"total"`
	Page       int       `json:"page"`
	PageSize   int       `json:"page_size"`
	TotalPages int       `json:"total_pages"`
}

type Stats struct {
	Total         int `json:"total"`
	New           int `json:"new"`
	Triaged       int `json:"triaged"`
	FalsePositive int `json:"false_positive"`
	Resolved      int `json:"resolved"`
	Likely        int `json:"likely"`
	Suspected     int `json:"suspected"`
}

// SearchQuota search 桶实时配额快照（GET /rate_limit 采集，不计入配额）。
type SearchQuota struct {
	Remaining int
	Limit     int
	ResetAt   *time.Time
}

type RuntimeStatus struct {
	Enabled                bool         `json:"enabled"`
	Configured             bool         `json:"configured"`
	Running                bool         `json:"running"`
	LastRunAt              *time.Time   `json:"last_run_at,omitempty"`
	NextRunAt              *time.Time   `json:"next_run_at,omitempty"`
	LastStatus             string       `json:"last_status"`
	LastError              string       `json:"last_error"`
	LastWarning            string       `json:"last_warning"`
	RateRemaining          int          `json:"rate_remaining"`
	RateResetAt            *time.Time   `json:"rate_reset_at,omitempty"`
	IntervalSeconds        int          `json:"interval_seconds"`
	RequestIntervalSeconds int          `json:"request_interval_seconds"`
	RequestTimeoutSeconds  int          `json:"request_timeout_seconds"`
	Keywords               []string     `json:"keywords"`
	Query                  string       `json:"query"`
	RepoMaxAgeDays         int          `json:"repo_max_age_days"`
	LookbackDays           int          `json:"lookback_days"`
	Rules                  []RuleStatus `json:"rules"`
	LastRequests           int          `json:"last_requests"`
	LastProcessed          int          `json:"last_processed"`
	LastDetected           int          `json:"last_detected"`
	NotifyEnabled          bool         `json:"notify_enabled"`
	// 实时 search 配额（/rate_limit 探测，进程内 1 分钟缓存）。未配置/探测失败/
	// 运行中时 Remaining=-1，此时以最近一轮 run 的响应头值（RateRemaining）为准。
	SearchQuotaRemaining int        `json:"search_quota_remaining"`
	SearchQuotaLimit     int        `json:"search_quota_limit,omitempty"`
	SearchQuotaResetAt   *time.Time `json:"search_quota_reset_at,omitempty"`
	SearchQuotaCheckedAt *time.Time `json:"search_quota_checked_at,omitempty"`
}

type RuleStatus struct {
	Enabled       bool       `json:"enabled"`
	Name          string     `json:"name"`
	Keywords      []string   `json:"keywords"`
	Query         string     `json:"query"`
	LastAttemptAt *time.Time `json:"last_attempt_at,omitempty"`
	LastSuccessAt *time.Time `json:"last_success_at,omitempty"`
	LastStatus    string     `json:"last_status"`
	LastError     string     `json:"last_error"`
	Incomplete    bool       `json:"incomplete"`
	Truncated     bool       `json:"truncated"`
	// PageCursor 跨轮翻页游标当前位置（单轮每规则一页，多轮滚动覆盖可达前 10 页）；
	// 结合 Truncated 判断规则是否仍在向搜索结果深处推进。
	PageCursor int `json:"page_cursor"`
}

type KeywordState struct {
	Keyword       string
	ETag          string
	LastAttemptAt *time.Time
	LastSuccessAt *time.Time
	LastStatus    string
	LastError     string
	Incomplete    bool
	Truncated     bool
	// 路径时效校验状态（回溯窗口/策略变化时整体失效重来）：
	FreshnessPolicy     string
	FreshnessCheckedAt  *time.Time
	FreshnessCursor     int
	FreshnessCursorETag string
	// 跨轮翻页游标（1 起始）：单轮每规则只取一页，多轮滚动覆盖 GitHub 搜索
	// 可达的前 maxSearchPagesPerRule 页，避免永远钉死在相关度排序头部。
	PageCursor int
}

type RunRecord struct {
	ID            string
	Status        string
	Error         string
	StartedAt     time.Time
	FinishedAt    *time.Time
	RateRemaining int
	RateResetAt   *time.Time
	Requests      int
	Processed     int
	Detected      int
	// 误报治理过滤分类计数（运营可见性：每类每天拦了多少）
	FilteredFork        int
	FilteredNoise       int
	FilteredSuppressed  int
	FilteredBoilerplate int
}
