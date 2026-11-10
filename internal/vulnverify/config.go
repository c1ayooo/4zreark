package vulnverify

// Config 是自动验证链路的运行配置。只能调小资源上限，不能放大。
type Config struct {
	Configured  bool `json:"configured"`
	Enabled     bool `json:"enabled"`
	RecheckDays int  `json:"recheck_days"`
	Concurrency int  `json:"concurrency"`
	RateLimit   int  `json:"rate_limit"`
	// DenyTemplateIDs 是 nuclei 误报黑名单：召回出的模板先按 id 过滤再执行。
	DenyTemplateIDs []string `json:"deny_template_ids,omitempty"`
}

// Denied 查 template-id 是否在黑名单内。
func (c Config) Denied(templateID string) bool {
	if len(c.DenyTemplateIDs) == 0 || templateID == "" {
		return false
	}
	for _, id := range c.DenyTemplateIDs {
		if id == templateID {
			return true
		}
	}
	return false
}

// EnabledOrDefault 未显式配置时默认开启（与 4zreco 语义一致）。
func (c Config) EnabledOrDefault() bool {
	if !c.Configured {
		return true
	}
	return c.Enabled
}

func (c Config) RecheckDaysEffective() int {
	if c.RecheckDays <= 0 {
		return 7
	}
	return c.RecheckDays
}

func (c Config) ConcurrencyEffective() int {
	if c.Concurrency <= 0 {
		return 1
	}
	if c.Concurrency > 4 {
		return 4
	}
	return c.Concurrency
}

func (c Config) RateLimitEffective() int {
	if c.RateLimit <= 0 {
		return 10
	}
	if c.RateLimit > maxRateLimit {
		return maxRateLimit
	}
	return c.RateLimit
}
