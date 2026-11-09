package repo

import (
	"context"
	"time"
)

// LLM 调用记账。表 llm_usage 由 schema_init.sql 建好，这里只读写、不建表不改列：
//   model / purpose / intel_id / prompt_tokens / completion_tokens / cost_usd / created_at
// 新业务用 purpose 承载场景名（如 sentinel_judge），不额外加列。

// LLMUsage 是一次模型调用的计量记录。
type LLMUsage struct {
	Model            string    `json:"model"`
	Purpose          string    `json:"purpose"`
	IntelID          *int64    `json:"intel_id,omitempty"`
	PromptTokens     int       `json:"prompt_tokens"`
	CompletionTokens int       `json:"completion_tokens"`
	CostUSD          float64   `json:"cost_usd"`
	CreatedAt        time.Time `json:"created_at"`
}

// LLMUsageRepo 是 llm_usage 的唯一数据入口。
type LLMUsageRepo struct{ r *Repo }

// LLMUsage 返回 LLM 记账仓储。
func (r *Repo) LLMUsage() *LLMUsageRepo { return &LLMUsageRepo{r: r} }

// Insert 写一条调用记录。
func (u *LLMUsageRepo) Insert(ctx context.Context, usage *LLMUsage) error {
	_, err := u.r.Pool().Exec(ctx, `
		insert into llm_usage (model, purpose, intel_id, prompt_tokens, completion_tokens, cost_usd)
		values ($1,$2,$3,$4,$5,$6)`,
		usage.Model, usage.Purpose, usage.IntelID,
		usage.PromptTokens, usage.CompletionTokens, usage.CostUSD)
	return err
}

// LLMUsageSummary 是某个场景在时间窗内的用量汇总。
type LLMUsageSummary struct {
	Calls            int64   `json:"calls"`
	PromptTokens     int64   `json:"prompt_tokens"`
	CompletionTokens int64   `json:"completion_tokens"`
	CostUSD          float64 `json:"cost_usd"`
}

// Summary 汇总 since 之后某场景的调用量；purpose 为空表示全部场景。
func (u *LLMUsageRepo) Summary(ctx context.Context, purpose string, since time.Time) (*LLMUsageSummary, error) {
	var s LLMUsageSummary
	err := u.r.Pool().QueryRow(ctx, `
		select count(*), coalesce(sum(prompt_tokens),0), coalesce(sum(completion_tokens),0),
		       coalesce(sum(cost_usd),0)::float8
		  from llm_usage
		 where created_at >= $1 and ($2 = '' or purpose = $2)`, since, purpose).
		Scan(&s.Calls, &s.PromptTokens, &s.CompletionTokens, &s.CostUSD)
	if err != nil {
		return nil, err
	}
	return &s, nil
}
