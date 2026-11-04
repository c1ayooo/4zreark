package repo

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// MCP 治理面：工具级全局开关 + 分钟级速率配额计数。
// 配额按 key 哈希计数，库里不落明文；缺表/无连接时由调用方降级（见 service 层）。

// MCPSwitchState 是一个工具的总闸状态。
type MCPSwitchState struct {
	Tool      string
	Enabled   bool
	UpdatedAt time.Time
}

type MCPGovernanceRepo interface {
	// ToolEnabled 返回工具是否启用；无记录视为启用（err==nil, enabled==true）。
	ToolEnabled(ctx context.Context, tool string) (bool, error)
	// SetToolSwitch 写入（upsert）工具开关。
	SetToolSwitch(ctx context.Context, tool string, enabled bool) error
	// ListToolSwitches 返回所有显式记录的开关（无记录的工具不在结果里）。
	ListToolSwitches(ctx context.Context) ([]MCPSwitchState, error)
	// ConsumeQuota 对 keyID 的当前分钟桶原子 +1，返回自增后的计数。
	ConsumeQuota(ctx context.Context, keyID int64) (int64, error)
}

type mcpGovernanceRepo struct{ r *Repo }

func (r *Repo) MCPGovernance() MCPGovernanceRepo { return &mcpGovernanceRepo{r: r} }

func (r *mcpGovernanceRepo) ToolEnabled(ctx context.Context, tool string) (bool, error) {
	var enabled bool
	err := r.r.pool.QueryRow(ctx,
		`select enabled from mcp_tool_switches where tool = $1`, tool).Scan(&enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return enabled, nil
}

func (r *mcpGovernanceRepo) SetToolSwitch(ctx context.Context, tool string, enabled bool) error {
	_, err := r.r.pool.Exec(ctx, `
insert into mcp_tool_switches (tool, enabled, updated_at)
values ($1, $2, now())
on conflict (tool) do update set enabled = excluded.enabled, updated_at = now()`,
		tool, enabled)
	return err
}

func (r *mcpGovernanceRepo) ListToolSwitches(ctx context.Context) ([]MCPSwitchState, error) {
	rows, err := r.r.pool.Query(ctx,
		`select tool, enabled, updated_at from mcp_tool_switches order by tool`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]MCPSwitchState, 0, 16)
	for rows.Next() {
		var s MCPSwitchState
		if err := rows.Scan(&s.Tool, &s.Enabled, &s.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (r *mcpGovernanceRepo) ConsumeQuota(ctx context.Context, keyID int64) (int64, error) {
	// 分钟桶：epoch/60。顺带删掉两分钟前的旧行，表常驻只有当前桶级别大小的行数。
	bucket := time.Now().Unix() / 60
	if _, err := r.r.pool.Exec(ctx,
		`delete from mcp_rate_limits where bucket < $1`, bucket-1); err != nil {
		return 0, err
	}
	var count int64
	err := r.r.pool.QueryRow(ctx, `
insert into mcp_rate_limits (key_id, bucket, count, updated_at)
values ($1, $2, 1, now())
on conflict (key_id, bucket) do update set count = mcp_rate_limits.count + 1, updated_at = now()
returning count`,
		keyID, bucket).Scan(&count)
	return count, err
}
