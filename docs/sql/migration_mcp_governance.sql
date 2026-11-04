-- MCP 治理三件套 DDL：工具级全局开关 + 分钟级速率配额计数
-- 执行顺序：schema_init.sql → schema_api_key.sql 之后；重复执行幂等。
--
-- 设计：
--   * mcp_tool_switches 无记录 = 启用；显式 false 才停用（升级无感）。
--     它是管理员总闸，与 key 的 scopes 正交：总闸关掉的工具对所有 key 不可见、不可调。
--   * mcp_rate_limits 按 key ID + 分钟桶原子自增计数；
--     bucket = extract(epoch from now())::bigint / 60，旧行由清理逻辑顺带删除。
--   * 两张表都不存明文 key。

BEGIN;

CREATE TABLE IF NOT EXISTS mcp_tool_switches (
    tool       text        PRIMARY KEY,
    enabled    boolean     NOT NULL DEFAULT true,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS mcp_rate_limits (
    key_id   bigint   NOT NULL,
    bucket   bigint   NOT NULL,
    count    bigint   NOT NULL DEFAULT 0,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (key_id, bucket)
);

INSERT INTO schema_migrations (name) VALUES ('migration_mcp_governance')
ON CONFLICT (name) DO NOTHING;

COMMIT;
