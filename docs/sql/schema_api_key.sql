-- 4zreark API 访问凭证与 MCP 接入 DDL
-- 目标库：PostgreSQL 16+；库名 zreark；schema zre（本文件默认在当前 search_path 执行）
-- 执行顺序：schema_init.sql → migration_assets_p0.sql → schema_governance.sql → 本文件
--
-- 设计：
--   * 外部平台不拿 JWT，改用平台签发的 API key；库里只存 SHA-256 哈希，明文只在创建时返回一次。
--   * project_id 是权限边界：绑定项目后只能读该项目下的资产；NULL 表示全部项目（只读）。
--   * scopes 预留细粒度授权，当前 MCP 只认 assets:read。
--   * 账本仍写 schema_migrations，和其余增量脚本保持一致；重复执行幂等。

BEGIN;

CREATE TABLE IF NOT EXISTS api_keys (
    id            bigserial   PRIMARY KEY,
    name          text        NOT NULL,
    -- 展示用前缀（zr_ + 8 位），完整 key 不落库
    key_prefix    text        NOT NULL,
    key_hash      char(64)    NOT NULL UNIQUE,
    -- NULL = 所有项目；非 NULL 时只能读该项目
    project_id    bigint      REFERENCES projects(id) ON DELETE CASCADE,
    scopes        text[]      NOT NULL DEFAULT '{assets:read}',
    enabled       boolean     NOT NULL DEFAULT true,
    expires_at    timestamptz,
    last_used_at  timestamptz,
    request_count bigint      NOT NULL DEFAULT 0,
    created_by    char(24),
    created_at    timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT api_keys_name_len_chk CHECK (length(name) BETWEEN 1 AND 120)
);

CREATE INDEX IF NOT EXISTS api_keys_project_idx ON api_keys (project_id);
CREATE INDEX IF NOT EXISTS api_keys_enabled_idx ON api_keys (enabled) WHERE enabled;
CREATE INDEX IF NOT EXISTS api_keys_last_used_idx ON api_keys (last_used_at DESC NULLS LAST);

-- ---------------------------------------------------------------- 迁移账本

INSERT INTO schema_migrations (name) VALUES ('schema_api_key')
ON CONFLICT (name) DO NOTHING;

COMMIT;
