-- toolruntime：外部扫描工具（gogo/spray/katana/rem）的版本与更新台账。
-- 状态行由 internal/toolruntime 维护；tool_update_history 记录每次
-- 安装/回滚（ok=false 是被探针拦下的失败尝试），供审计与回滚决策。
BEGIN;

CREATE TABLE IF NOT EXISTS tool_runtime (
    name                 text        PRIMARY KEY,
    repo                 text        NOT NULL,
    pinned_version       text        NOT NULL DEFAULT '',
    installed_version    text        NOT NULL DEFAULT '',
    installed_sha256     text        NOT NULL DEFAULT '',
    prev_version         text        NOT NULL DEFAULT '',
    prev_sha256          text        NOT NULL DEFAULT '',
    latest_version       text        NOT NULL DEFAULT '',
    latest_checked_at    timestamptz,
    auto_update          boolean     NOT NULL DEFAULT true,
    check_interval_hours int         NOT NULL DEFAULT 24,
    status               text        NOT NULL DEFAULT 'missing'
                         CHECK (status IN ('ok', 'stale', 'missing', 'needs_review')),
    status_note          text        NOT NULL DEFAULT '',
    updated_at           timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS tool_update_history (
    id           bigserial  PRIMARY KEY,
    tool         text       NOT NULL,
    from_version text       NOT NULL DEFAULT '',
    to_version   text       NOT NULL DEFAULT '',
    sha256       text       NOT NULL DEFAULT '',
    ok           boolean    NOT NULL DEFAULT true,
    note         text       NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS tool_update_history_tool_idx
    ON tool_update_history (tool, created_at DESC);

INSERT INTO schema_migrations (name) VALUES ('migration_tool_runtime')
ON CONFLICT (name) DO NOTHING;

COMMIT;
