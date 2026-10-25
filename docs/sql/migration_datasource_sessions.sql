-- 数据源会话托管：企业数据源（aqc/tyc/kuaicha/fengniao/qcc/xiaolanben）的会话
-- 持久化（扫码/Cookie/账号密码），provider 与 internal/enterprise Registry 的 Name 一致。
BEGIN;

CREATE TABLE IF NOT EXISTS datasource_sessions (
    provider      text        PRIMARY KEY,
    cookie        text        NOT NULL DEFAULT '',
    username      text        NOT NULL DEFAULT '',
    password      text        NOT NULL DEFAULT '',
    status        text        NOT NULL DEFAULT 'unconfigured'
                  CHECK (status IN ('unconfigured', 'active', 'expired')),
    last_login_at timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);

INSERT INTO schema_migrations (name) VALUES ('migration_datasource_sessions')
ON CONFLICT (name) DO NOTHING;

COMMIT;
