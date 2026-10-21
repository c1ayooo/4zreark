-- 企业身份线索：企业名 / 备案域名 / 与 APP 名单归属对齐。
-- 新表，不改既有表；项目删除时级联清理。
BEGIN;

CREATE TABLE IF NOT EXISTS enterprise_entities (
    id          bigserial   PRIMARY KEY,
    project_id  bigint      NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name        text        NOT NULL,
    credit_code text        NOT NULL DEFAULT '',
    legal_person text       NOT NULL DEFAULT '',
    open_status text        NOT NULL DEFAULT '',
    industry    text        NOT NULL DEFAULT '',
    address     text        NOT NULL DEFAULT '',
    icp_numbers jsonb       NOT NULL DEFAULT '[]'::jsonb,
    domains     jsonb       NOT NULL DEFAULT '[]'::jsonb,
    source      text        NOT NULL DEFAULT 'manual',
    status      text        NOT NULL DEFAULT 'unverified'
                CHECK (status IN ('unverified', 'verified', 'ignored')),
    notes       text        NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (project_id, name)
);

CREATE INDEX IF NOT EXISTS enterprise_entities_project_idx
    ON enterprise_entities (project_id, updated_at DESC);

CREATE INDEX IF NOT EXISTS enterprise_entities_name_idx
    ON enterprise_entities (lower(name));

INSERT INTO schema_migrations (name) VALUES ('migration_enterprise_entities')
ON CONFLICT (name) DO NOTHING;

COMMIT;
