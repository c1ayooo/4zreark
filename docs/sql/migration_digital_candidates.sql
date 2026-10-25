-- 数字资产候选池：自动采集结果先入池，人工确认后经既有两段式导入落名单。
-- 对账语义：入池时已存在于 digital_assets 的条目直接标 imported（batch_id 空，
-- 不随批次撤销回退）；rejected 为用户终态，重复入池不复活。
BEGIN;

CREATE TABLE IF NOT EXISTS digital_candidates (
    id          bigserial   PRIMARY KEY,
    project_id  bigint      NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    kind        text        NOT NULL,
    name        text        NOT NULL,
    company     text        NOT NULL DEFAULT '',
    platform    text        NOT NULL DEFAULT '',
    source      text        NOT NULL DEFAULT '',
    entity_name text        NOT NULL DEFAULT '',
    evidence    text        NOT NULL DEFAULT '',
    status      text        NOT NULL DEFAULT 'candidate'
                CHECK (status IN ('candidate', 'imported', 'rejected')),
    batch_id    bigint,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT digital_candidates_kind_chk
        CHECK (kind IN ('app', 'miniapp', 'official_account', 'newmedia')),
    UNIQUE (project_id, kind, name)
);

CREATE INDEX IF NOT EXISTS digital_candidates_project_idx
    ON digital_candidates (project_id, status, created_at DESC);

CREATE INDEX IF NOT EXISTS digital_candidates_batch_idx
    ON digital_candidates (batch_id) WHERE batch_id IS NOT NULL;

-- 企业 BFS 深度采集顺带数字资产：任务统计列。
ALTER TABLE enterprise_jobs ADD COLUMN IF NOT EXISTS digital int NOT NULL DEFAULT 0;

INSERT INTO schema_migrations (name) VALUES ('migration_digital_candidates')
ON CONFLICT (name) DO NOTHING;

COMMIT;
