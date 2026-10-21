-- 企业信息深度采集（4zreco internal/enterprise/collector.go 的落库适配）
-- 新表 + enterprise_entities 增量列；不改既有列。
BEGIN;

CREATE TABLE IF NOT EXISTS enterprise_jobs (
    id          char(24)    PRIMARY KEY,
    project_id  bigint      NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    owner       text        NOT NULL DEFAULT '',
    provider    text        NOT NULL,
    keyword     text        NOT NULL DEFAULT '',
    status      text        NOT NULL DEFAULT 'running'
                CHECK (status IN ('running', 'done', 'error', 'canceled')),
    depth       int         NOT NULL DEFAULT 1,
    max_nodes   int         NOT NULL DEFAULT 20,
    nodes       int         NOT NULL DEFAULT 0,
    entities    int         NOT NULL DEFAULT 0,
    domains     int         NOT NULL DEFAULT 0,
    imported    int         NOT NULL DEFAULT 0,
    error       text        NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz
);

CREATE INDEX IF NOT EXISTS enterprise_jobs_project_idx
    ON enterprise_jobs (project_id, created_at DESC);

CREATE TABLE IF NOT EXISTS enterprise_candidates (
    id          bigserial   PRIMARY KEY,
    job_id      char(24)    REFERENCES enterprise_jobs(id) ON DELETE CASCADE,
    project_id  bigint      NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    domain      text        NOT NULL,
    site        text        NOT NULL DEFAULT '',
    icp         text        NOT NULL DEFAULT '',
    entity_name text        NOT NULL DEFAULT '',
    status      text        NOT NULL DEFAULT 'candidate'
                CHECK (status IN ('candidate', 'imported', 'rejected')),
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (project_id, domain)
);

CREATE INDEX IF NOT EXISTS enterprise_candidates_project_idx
    ON enterprise_candidates (project_id, status, created_at DESC);

-- 采集器需要把实体树挂到任务上；手工维护的行这些列为空/默认值。
ALTER TABLE enterprise_entities ADD COLUMN IF NOT EXISTS job_id char(24);
ALTER TABLE enterprise_entities ADD COLUMN IF NOT EXISTS ext_id text NOT NULL DEFAULT '';
ALTER TABLE enterprise_entities ADD COLUMN IF NOT EXISTS entity_type text NOT NULL DEFAULT 'root';
ALTER TABLE enterprise_entities ADD COLUMN IF NOT EXISTS parent_ext_id text NOT NULL DEFAULT '';
ALTER TABLE enterprise_entities ADD COLUMN IF NOT EXISTS depth int NOT NULL DEFAULT 0;
ALTER TABLE enterprise_entities ADD COLUMN IF NOT EXISTS phone text NOT NULL DEFAULT '';
ALTER TABLE enterprise_entities ADD COLUMN IF NOT EXISTS email text NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS enterprise_entities_job_idx
    ON enterprise_entities (job_id) WHERE job_id IS NOT NULL;

INSERT INTO schema_migrations (name) VALUES ('migration_enterprise_collector')
ON CONFLICT (name) DO NOTHING;

COMMIT;
