-- 种子收集队列：多选/全选种子（域名/公司(ICP)/证书组织）排队串行做 live 收集。
-- discovery_runs：发现轮历史，供前端巡航状态展示（每项目每天一轮）。
BEGIN;

CREATE TABLE IF NOT EXISTS seed_collection_jobs (
    id          char(24)    PRIMARY KEY,
    project_id  bigint      NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    seed_id     bigint      NOT NULL,
    kind        text        NOT NULL,
    value       text        NOT NULL,
    status      text        NOT NULL DEFAULT 'queued'
                CHECK (status IN ('queued', 'running', 'done', 'error')),
    found       int         NOT NULL DEFAULT 0,
    error       text        NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    started_at  timestamptz,
    finished_at timestamptz
);

CREATE INDEX IF NOT EXISTS seed_collection_jobs_proj_idx
    ON seed_collection_jobs (project_id, created_at DESC);

CREATE TABLE IF NOT EXISTS discovery_runs (
    id           bigserial   PRIMARY KEY,
    project_id   bigint      NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    ran_at       timestamptz NOT NULL DEFAULT now(),
    from_ctlog   int         NOT NULL DEFAULT 0,
    from_engines int         NOT NULL DEFAULT 0,
    new_count    int         NOT NULL DEFAULT 0,
    error        text        NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS discovery_runs_proj_idx
    ON discovery_runs (project_id, ran_at DESC);

INSERT INTO schema_migrations (name) VALUES ('migration_seed_collection')
ON CONFLICT (name) DO NOTHING;

COMMIT;
