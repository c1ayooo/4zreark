-- nuclei 自动验证任务台账（来源：4zreco internal/vulnverify/store_sql.go）
BEGIN;

CREATE TABLE IF NOT EXISTS vulnverify_jobs (
    id             text        PRIMARY KEY,
    project_id     text        NOT NULL DEFAULT '',
    target         text        NOT NULL,
    product        text        NOT NULL,
    status         text        NOT NULL DEFAULT 'queued',
    result_vuln_id text        NOT NULL DEFAULT '',
    error          text        NOT NULL DEFAULT '',
    template_ids   jsonb       NOT NULL DEFAULT '[]'::jsonb,
    created_at     timestamptz NOT NULL DEFAULT now(),
    finished_at    timestamptz
);

-- 同 (target, product) 在途只允许一条；完结后的重跑由应用层的 recheck 窗口控制。
CREATE UNIQUE INDEX IF NOT EXISTS vulnverify_jobs_inflight_uq
    ON vulnverify_jobs (target, product)
    WHERE status IN ('queued', 'running');

CREATE INDEX IF NOT EXISTS vulnverify_jobs_finished_idx
    ON vulnverify_jobs (finished_at DESC) WHERE finished_at IS NOT NULL;

INSERT INTO schema_migrations (name) VALUES ('migration_vulnverify_jobs')
ON CONFLICT (name) DO NOTHING;

COMMIT;
