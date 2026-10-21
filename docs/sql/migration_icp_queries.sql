-- 工信部 ICP 官方查询的异步任务与结果快照。
-- 查询走单 worker + 全局限速，API 只入队，不阻塞任何业务队列。
BEGIN;

CREATE TABLE IF NOT EXISTS icp_queries (
    id           char(24)    PRIMARY KEY,
    project_id   bigint      NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    query        text        NOT NULL,
    service_type int         NOT NULL DEFAULT 1,
    page_size    int         NOT NULL DEFAULT 40,
    status       text        NOT NULL DEFAULT 'queued'
                 CHECK (status IN ('queued', 'running', 'done', 'error', 'canceled')),
    total        int         NOT NULL DEFAULT 0,
    pages        int         NOT NULL DEFAULT 0,
    fetched      int         NOT NULL DEFAULT 0,
    error        text        NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL DEFAULT now(),
    started_at   timestamptz,
    finished_at  timestamptz
);

CREATE INDEX IF NOT EXISTS icp_queries_project_idx
    ON icp_queries (project_id, created_at DESC);

CREATE TABLE IF NOT EXISTS icp_filings (
    id                 bigserial   PRIMARY KEY,
    query_id           char(24)    NOT NULL REFERENCES icp_queries(id) ON DELETE CASCADE,
    project_id         bigint      NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    domain             text        NOT NULL DEFAULT '',
    main_licence       text        NOT NULL DEFAULT '',
    service_licence    text        NOT NULL DEFAULT '',
    unit_name          text        NOT NULL DEFAULT '',
    nature_name        text        NOT NULL DEFAULT '',
    content_type       text        NOT NULL DEFAULT '',
    leader_name        text        NOT NULL DEFAULT '',
    update_record_time text        NOT NULL DEFAULT '',
    created_at         timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS icp_filings_query_uq
    ON icp_filings (query_id, service_licence, domain);

CREATE INDEX IF NOT EXISTS icp_filings_project_idx
    ON icp_filings (project_id, created_at DESC);

INSERT INTO schema_migrations (name) VALUES ('migration_icp_queries')
ON CONFLICT (name) DO NOTHING;

COMMIT;
