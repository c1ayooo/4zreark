-- 信息收集计划与阶段账本。父计划只承载编排状态，不直接执行扫描；
-- 每个阶段是一条独立 tasks 行，通过 collection_stages.task_id 关联。
CREATE TABLE IF NOT EXISTS collection_plans (
    id             char(24)    PRIMARY KEY,
    project_id     bigint      NOT NULL,
    mode           text        NOT NULL DEFAULT 'auto',   -- auto | full | staged
    status         text        NOT NULL DEFAULT 'pending',-- pending | running | completed | failed | cancelled
    current_stage  text        NOT NULL DEFAULT '',
    seed           text        NOT NULL DEFAULT '',
    deadline       timestamptz,
    created_by     char(24),
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS collection_stages (
    id             bigserial   PRIMARY KEY,
    plan_id        char(24)    NOT NULL REFERENCES collection_plans(id) ON DELETE CASCADE,
    stage          text        NOT NULL,                  -- s1_domains | s2_probe | s3a_crawl | s3b_ports | s4_enrich | s5_assess
    task_id        char(24),
    status         text        NOT NULL DEFAULT 'pending',-- pending | running | completed | failed | skipped
    attempt        integer     NOT NULL DEFAULT 0,
    skip_reason    text        NOT NULL DEFAULT '',
    input_filter   jsonb       NOT NULL DEFAULT '{}'::jsonb,
    started_at     timestamptz,
    finished_at    timestamptz,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT collection_stages_status_chk CHECK (status IN ('pending','running','completed','failed','skipped')),
    CONSTRAINT collection_stages_unique UNIQUE (plan_id, stage)
);

CREATE INDEX IF NOT EXISTS collection_plans_status_idx ON collection_plans (status, updated_at DESC);
CREATE INDEX IF NOT EXISTS collection_stages_plan_idx  ON collection_stages (plan_id, stage);
CREATE INDEX IF NOT EXISTS collection_stages_task_idx  ON collection_stages (task_id);
