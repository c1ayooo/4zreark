-- 信息收集侧 AI 数据面：原文快照、Gate 判定 trace、结构化条目、diff 触发。
-- 与《信息收集侧AI接入方案》第 4/6 节对齐；AI 只写判定/抽取字段，不写结论。
CREATE TABLE IF NOT EXISTS raw_snapshots (
    id             bigserial   PRIMARY KEY,
    raw_id         text        NOT NULL,
    task_id        char(24),
    entity_id      text        NOT NULL DEFAULT '',
    source         text        NOT NULL DEFAULT '',
    body           text        NOT NULL DEFAULT '',
    content_hash   text        NOT NULL DEFAULT '',
    fetched_at     timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz,
    UNIQUE (raw_id, content_hash)
);

CREATE TABLE IF NOT EXISTS ai_gate_verdicts (
    id             bigserial   PRIMARY KEY,
    raw_id         text        NOT NULL,
    prompt_ver     text        NOT NULL DEFAULT '',
    model          text        NOT NULL DEFAULT '',
    input_snapshot text        NOT NULL DEFAULT '',
    verdict        jsonb       NOT NULL DEFAULT '{}'::jsonb,
    keep           boolean     NOT NULL DEFAULT false,
    score          double precision NOT NULL DEFAULT 0,
    latency_ms     integer     NOT NULL DEFAULT 0,
    created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ai_items (
    id             bigserial   PRIMARY KEY,
    entity_id      text        NOT NULL,
    raw_id         text        NOT NULL DEFAULT '',
    source         text        NOT NULL DEFAULT '',
    summary        text        NOT NULL DEFAULT '',
    impact         jsonb       NOT NULL DEFAULT '{}'::jsonb,
    state          text        NOT NULL DEFAULT 'new',
    diff_job_id    bigint,
    diff_result    jsonb,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ai_items_state_chk CHECK (state IN ('new','routed','analyzed','archived','analyzed_failed'))
);

CREATE TABLE IF NOT EXISTS diff_jobs (
    id               bigserial   PRIMARY KEY,
    entity_id        text        NOT NULL,
    from_ref         text        NOT NULL DEFAULT '',
    to_ref           text        NOT NULL DEFAULT '',
    status           text        NOT NULL DEFAULT 'pending',
    idempotency_key  text        NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (idempotency_key)
);

CREATE INDEX IF NOT EXISTS raw_snapshots_entity_idx ON raw_snapshots (entity_id, fetched_at DESC);
CREATE INDEX IF NOT EXISTS ai_gate_verdicts_raw_idx ON ai_gate_verdicts (raw_id, prompt_ver);
CREATE INDEX IF NOT EXISTS ai_items_state_idx       ON ai_items (state, updated_at DESC);
CREATE INDEX IF NOT EXISTS diff_jobs_status_idx     ON diff_jobs (status, updated_at DESC);
