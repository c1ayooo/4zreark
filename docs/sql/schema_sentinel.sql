-- CommitSentinel 域（v0.3 §5）：仓库 → 提交 → 判定 → 发现 → 产物 全链路。
--
-- 约定：
--   * 本脚本不自带 BEGIN，由 docs/sql/apply_all.sh 以单事务执行；
--   * 全部 DDL 幂等（IF NOT EXISTS），可重复执行；
--   * 认证复用既有 users/JWT/RBAC，不建 app_user / session / job；
--   * token 用量写既有 llm_usage 表（schema_init.sql:530），本脚本不重建。

-- ---------------------------------------------------------------- 仓库

CREATE TABLE IF NOT EXISTS repo (
    id              char(24)    PRIMARY KEY,
    full_name       text        NOT NULL,                 -- owner/name（展示与唯一键）
    clone_url       text        NOT NULL,                 -- 仅接受 https://github.com/...
    default_branch  text        NOT NULL DEFAULT 'main',
    branch          text        NOT NULL DEFAULT '',      -- 空串表示跟随 default_branch
    interval_minutes integer    NOT NULL DEFAULT 60,      -- 采集间隔（分钟）
    enabled         boolean     NOT NULL DEFAULT true,
    last_checked_at timestamptz,
    last_commit_sha text        NOT NULL DEFAULT '',      -- 上次采到的最新 sha，用于 rev-list 增量
    last_error      text        NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS repo_full_name_uidx ON repo (full_name);
CREATE INDEX IF NOT EXISTS repo_due_idx ON repo (enabled, last_checked_at);

-- ---------------------------------------------------------------- 提交

CREATE TABLE IF NOT EXISTS commit (
    id            bigserial   PRIMARY KEY,
    repo_id       char(24)    NOT NULL REFERENCES repo(id) ON DELETE CASCADE,
    sha           text        NOT NULL,
    author_name   text        NOT NULL DEFAULT '',
    author_email  text        NOT NULL DEFAULT '',
    committed_at  timestamptz NOT NULL,
    subject       text        NOT NULL DEFAULT '',
    message       text        NOT NULL DEFAULT '',
    files_changed integer     NOT NULL DEFAULT 0,
    additions     integer     NOT NULL DEFAULT 0,
    deletions     integer     NOT NULL DEFAULT 0,
    diff          text        NOT NULL DEFAULT '',        -- 清洗后的 patch（列表查询不要 select）
    status        text        NOT NULL DEFAULT 'pending', -- pending/skipped/judged/failed
    skip_reason   text        NOT NULL DEFAULT '',
    created_at    timestamptz NOT NULL DEFAULT now()
);

-- 同一仓库同一 sha 只入一次，采集重跑天然幂等
CREATE UNIQUE INDEX IF NOT EXISTS commit_repo_sha_uidx ON commit (repo_id, sha);
-- 列表/游标分页：按提交时间倒序
CREATE INDEX IF NOT EXISTS commit_repo_time_idx ON commit (repo_id, committed_at DESC, id DESC);
-- 待判定队列：只索引未终态，避免全表扫
CREATE INDEX IF NOT EXISTS commit_pending_idx ON commit (status, committed_at DESC)
    WHERE status IN ('pending', 'failed');

-- ---------------------------------------------------------------- 判定

CREATE TABLE IF NOT EXISTS judgment (
    id                bigserial   PRIMARY KEY,
    commit_id         bigint      NOT NULL REFERENCES commit(id) ON DELETE CASCADE,
    model             text        NOT NULL,
    is_security_fix   boolean     NOT NULL DEFAULT false,
    vuln_class        text        NOT NULL DEFAULT 'OTHER',
    severity          text        NOT NULL DEFAULT 'info',
    confidence        numeric(4,3) NOT NULL DEFAULT 0,
    title             text        NOT NULL DEFAULT '',
    reasoning         text        NOT NULL DEFAULT '',
    evidence          jsonb       NOT NULL DEFAULT '[]'::jsonb,
    -- 命中安全修复时展开的三段式说明（审计质量增强，migration_sentinel_judge_detail.sql）
    attack_path       text        NOT NULL DEFAULT '',        -- 攻击路径：入口 → 传播 → 汇聚点
    impact            text        NOT NULL DEFAULT '',        -- 影响与可利用条件
    fix_evidence      text        NOT NULL DEFAULT '',        -- 修复消除了攻击链哪一环
    evidence_snippets jsonb       NOT NULL DEFAULT '[]'::jsonb, -- 模型摘录的 diff 关键代码行（防幻觉校验）
    partial           boolean     NOT NULL DEFAULT false,  -- 模型失败/校验降级时为 true
    prompt_tokens     integer     NOT NULL DEFAULT 0,
    completion_tokens integer     NOT NULL DEFAULT 0,
    created_at        timestamptz NOT NULL DEFAULT now()
);

-- 永不重判：(commit_id, model) 唯一，写库走 ON CONFLICT DO NOTHING
CREATE UNIQUE INDEX IF NOT EXISTS judgment_commit_model_uidx ON judgment (commit_id, model);
-- 命中列表：部分索引只覆盖安全修复
CREATE INDEX IF NOT EXISTS judgment_hit_idx ON judgment (created_at DESC, id DESC)
    WHERE is_security_fix;

-- ---------------------------------------------------------------- 发现 / 产物

CREATE TABLE IF NOT EXISTS finding (
    id          bigserial   PRIMARY KEY,
    commit_id   bigint      NOT NULL REFERENCES commit(id) ON DELETE CASCADE,
    judgment_id bigint      REFERENCES judgment(id) ON DELETE SET NULL,
    vuln_class  text        NOT NULL DEFAULT 'OTHER',
    severity    text        NOT NULL DEFAULT 'info',
    status      text        NOT NULL DEFAULT 'open',      -- open / confirmed / ignored / resolved
    title       text        NOT NULL DEFAULT '',
    detail      text        NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS finding_commit_idx ON finding (commit_id, id DESC);
CREATE INDEX IF NOT EXISTS finding_status_idx ON finding (status, id DESC);

CREATE TABLE IF NOT EXISTS artifact (
    id         bigserial   PRIMARY KEY,
    finding_id bigint      NOT NULL REFERENCES finding(id) ON DELETE CASCADE,
    kind       text        NOT NULL DEFAULT 'poc',        -- poc / nuclei / report / patch / repro_log
    title      text        NOT NULL DEFAULT '',
    status     text        NOT NULL DEFAULT 'draft',      -- draft/pending_review/verified/rejected/deprecated
    path       text        NOT NULL DEFAULT '',
    content    text        NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS artifact_finding_idx ON artifact (finding_id, id DESC);

-- ---------------------------------------------------------------- 对话（M6 起使用，先建表避免后续再迁移）

CREATE TABLE IF NOT EXISTS conversation (
    id         char(24)    PRIMARY KEY,
    commit_id  bigint      REFERENCES commit(id) ON DELETE CASCADE,
    user_id    char(24)    NOT NULL DEFAULT '',
    title      text        NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS conversation_user_idx ON conversation (user_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS message (
    id              bigserial   PRIMARY KEY,
    conversation_id char(24)    NOT NULL REFERENCES conversation(id) ON DELETE CASCADE,
    role            text        NOT NULL DEFAULT 'user',  -- user/assistant/system
    content         text        NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS message_conversation_idx ON message (conversation_id, id);

-- ---------------------------------------------------------------- 批次 / 事件流

CREATE TABLE IF NOT EXISTS run (
    id          bigserial   PRIMARY KEY,
    run_type    text        NOT NULL DEFAULT 'collect',   -- collect/judge/repro
    repo_id     char(24)    REFERENCES repo(id) ON DELETE SET NULL,
    status      text        NOT NULL DEFAULT 'pending',   -- pending/running/completed/failed/cancelled
    total       integer     NOT NULL DEFAULT 0,
    processed   integer     NOT NULL DEFAULT 0,
    failed      integer     NOT NULL DEFAULT 0,
    last_seq    bigint      NOT NULL DEFAULT 0,           -- 事件流游标（续传用）
    error       text        NOT NULL DEFAULT '',
    started_at  timestamptz,
    finished_at timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS run_type_time_idx ON run (run_type, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS run_repo_idx ON run (repo_id, created_at DESC);

CREATE TABLE IF NOT EXISTS run_event (
    id         bigserial   PRIMARY KEY,
    run_id     bigint      NOT NULL REFERENCES run(id) ON DELETE CASCADE,
    seq        bigint      NOT NULL,
    level      text        NOT NULL DEFAULT 'info',       -- info/warn/error
    kind       text        NOT NULL DEFAULT '',
    message    text        NOT NULL DEFAULT '',
    payload    jsonb       NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- 订阅端带 last_seq 续传：唯一键保证 seq 不被重复消费
CREATE UNIQUE INDEX IF NOT EXISTS run_event_run_seq_uidx ON run_event (run_id, seq);

-- ---------------------------------------------------------------- 附件（评测样本 / 截图）

CREATE TABLE IF NOT EXISTS attachment (
    id         bigserial   PRIMARY KEY,
    run_id     bigint      REFERENCES run(id) ON DELETE CASCADE,
    commit_id  bigint      REFERENCES commit(id) ON DELETE CASCADE,
    filename   text        NOT NULL DEFAULT '',
    mime       text        NOT NULL DEFAULT '',
    size_bytes bigint      NOT NULL DEFAULT 0,
    content    bytea,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS attachment_commit_idx ON attachment (commit_id, id DESC);

-- ---------------------------------------------------------------- 域内审计

CREATE TABLE IF NOT EXISTS audit (
    id         bigserial   PRIMARY KEY,
    actor      text        NOT NULL DEFAULT '',
    action     text        NOT NULL DEFAULT '',
    target     text        NOT NULL DEFAULT '',
    detail     jsonb       NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS audit_created_idx ON audit (created_at DESC, id DESC);

INSERT INTO schema_migrations (name) VALUES ('schema_sentinel')
ON CONFLICT (name) DO NOTHING;
