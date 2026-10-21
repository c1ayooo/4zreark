-- 4zreark 资产治理域增量 DDL（ScopesHub 复刻）· 延展层
-- 执行顺序：schema_init.sql → migration_assets_p0.sql → 本文件
-- 目标库：PostgreSQL 16+；库名 zreark；schema zre（本文件默认在当前 search_path 执行）
--
-- 分工（重要）：
--   migration_assets_p0.sql 已建 6 张 P0 表：projects / sites / raw_records / verifications /
--   asset_events / connectivity_policies，并已在真实库带数据运行。本文件**不重建、不改写**这 6 张表，
--   只做两件事：(1) 给它们补治理域需要的列（additive）；(2) 建 P1–P4 才用到的 16 张新表。
--   把 P0 的列名改掉会让已上线的 assets_repo.go 全部失效，所以一律「只加不改」。
--
-- 命名：脚本按内容命名，不使用数字前缀；表名不带序号；月分区名保留 YYYY_MM。
-- 主键：新增表 bigserial；跨域引用只允许 project_id bigint / site_id bigint / workspace_id char(24) / task_id char(24)。
-- 一致性：整段一个事务，任一语句失败全体回滚。

BEGIN;

CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- ---------------------------------------------------------------- P0 表的增量列（只加不改）

-- 项目挂到既有的 workspaces（租户边界），资产记录仍然只带 project_id
ALTER TABLE projects ADD COLUMN IF NOT EXISTS workspace_id char(24) NOT NULL DEFAULT '000000000000000000000000';
CREATE INDEX IF NOT EXISTS projects_ws_idx ON projects (workspace_id, collection_paused);

-- 站点侧补齐：核心资产标记、原始记录计数、人工删除保护期
ALTER TABLE sites ADD COLUMN IF NOT EXISTS core           boolean     NOT NULL DEFAULT false;
ALTER TABLE sites ADD COLUMN IF NOT EXISTS raw_count      integer     NOT NULL DEFAULT 0;
ALTER TABLE sites ADD COLUMN IF NOT EXISTS protected_until timestamptz;
CREATE INDEX IF NOT EXISTS sites_project_core_idx ON sites (project_id, core, last_seen DESC);

-- 原始记录侧补齐：治理批次的回溯链路 + 富化字段（P1/P2 才会写）
ALTER TABLE raw_records ADD COLUMN IF NOT EXISTS run_id       bigint;
ALTER TABLE raw_records ADD COLUMN IF NOT EXISTS source_id    bigint;
ALTER TABLE raw_records ADD COLUMN IF NOT EXISTS task_id      char(24);
ALTER TABLE raw_records ADD COLUMN IF NOT EXISTS tech         jsonb  NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE raw_records ADD COLUMN IF NOT EXISTS server       text   NOT NULL DEFAULT '';
ALTER TABLE raw_records ADD COLUMN IF NOT EXISTS icon_sha256  char(64);
ALTER TABLE raw_records ADD COLUMN IF NOT EXISTS last_seen_at timestamptz NOT NULL DEFAULT now();
CREATE INDEX IF NOT EXISTS raw_records_run_idx  ON raw_records (run_id)  WHERE run_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS raw_records_task_idx ON raw_records (task_id) WHERE task_id IS NOT NULL;

-- 事件要能回溯到证据行（关系已有 relation_evidence，事件也留一条）
ALTER TABLE asset_events ADD COLUMN IF NOT EXISTS record_id bigint;

-- ---------------------------------------------------------------- 种子与计划（P1）

CREATE TABLE IF NOT EXISTS seeds (
    id         bigserial   PRIMARY KEY,
    project_id bigint      NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    kind       text        NOT NULL,
    value      text        NOT NULL,
    capability jsonb       NOT NULL DEFAULT '{}'::jsonb,
    enabled    boolean     NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT seeds_kind_chk CHECK (kind IN ('domain','cidr','company','repo','app','dict')),
    UNIQUE (project_id, kind, value)
);

CREATE INDEX IF NOT EXISTS seeds_project_idx ON seeds (project_id, enabled);

CREATE TABLE IF NOT EXISTS monitoring_plans (
    id             bigserial   PRIMARY KEY,
    seed_id        bigint      NOT NULL REFERENCES seeds(id) ON DELETE CASCADE,
    interval_hours integer     NOT NULL DEFAULT 24,
    budget         jsonb       NOT NULL DEFAULT '{}'::jsonb,
    enabled        boolean     NOT NULL DEFAULT true,
    next_run_at    timestamptz,
    last_run_at    timestamptz,
    created_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT plans_interval_chk CHECK (interval_hours BETWEEN 1 AND 720)
);

-- 到期轮询只关心启用的计划，用部分索引
CREATE INDEX IF NOT EXISTS plans_due_idx ON monitoring_plans (next_run_at) WHERE enabled;

CREATE TABLE IF NOT EXISTS monitoring_presets (
    id             bigserial   PRIMARY KEY,
    name           text        NOT NULL UNIQUE,
    interval_hours integer     NOT NULL,
    budget         jsonb       NOT NULL DEFAULT '{}'::jsonb,
    is_default     boolean     NOT NULL DEFAULT false,
    created_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT presets_interval_chk CHECK (interval_hours BETWEEN 1 AND 720)
);

-- ---------------------------------------------------------------- 执行批次（P1）

CREATE TABLE IF NOT EXISTS runs (
    id          bigserial   PRIMARY KEY,
    plan_id     bigint      NOT NULL REFERENCES monitoring_plans(id) ON DELETE CASCADE,
    project_id  bigint      NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    -- 幂等键独立成列：塞进 stats jsonb 做表达式唯一索引，统计口径一改就失效
    cycle_start timestamptz NOT NULL,
    status      text        NOT NULL DEFAULT 'queued',
    budget      jsonb       NOT NULL DEFAULT '{}'::jsonb,
    started_at  timestamptz,
    ended_at    timestamptz,
    stats       jsonb       NOT NULL DEFAULT '{}'::jsonb,
    CONSTRAINT runs_status_chk CHECK (status IN ('queued','running','partial','done','failed')),
    UNIQUE (plan_id, cycle_start)
);

CREATE INDEX IF NOT EXISTS runs_project_idx ON runs (project_id, cycle_start DESC);
CREATE INDEX IF NOT EXISTS runs_open_idx    ON runs (status) WHERE status IN ('queued','running');

CREATE TABLE IF NOT EXISTS run_targets (
    id          bigserial   PRIMARY KEY,
    run_id      bigint      NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    host        text        NOT NULL,
    port        integer     NOT NULL DEFAULT 0,
    capability  jsonb       NOT NULL DEFAULT '{}'::jsonb,
    state       text        NOT NULL DEFAULT 'pending',
    lease_until timestamptz,
    attempts    integer     NOT NULL DEFAULT 0,
    CONSTRAINT targets_state_chk CHECK (state IN ('pending','running','done','failed','skipped')),
    -- 种子展开可能重叠，同一 run 内同一目标只入队一次
    UNIQUE (run_id, host, port)
);

-- 领取走 (state, lease_until) + FOR UPDATE SKIP LOCKED
CREATE INDEX IF NOT EXISTS targets_due_idx ON run_targets (state, lease_until);

-- ---------------------------------------------------------------- 站点入口（P1）

-- P0 的 sites 只存了一个展示用 protocol/value（https 优先）。
-- 站点按 host 归并（site_key = sha1(project|host)），同一个 host 的 http:80、https:443
-- 以及 http:8080 这类非标准入口都落在这一个站点下，端口视图只能靠本表还原。
-- 唯一键是 (site_id, scheme, port) 而不是 (site_id, scheme)：
-- 否则同 host 的 http:80 与 http:8080 会互相覆盖，端口视图还是缺。
CREATE TABLE IF NOT EXISTS site_endpoints (
    id           bigserial   PRIMARY KEY,
    site_id      bigint      NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    scheme       text        NOT NULL,
    host         text        NOT NULL,
    port         integer     NOT NULL,
    status_code  integer,
    verified_at  timestamptz,
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT endpoints_scheme_chk CHECK (scheme IN ('http','https','tcp')),
    UNIQUE (site_id, scheme, port)
);

CREATE INDEX IF NOT EXISTS site_endpoints_site_idx ON site_endpoints (site_id, port);

-- ---------------------------------------------------------------- 关系与证据（P4）

CREATE TABLE IF NOT EXISTS relations (
    id            bigserial   PRIMARY KEY,
    project_id    bigint      NOT NULL,
    type          text        NOT NULL,
    key           text        NOT NULL,
    left_site_id  bigint      NOT NULL,
    right_site_id bigint      NOT NULL,
    confidence    real        NOT NULL DEFAULT 0.5,
    created_at    timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT relations_type_chk  CHECK (type IN ('domain_parent','same_ip','same_cert','same_icon','same_fp','cname')),
    -- 无向边统一小 id 在左，避免 (a,b) 与 (b,a) 两条重复
    CONSTRAINT relations_order_chk CHECK (left_site_id < right_site_id),
    UNIQUE (project_id, type, key, left_site_id, right_site_id)
);

CREATE INDEX IF NOT EXISTS relations_left_idx  ON relations (project_id, left_site_id);
CREATE INDEX IF NOT EXISTS relations_right_idx ON relations (project_id, right_site_id);

CREATE TABLE IF NOT EXISTS relation_evidence (
    relation_id bigint NOT NULL REFERENCES relations(id) ON DELETE CASCADE,
    record_id   bigint NOT NULL,
    rule_id     bigint,
    note        text   NOT NULL DEFAULT '',
    PRIMARY KEY (relation_id, record_id)
);

-- ---------------------------------------------------------------- 指纹命中（P2）

CREATE TABLE IF NOT EXISTS fingerprint_hits (
    site_id     bigint      NOT NULL,
    rule_id     char(24)    NOT NULL,   -- fingerprint_rules.id（既有 30 张表之一）
    observed_at timestamptz NOT NULL DEFAULT now(),
    record_id   bigint,
    evidence    jsonb       NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (site_id, rule_id)
);

CREATE INDEX IF NOT EXISTS fhits_rule_idx   ON fingerprint_hits (rule_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS fhits_record_idx ON fingerprint_hits (record_id) WHERE record_id IS NOT NULL;

-- ---------------------------------------------------------------- 数据源与凭据（P3）

CREATE TABLE IF NOT EXISTS sources (
    id             bigserial   PRIMARY KEY,
    kind           text        NOT NULL,
    name           text        NOT NULL,
    endpoint       text        NOT NULL DEFAULT '',
    enabled        boolean     NOT NULL DEFAULT true,
    config         jsonb       NOT NULL DEFAULT '{}'::jsonb,
    credential_ref text,
    last_ok_at     timestamptz,
    last_error     text        NOT NULL DEFAULT '',
    cooldown_until timestamptz,
    created_at     timestamptz NOT NULL DEFAULT now(),
    UNIQUE (kind, name)
);

-- 凭据只存密文：AES-256-GCM，密钥来自 ZRE_SECRET_KEY；接口只回 has_secret
CREATE TABLE IF NOT EXISTS source_credentials (
    ref        text        PRIMARY KEY,
    ciphertext bytea       NOT NULL,
    nonce      bytea       NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------- 图标库（P2）

CREATE TABLE IF NOT EXISTS asset_icons (
    sha256        char(64)    PRIMARY KEY,
    mmh3          integer,
    content_type  text        NOT NULL DEFAULT 'image/png',
    size_bytes    integer     NOT NULL DEFAULT 0,
    object_path   text        NOT NULL DEFAULT '',
    thumb_path    text        NOT NULL DEFAULT '',
    first_seen_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS asset_icons_mmh3_idx ON asset_icons (mmh3);

-- ---------------------------------------------------------------- 字典条目（P3）

-- 既有 dictionaries 只有 file_path + line_count，没有条目表；
-- 分段预览与「被计划引用的词表不可删」都需要条目级物化，只物化被引用的段。
CREATE TABLE IF NOT EXISTS dict_entries (
    id         bigserial   NOT NULL,
    dict_id    char(24)    NOT NULL,   -- dictionaries.id
    segment    integer     NOT NULL DEFAULT 1,
    value      text        NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (dict_id, segment, value)
);

CREATE INDEX IF NOT EXISTS dict_entries_dict_idx ON dict_entries (dict_id, segment);

-- ---------------------------------------------------------------- 数字资产与导入批次（P3/P5）

CREATE TABLE IF NOT EXISTS digital_assets (
    id         bigserial   PRIMARY KEY,
    project_id bigint      NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    kind       text        NOT NULL,
    name       text        NOT NULL,
    company    text        NOT NULL DEFAULT '',
    platform   text        NOT NULL DEFAULT '',
    source     text        NOT NULL DEFAULT '',
    status     text        NOT NULL DEFAULT 'unverified',
    -- 导入撤销按批次回滚，必须能反查
    batch_id   bigint,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT digital_kind_chk CHECK (kind IN ('app','miniapp','official_account','newmedia')),
    UNIQUE (project_id, kind, name)
);

CREATE INDEX IF NOT EXISTS digital_batch_idx ON digital_assets (batch_id) WHERE batch_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS import_batches (
    id         bigserial   PRIMARY KEY,
    project_id bigint      NOT NULL,
    kind       text        NOT NULL,
    status     text        NOT NULL DEFAULT 'previewed',
    summary    jsonb       NOT NULL DEFAULT '{}'::jsonb,
    expires_at timestamptz,
    created_by char(24),
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT import_kind_chk   CHECK (kind IN ('dictionary','digital','local_doc','fingerprint')),
    CONSTRAINT import_status_chk CHECK (status IN ('previewed','committed','cancelled','undone','expired'))
);

CREATE INDEX IF NOT EXISTS import_batches_project_idx ON import_batches (project_id, created_at DESC);

CREATE TABLE IF NOT EXISTS registration_codes (
    code       text        PRIMARY KEY,
    role       text        NOT NULL DEFAULT 'viewer',
    max_uses   integer     NOT NULL DEFAULT 1,
    used_count integer     NOT NULL DEFAULT 0,
    expires_at timestamptz,
    created_by char(24),
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT codes_role_chk CHECK (role IN ('admin','operator','user','viewer')),
    CONSTRAINT codes_use_chk  CHECK (used_count <= max_uses)
);

-- ---------------------------------------------------------------- 既有表的最小改动

-- 治理域要区分「只读会员 / 运营 / 管理员」，users.role 取值域必须放开 operator。
-- 存量数据只有 admin/user/viewer，放开不影响既有行。
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_chk;
ALTER TABLE users ADD  CONSTRAINT users_role_chk CHECK (role IN ('admin','operator','user','viewer'));

-- ---------------------------------------------------------------- 迁移账本

INSERT INTO schema_migrations (name) VALUES ('schema_governance')
ON CONFLICT (name) DO NOTHING;

COMMIT;
