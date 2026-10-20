-- 4zreark PostgreSQL 初始化 DDL
-- 目标库：PostgreSQL 16+；库名 zreark；schema zre（本文件默认在当前 search_path 执行）
-- 来源：src/backend/models 的 6 个模型文件（User/Role/Permission/OperationLog/Workspace、
--       Task/TaskConfig/TaskResultStats/TaskTemplate/TaskLog、ScanResult 及 10 种结果结构、
--       Vulnerability/POC/VulnReport、ScannerNode/Plugin/FingerprintRule/Dictionary、
--       CruiseTask/CruiseLog）逐一映射；情报三表按 4zrec vuln_intel 结构移植。
-- 约定：ObjectID → char(24)；time.Time 零值 → NULL；bson.M / 结构体 → jsonb；[]string → text[]
-- 命名：脚本按内容命名（schema_init.sql、schema_<主题>.sql），不使用 0001/0002 这类数字前缀；
--       表名同样不带序号；唯一保留数字的是按月分区的分区名（必须能区分到月）。

BEGIN;

CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- ---------------------------------------------------------------- 身份

CREATE TABLE IF NOT EXISTS users (
    id             char(24)    PRIMARY KEY,
    username       text        NOT NULL UNIQUE,
    password       text        NOT NULL,
    email          text        NOT NULL DEFAULT '',
    phone          text        NOT NULL DEFAULT '',
    nickname       text        NOT NULL DEFAULT '',
    avatar         text        NOT NULL DEFAULT '',
    role           text        NOT NULL DEFAULT 'user',
    status         smallint    NOT NULL DEFAULT 1,
    -- 全端失效：改密 / 禁用 / 踢下线时 +1，旧 token 立即作废
    token_version  integer     NOT NULL DEFAULT 0,
    last_login     timestamptz,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT users_role_chk   CHECK (role IN ('admin','user','viewer')),
    CONSTRAINT users_status_chk CHECK (status IN (0,1))
);

CREATE UNIQUE INDEX IF NOT EXISTS users_email_uq ON users (email) WHERE email <> '';
CREATE INDEX IF NOT EXISTS users_username_trgm ON users USING gin (username gin_trgm_ops);

-- 单端登出：精确作废某一个 token，存 SHA-256 十六进制，不存令牌原文
CREATE TABLE IF NOT EXISTS token_blacklist (
    token_hash char(64)    PRIMARY KEY,
    user_id    char(24)    NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS token_blacklist_expires_idx ON token_blacklist (expires_at);
CREATE INDEX IF NOT EXISTS token_blacklist_user_idx    ON token_blacklist (user_id);

CREATE TABLE IF NOT EXISTS roles (
    id          char(24)    PRIMARY KEY,
    name        text        NOT NULL UNIQUE,
    description text        NOT NULL DEFAULT '',
    permissions text[]      NOT NULL DEFAULT '{}',
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS permissions (
    id          char(24)    PRIMARY KEY,
    name        text        NOT NULL,
    code        text        NOT NULL UNIQUE,
    description text        NOT NULL DEFAULT '',
    module      text        NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS workspaces (
    id          char(24)    PRIMARY KEY,
    name        text        NOT NULL,
    description text        NOT NULL DEFAULT '',
    owner_id    char(24),
    members     text[]      NOT NULL DEFAULT '{}',
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS operation_logs (
    id         bigserial   PRIMARY KEY,
    user_id    char(24),
    username   text        NOT NULL DEFAULT '',
    action     text        NOT NULL DEFAULT '',
    module     text        NOT NULL DEFAULT '',
    target     text        NOT NULL DEFAULT '',
    detail     text        NOT NULL DEFAULT '',
    ip         text        NOT NULL DEFAULT '',
    user_agent text        NOT NULL DEFAULT '',
    status     smallint    NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS operation_logs_created_idx ON operation_logs (created_at DESC);
CREATE INDEX IF NOT EXISTS operation_logs_user_idx    ON operation_logs (user_id, created_at DESC);

-- ---------------------------------------------------------------- 任务

CREATE TABLE IF NOT EXISTS tasks (
    id               char(24)    PRIMARY KEY,
    workspace_id     char(24)    NOT NULL DEFAULT '000000000000000000000000',
    name             text        NOT NULL,
    description      text        NOT NULL DEFAULT '',
    type             text        NOT NULL,
    status           text        NOT NULL DEFAULT 'pending',
    targets          text[]      NOT NULL DEFAULT '{}',
    target_type      text        NOT NULL DEFAULT '',
    config           jsonb       NOT NULL DEFAULT '{}'::jsonb,
    is_scheduled     boolean     NOT NULL DEFAULT false,
    cron_expr        text        NOT NULL DEFAULT '',
    progress         smallint    NOT NULL DEFAULT 0,
    progress_details jsonb       NOT NULL DEFAULT '{}'::jsonb,  -- 分模块进度，前端直接渲染
    node_id          text        NOT NULL DEFAULT '',
    started_at       timestamptz,
    completed_at     timestamptz,
    total_targets      integer  NOT NULL DEFAULT 0,
    scanned_targets    integer  NOT NULL DEFAULT 0,
    discovered_assets  integer  NOT NULL DEFAULT 0,
    discovered_vulns   integer  NOT NULL DEFAULT 0,
    discovered_ports   integer  NOT NULL DEFAULT 0,
    last_scanned_index integer  NOT NULL DEFAULT 0,
    completed_stages   text[]   NOT NULL DEFAULT '{}',
    retry_count      integer     NOT NULL DEFAULT 0,
    last_error       text        NOT NULL DEFAULT '',
    created_by       char(24),
    tags             text[]      NOT NULL DEFAULT '{}',
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    -- 取值来自 models.TaskType，前端 TaskCreatePage 用的也是这一套
    CONSTRAINT tasks_type_chk CHECK (type IN ('asset_discovery','port_scan','fingerprint','vuln_scan','subdomain','takeover','dir_scan','crawler','bruteforce','monitor','full','custom')),
    CONSTRAINT tasks_status_chk CHECK (status IN ('pending','running','paused','completed','failed','cancelled')),
    CONSTRAINT tasks_progress_chk CHECK (progress BETWEEN 0 AND 100)
);

CREATE INDEX IF NOT EXISTS tasks_list_idx    ON tasks (status, type, updated_at DESC);
CREATE INDEX IF NOT EXISTS tasks_ws_idx      ON tasks (workspace_id, created_at DESC);
CREATE INDEX IF NOT EXISTS tasks_created_idx ON tasks (created_at DESC);
CREATE INDEX IF NOT EXISTS tasks_tags_gin    ON tasks USING gin (tags);
CREATE INDEX IF NOT EXISTS tasks_name_trgm   ON tasks USING gin (name gin_trgm_ops);

CREATE TABLE IF NOT EXISTS task_templates (
    id           char(24)    PRIMARY KEY,
    workspace_id char(24)    NOT NULL DEFAULT '000000000000000000000000',
    name         text        NOT NULL,
    description  text        NOT NULL DEFAULT '',
    type         text        NOT NULL,
    config       jsonb       NOT NULL DEFAULT '{}'::jsonb,
    is_public    boolean     NOT NULL DEFAULT false,
    created_by   char(24),
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS task_templates_ws_idx ON task_templates (workspace_id, is_public);

CREATE TABLE IF NOT EXISTS task_logs (
    id         bigserial   PRIMARY KEY,
    task_id    char(24)    NOT NULL,
    level      text        NOT NULL DEFAULT 'info',
    message    text        NOT NULL DEFAULT '',
    detail     text        NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS task_logs_task_idx ON task_logs (task_id, created_at DESC);

-- 运行态：任务分片队列（替代 Redis LPOP，带租约与断点）
CREATE TABLE IF NOT EXISTS task_jobs (
    id               bigserial   PRIMARY KEY,
    task_id          char(24)    NOT NULL,
    kind             text        NOT NULL DEFAULT 'scan',
    stage            text        NOT NULL DEFAULT '',
    priority         smallint    NOT NULL DEFAULT 100,
    status           text        NOT NULL DEFAULT 'queued',
    payload          jsonb       NOT NULL DEFAULT '{}'::jsonb,
    checkpoint       jsonb       NOT NULL DEFAULT '{}'::jsonb,
    attempts         integer     NOT NULL DEFAULT 0,
    max_attempts     integer     NOT NULL DEFAULT 3,
    worker_id        text,
    lease_expires_at timestamptz,
    scheduled_at     timestamptz NOT NULL DEFAULT now(),
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT task_jobs_status_chk CHECK (status IN ('queued','running','done','failed','dead')),
    CONSTRAINT task_jobs_kind_chk   CHECK (kind IN ('scan','job'))
);

CREATE INDEX IF NOT EXISTS task_jobs_claim_idx ON task_jobs (priority DESC, id) WHERE status = 'queued';
CREATE INDEX IF NOT EXISTS task_jobs_lease_idx ON task_jobs (lease_expires_at) WHERE status = 'running';
CREATE INDEX IF NOT EXISTS task_jobs_task_idx  ON task_jobs (task_id);
CREATE INDEX IF NOT EXISTS task_jobs_kind_idx  ON task_jobs (kind, status, priority DESC, id);

-- ---------------------------------------------------------------- 扫描结果（按月分区）

CREATE TABLE IF NOT EXISTS scan_results (
    id           char(24)    NOT NULL,
    task_id      char(24)    NOT NULL,
    workspace_id char(24)    NOT NULL DEFAULT '000000000000000000000000',
    type         text        NOT NULL,
    data         jsonb       NOT NULL DEFAULT '{}'::jsonb,
    tags         text[]      NOT NULL DEFAULT '{}',
    project      text        NOT NULL DEFAULT '',
    source       text        NOT NULL DEFAULT '',
    dedup_key    text        NOT NULL DEFAULT '',
    host         text,
    url          text,
    ip           inet,
    port         integer,
    status_code  integer,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (id, created_at)
) PARTITION BY RANGE (created_at);

CREATE TABLE IF NOT EXISTS scan_results_2026_10 PARTITION OF scan_results
    FOR VALUES FROM ('2026-10-01 00:00:00+08') TO ('2026-11-01 00:00:00+08');
CREATE TABLE IF NOT EXISTS scan_results_2026_11 PARTITION OF scan_results
    FOR VALUES FROM ('2026-11-01 00:00:00+08') TO ('2026-12-01 00:00:00+08');
CREATE TABLE IF NOT EXISTS scan_results_2026_12 PARTITION OF scan_results
    FOR VALUES FROM ('2026-12-01 00:00:00+08') TO ('2027-01-01 00:00:00+08');
CREATE TABLE IF NOT EXISTS scan_results_2027_01 PARTITION OF scan_results
    FOR VALUES FROM ('2027-01-01 00:00:00+08') TO ('2027-02-01 00:00:00+08');

-- 分区表的唯一索引必须包含分区键（PG 硬限制），因此跨月去重不能靠本表唯一约束，
-- 落到不分区的小表 result_dedup：与结果行同事务 ON CONFLICT DO NOTHING，天然一致
CREATE INDEX IF NOT EXISTS scan_results_task_type_idx ON scan_results (task_id, type, created_at DESC);
CREATE INDEX IF NOT EXISTS scan_results_ws_type_idx   ON scan_results (workspace_id, type, created_at DESC);
CREATE INDEX IF NOT EXISTS scan_results_host_idx      ON scan_results (host);
CREATE INDEX IF NOT EXISTS scan_results_status_idx    ON scan_results (task_id, status_code);
CREATE INDEX IF NOT EXISTS scan_results_tags_gin      ON scan_results USING gin (tags);
CREATE INDEX IF NOT EXISTS scan_results_data_gin      ON scan_results USING gin (data jsonb_path_ops);
CREATE INDEX IF NOT EXISTS scan_results_url_trgm      ON scan_results USING gin (url gin_trgm_ops);
CREATE INDEX IF NOT EXISTS scan_results_dedup_idx     ON scan_results (task_id, type, dedup_key);

-- 跨月去重表：dedup_key 由 task_id + type + 业务键拼成；清理交给 reaper（保留 7 天）
CREATE TABLE IF NOT EXISTS result_dedup (
    dedup_key  text        PRIMARY KEY,
    task_id    char(24)    NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS result_dedup_created_idx ON result_dedup (created_at);
CREATE INDEX IF NOT EXISTS result_dedup_task_idx    ON result_dedup (task_id);

-- ---------------------------------------------------------------- 漏洞与模板

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id               char(24)    PRIMARY KEY,
    workspace_id     char(24)    NOT NULL DEFAULT '000000000000000000000000',
    asset_id         char(24),
    task_id          char(24),
    name             text        NOT NULL,
    description      text        NOT NULL DEFAULT '',
    severity         text        NOT NULL DEFAULT 'info',
    status           text        NOT NULL DEFAULT 'new',
    type             text        NOT NULL DEFAULT '',
    template_id      text        NOT NULL DEFAULT '',
    target           text        NOT NULL DEFAULT '',
    method           text        NOT NULL DEFAULT '',
    payload          text        NOT NULL DEFAULT '',
    evidence         text        NOT NULL DEFAULT '',
    request          text        NOT NULL DEFAULT '',
    response         text        NOT NULL DEFAULT '',
    cve_id           text[]      NOT NULL DEFAULT '{}',
    cnnvd_id         text[]      NOT NULL DEFAULT '{}',
    refs             text[]      NOT NULL DEFAULT '{}',
    poc_id           char(24),
    poc_name         text        NOT NULL DEFAULT '',
    solution         text        NOT NULL DEFAULT '',
    fixed_at         timestamptz,
    fixed_by         text        NOT NULL DEFAULT '',
    last_verified_at timestamptz,
    scanner          text        NOT NULL DEFAULT '',
    tags             text[]      NOT NULL DEFAULT '{}',
    intel_id         bigint,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT vuln_severity_chk CHECK (severity IN ('critical','high','medium','low','info')),
    CONSTRAINT vuln_status_chk   CHECK (status IN ('new','confirmed','fixed','ignored','false_positive'))
);

CREATE UNIQUE INDEX IF NOT EXISTS vuln_dedup_uq    ON vulnerabilities (workspace_id, template_id, target) WHERE template_id <> '';
CREATE INDEX IF NOT EXISTS vuln_manual_dedup_idx  ON vulnerabilities (workspace_id, target) WHERE template_id = '';
CREATE INDEX IF NOT EXISTS vuln_sev_status_idx    ON vulnerabilities (workspace_id, severity, status);
CREATE INDEX IF NOT EXISTS vuln_task_idx          ON vulnerabilities (task_id);
CREATE INDEX IF NOT EXISTS vuln_created_idx       ON vulnerabilities (created_at DESC);
CREATE INDEX IF NOT EXISTS vuln_target_trgm       ON vulnerabilities USING gin (target gin_trgm_ops);
CREATE INDEX IF NOT EXISTS vuln_tags_gin          ON vulnerabilities USING gin (tags);

CREATE TABLE IF NOT EXISTS pocs (
    id          char(24)    PRIMARY KEY,
    template_id text        NOT NULL DEFAULT '',
    name        text        NOT NULL DEFAULT '',
    description text        NOT NULL DEFAULT '',
    author      text        NOT NULL DEFAULT '',
    severity    text        NOT NULL DEFAULT 'info',
    type        text        NOT NULL DEFAULT '',
    tags        text[]      NOT NULL DEFAULT '{}',
    content     text        NOT NULL DEFAULT '',
    cve_id      text[]      NOT NULL DEFAULT '{}',
    refs        text[]      NOT NULL DEFAULT '{}',
    enabled     boolean     NOT NULL DEFAULT true,
    version     text        NOT NULL DEFAULT '',
    source      text        NOT NULL DEFAULT '',
    origin      text        NOT NULL DEFAULT 'manual',
    intel_id    bigint,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pocs_origin_chk CHECK (origin IN ('manual','intel','import'))
);

-- 手工创建的 POC 没有 Nuclei 模板 ID，空串不能参与唯一约束，
-- 所以唯一性只覆盖非空的 template_id（与 vulnerabilities 的去重口径一致）。
CREATE UNIQUE INDEX IF NOT EXISTS pocs_template_uq ON pocs (template_id) WHERE template_id <> '';
CREATE INDEX IF NOT EXISTS pocs_sev_idx     ON pocs (severity, enabled);
CREATE INDEX IF NOT EXISTS pocs_tags_gin    ON pocs USING gin (tags);
CREATE INDEX IF NOT EXISTS pocs_name_trgm   ON pocs USING gin (name gin_trgm_ops);

CREATE TABLE IF NOT EXISTS vuln_reports (
    id           char(24)    PRIMARY KEY,
    workspace_id char(24)    NOT NULL DEFAULT '000000000000000000000000',
    name         text        NOT NULL,
    type         text        NOT NULL DEFAULT '',
    summary      jsonb       NOT NULL DEFAULT '{}'::jsonb,
    file_path    text        NOT NULL DEFAULT '',
    created_by   char(24),
    created_at   timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------- 节点与扩展

CREATE TABLE IF NOT EXISTS scanner_nodes (
    id                 char(24)    PRIMARY KEY,
    node_id            text        NOT NULL UNIQUE,
    name               text        NOT NULL DEFAULT '',
    description        text        NOT NULL DEFAULT '',
    type               text        NOT NULL DEFAULT 'local',
    status             text        NOT NULL DEFAULT 'offline',
    ip                 text        NOT NULL DEFAULT '',
    port               integer     NOT NULL DEFAULT 0,
    version            text        NOT NULL DEFAULT '',
    capabilities       text[]      NOT NULL DEFAULT '{}',
    max_tasks          integer     NOT NULL DEFAULT 0,
    current_tasks      integer     NOT NULL DEFAULT 0,
    system_info        jsonb       NOT NULL DEFAULT '{}'::jsonb,
    last_heartbeat     timestamptz,
    heartbeat_interval integer     NOT NULL DEFAULT 30,
    tags               text[]      NOT NULL DEFAULT '{}',
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS nodes_status_idx ON scanner_nodes (status, last_heartbeat DESC);

CREATE TABLE IF NOT EXISTS plugins (
    id           char(24)    PRIMARY KEY,
    name         text        NOT NULL UNIQUE,
    description  text        NOT NULL DEFAULT '',
    author       text        NOT NULL DEFAULT '',
    version      text        NOT NULL DEFAULT '',
    type         text        NOT NULL DEFAULT '',
    language     text        NOT NULL DEFAULT '',
    entry_file   text        NOT NULL DEFAULT '',
    dependencies text[]      NOT NULL DEFAULT '{}',
    enabled      boolean     NOT NULL DEFAULT false,
    installed    boolean     NOT NULL DEFAULT false,
    source       text        NOT NULL DEFAULT '',
    downloads    integer     NOT NULL DEFAULT 0,
    rating       real        NOT NULL DEFAULT 0,
    tags         text[]      NOT NULL DEFAULT '{}',
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS fingerprint_rules (
    id         char(24)    PRIMARY KEY,
    name       text        NOT NULL,
    category   text        NOT NULL DEFAULT '',
    version    text        NOT NULL DEFAULT '',
    rules      jsonb       NOT NULL DEFAULT '[]'::jsonb,
    enabled    boolean     NOT NULL DEFAULT true,
    source     text        NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS fingerprint_name_uq ON fingerprint_rules (name);
CREATE INDEX IF NOT EXISTS fingerprint_cat_idx ON fingerprint_rules (category, enabled);

CREATE TABLE IF NOT EXISTS dictionaries (
    id          char(24)    PRIMARY KEY,
    name        text        NOT NULL,
    type        text        NOT NULL,
    description text        NOT NULL DEFAULT '',
    file_path   text        NOT NULL DEFAULT '',
    line_count  integer     NOT NULL DEFAULT 0,
    is_builtin  boolean     NOT NULL DEFAULT false,
    created_by  char(24),
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS dict_type_name_uq ON dictionaries (type, name);

-- ---------------------------------------------------------------- 巡航

CREATE TABLE IF NOT EXISTS cruise_tasks (
    id                 char(24)    PRIMARY KEY,
    workspace_id       char(24)    NOT NULL DEFAULT '000000000000000000000000',
    name               text        NOT NULL,
    description        text        NOT NULL DEFAULT '',
    status             text        NOT NULL DEFAULT 'enabled',
    cron_expr          text        NOT NULL DEFAULT '',
    timezone           text        NOT NULL DEFAULT 'Asia/Shanghai',
    targets            text[]      NOT NULL DEFAULT '{}',
    target_type        text        NOT NULL DEFAULT '',
    task_type          text        NOT NULL DEFAULT '',
    config             jsonb       NOT NULL DEFAULT '{}'::jsonb,
    notify_on_complete boolean     NOT NULL DEFAULT false,
    notify_on_vuln     boolean     NOT NULL DEFAULT false,
    notify_channels    text[]      NOT NULL DEFAULT '{}',
    last_run_at        timestamptz,
    next_run_at        timestamptz,
    run_count          integer     NOT NULL DEFAULT 0,
    success_count      integer     NOT NULL DEFAULT 0,
    fail_count         integer     NOT NULL DEFAULT 0,
    last_task_id       text        NOT NULL DEFAULT '',
    last_status        text        NOT NULL DEFAULT '',
    created_by         char(24),
    tags               text[]      NOT NULL DEFAULT '{}',
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS cruise_next_run_idx ON cruise_tasks (status, next_run_at);

CREATE TABLE IF NOT EXISTS cruise_logs (
    id           bigserial   PRIMARY KEY,
    cruise_id    char(24)    NOT NULL,
    task_id      char(24),
    status       text        NOT NULL DEFAULT '',
    start_time   timestamptz,
    end_time     timestamptz,
    duration     bigint      NOT NULL DEFAULT 0,
    result_count integer     NOT NULL DEFAULT 0,
    vuln_count   integer     NOT NULL DEFAULT 0,
    error        text        NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS cruise_logs_cruise_idx ON cruise_logs (cruise_id, created_at DESC);

-- ---------------------------------------------------------------- 情报（移植自 4zrec）

CREATE TABLE IF NOT EXISTS vuln_intel (
    id          bigserial   PRIMARY KEY,
    unique_key  text        NOT NULL UNIQUE,
    title       text        NOT NULL DEFAULT '',
    description text        NOT NULL DEFAULT '',
    severity    text        NOT NULL DEFAULT '',
    cve         text        NOT NULL DEFAULT '',
    disclosure  text        NOT NULL DEFAULT '',
    solutions   text        NOT NULL DEFAULT '',
    source      text        NOT NULL DEFAULT '',
    source_url  text        NOT NULL DEFAULT '',
    tags        jsonb       NOT NULL DEFAULT '[]'::jsonb,
    refs        jsonb       NOT NULL DEFAULT '[]'::jsonb,
    github_poc  jsonb       NOT NULL DEFAULT '[]'::jsonb,
    cvss_score  real,
    cvss_vector text        NOT NULL DEFAULT '',
    cwes        jsonb       NOT NULL DEFAULT '[]'::jsonb,
    affected    jsonb       NOT NULL DEFAULT '[]'::jsonb,
    lab_only    boolean     NOT NULL DEFAULT false,
    enriched_at timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS intel_severity_idx ON vuln_intel (severity);
CREATE INDEX IF NOT EXISTS intel_cve_idx      ON vuln_intel (cve) WHERE cve <> '';
CREATE INDEX IF NOT EXISTS intel_created_idx  ON vuln_intel (created_at DESC);
CREATE INDEX IF NOT EXISTS intel_tags_gin     ON vuln_intel USING gin (tags jsonb_path_ops);

CREATE TABLE IF NOT EXISTS vuln_intel_analysis (
    vuln_intel_id  bigint      PRIMARY KEY REFERENCES vuln_intel(id) ON DELETE CASCADE,
    principle      text        NOT NULL DEFAULT '',
    attack_scope   text        NOT NULL DEFAULT '',
    description_zh text        NOT NULL DEFAULT '',
    poc_code       text        NOT NULL DEFAULT '',
    poc_lang       text        NOT NULL DEFAULT '',
    poc_origin     text        NOT NULL DEFAULT 'none',
    poc_note       text        NOT NULL DEFAULT '',
    nuclei_tpl     text        NOT NULL DEFAULT '',
    nuclei_state   text        NOT NULL DEFAULT 'none',
    fingerprint    text        NOT NULL DEFAULT '',
    fingerprint_id text        NOT NULL DEFAULT '',
    model          text        NOT NULL DEFAULT '',
    updated_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT intel_nuclei_state_chk CHECK (nuclei_state IN ('none','draft','confirmed','discarded'))
);

CREATE TABLE IF NOT EXISTS vuln_intel_settings (
    key        text        PRIMARY KEY,
    value      text        NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO vuln_intel_settings (key, value) VALUES
    ('vulnintel.enabled', 'false'),
    ('vulnintel.interval_minutes', '60'),
    ('vulnintel.analyze_enabled', 'false'),
    ('vulnintel.auto_translate', 'true'),
    ('vulnintel.auto_nuclei', 'false'),
    ('vulnintel.auto_fingerprint', 'false'),
    ('vulnintel.notify_enabled', 'true')
ON CONFLICT (key) DO NOTHING;

-- ---------------------------------------------------------------- 模型用量与迁移版本

CREATE TABLE IF NOT EXISTS llm_usage (
    id                bigserial   PRIMARY KEY,
    model             text        NOT NULL DEFAULT '',
    purpose           text        NOT NULL DEFAULT '',
    intel_id          bigint,
    prompt_tokens     integer     NOT NULL DEFAULT 0,
    completion_tokens integer     NOT NULL DEFAULT 0,
    cost_usd          numeric(10,6) NOT NULL DEFAULT 0,
    created_at        timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS llm_usage_day_idx ON llm_usage (created_at DESC);

-- 迁移账本：用脚本名标识，不用数字序号；执行顺序由代码里的有序清单保证
CREATE TABLE IF NOT EXISTS schema_migrations (
    name       text        PRIMARY KEY,
    checksum   text        NOT NULL DEFAULT '',
    applied_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO schema_migrations (name) VALUES ('schema_init')
ON CONFLICT (name) DO NOTHING;

COMMIT;
