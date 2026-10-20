-- ScopesHub 复刻 P0：资产治理三层（项目 / 站点 / 原始记录）+ 验证与事件
-- 口径对齐 ScopesHub 实测字段，见 docs/方案-ScopesHub功能复刻技术设计-20261020.md §2.3 §14
-- 执行顺序：schema_init.sql → 本文件 → schema_governance.sql

BEGIN;

CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE TABLE IF NOT EXISTS projects (
    id                     BIGSERIAL PRIMARY KEY,
    code                   TEXT NOT NULL UNIQUE,
    name                   TEXT NOT NULL,
    region                 TEXT NOT NULL DEFAULT 'domestic',
    description            TEXT,
    homepage_url           TEXT,
    color                  TEXT,
    icon_sha256            TEXT,
    collection_paused      BOOLEAN NOT NULL DEFAULT false,
    collection_pause_reason TEXT,
    cycle_interval_days    INT NOT NULL DEFAULT 30,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sites (
    id                     BIGSERIAL PRIMARY KEY,
    project_id             BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    site_key               TEXT NOT NULL UNIQUE,
    host                   TEXT NOT NULL,
    port                   INT NOT NULL DEFAULT 443,
    protocol               TEXT NOT NULL DEFAULT 'https',
    value                  TEXT NOT NULL,
    ip                     INET,
    http_status            INT NOT NULL DEFAULT 0,
    title                  TEXT,
    icon_sha256            TEXT,
    icon_path              TEXT,
    tech                   JSONB NOT NULL DEFAULT '[]'::jsonb,
    tech_status            TEXT NOT NULL DEFAULT 'pending',
    discovery_type         TEXT NOT NULL DEFAULT 'new',
    state                  TEXT NOT NULL DEFAULT 'pending',
    consecutive_failures   INT NOT NULL DEFAULT 0,
    retry_step             INT NOT NULL DEFAULT 0,
    lost_since_ms          BIGINT NOT NULL DEFAULT 0,
    next_check_ms          BIGINT NOT NULL DEFAULT 0,
    last_check_ms          BIGINT NOT NULL DEFAULT 0,
    cleanup_eligible       BOOLEAN NOT NULL DEFAULT false,
    verification_status    TEXT NOT NULL DEFAULT 'pending',
    verification_reason    TEXT,
    attempts               INT NOT NULL DEFAULT 0,
    max_attempts           INT NOT NULL DEFAULT 3,
    first_seen             TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen              TIMESTAMPTZ NOT NULL DEFAULT now(),
    verified_at            TIMESTAMPTZ,
    next_verification_at   TIMESTAMPTZ,
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_sites_project_state ON sites (project_id, state);
CREATE INDEX IF NOT EXISTS idx_sites_first_seen ON sites (first_seen DESC);
CREATE INDEX IF NOT EXISTS idx_sites_next_verification ON sites (next_verification_at) WHERE next_verification_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_sites_host_trgm ON sites USING gin (host gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_sites_title_trgm ON sites USING gin (title gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_sites_tech ON sites USING gin (tech);

CREATE TABLE IF NOT EXISTS raw_records (
    id           BIGSERIAL PRIMARY KEY,
    project_id   BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    site_id      BIGINT REFERENCES sites(id) ON DELETE SET NULL,
    source       TEXT NOT NULL,
    host         TEXT NOT NULL,
    port         INT NOT NULL,
    protocol     TEXT NOT NULL,
    value        TEXT NOT NULL,
    status_code  INT NOT NULL DEFAULT 0,
    title        TEXT,
    ip           INET,
    evidence     JSONB NOT NULL DEFAULT '{}'::jsonb,
    dedup_key    TEXT NOT NULL UNIQUE,
    observed_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_raw_project_time ON raw_records (project_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_raw_site ON raw_records (site_id);

CREATE TABLE IF NOT EXISTS verifications (
    id           BIGSERIAL PRIMARY KEY,
    site_id      BIGINT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    status       TEXT NOT NULL,
    reason_code  TEXT,
    http_status  INT NOT NULL DEFAULT 0,
    attempts     INT NOT NULL DEFAULT 1,
    detail       JSONB NOT NULL DEFAULT '{}'::jsonb,
    observed_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_verifications_site ON verifications (site_id, observed_at DESC);

CREATE TABLE IF NOT EXISTS asset_events (
    id           BIGSERIAL PRIMARY KEY,
    project_id   BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    site_id      BIGINT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    event_type   TEXT NOT NULL,
    title        TEXT NOT NULL,
    before       JSONB NOT NULL DEFAULT '{}'::jsonb,
    after        JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_asset_events_project_time ON asset_events (project_id, created_at DESC);

CREATE TABLE IF NOT EXISTS connectivity_policies (
    id                  INT PRIMARY KEY DEFAULT 1,
    failure_threshold   INT NOT NULL DEFAULT 3,
    first_hours         INT NOT NULL DEFAULT 24,
    second_hours        INT NOT NULL DEFAULT 72,
    repeat_hours        INT NOT NULL DEFAULT 168,
    cleanup_days        INT NOT NULL DEFAULT 30,
    auto_cleanup        BOOLEAN NOT NULL DEFAULT true,
    immediate_cleanup   BOOLEAN NOT NULL DEFAULT true,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO connectivity_policies (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

INSERT INTO schema_migrations (name, applied_at)
VALUES ('migration_assets_p0', now())
ON CONFLICT (name) DO NOTHING;

COMMIT;
