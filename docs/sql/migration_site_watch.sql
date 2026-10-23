-- 资产巡航 v2：新内容发现（候选清单）+ 站点内容慢速巡检。
-- asset_candidates：被动源（测绘引擎反查/证书透明）发现、待人工确认的新资产候选；
-- sites 内容巡检列：两级 hash（原始 body / 剥离正文）判变化，慢速队列每站每天至多一查。
BEGIN;

CREATE TABLE IF NOT EXISTS asset_candidates (
    id          bigserial   PRIMARY KEY,
    project_id  bigint      NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    kind        text        NOT NULL DEFAULT 'domain'
                CHECK (kind IN ('domain', 'cert_org', 'app')),
    value       text        NOT NULL,
    source      text        NOT NULL DEFAULT '',
    confidence  int         NOT NULL DEFAULT 50,
    status      text        NOT NULL DEFAULT 'pending'
                CHECK (status IN ('pending', 'accepted', 'rejected')),
    created_at  timestamptz NOT NULL DEFAULT now(),
    decided_at  timestamptz,
    UNIQUE (project_id, kind, value)
);

CREATE INDEX IF NOT EXISTS asset_candidates_pending_idx
    ON asset_candidates (project_id, status, created_at DESC)
    WHERE status = 'pending';

-- 站点内容巡检列（慢速队列按 content_checked_at 最旧优先选站）
ALTER TABLE sites ADD COLUMN IF NOT EXISTS content_hash text NOT NULL DEFAULT '';
ALTER TABLE sites ADD COLUMN IF NOT EXISTS content_text_hash text NOT NULL DEFAULT '';
ALTER TABLE sites ADD COLUMN IF NOT EXISTS content_checked_at timestamptz;
ALTER TABLE sites ADD COLUMN IF NOT EXISTS content_changed_at timestamptz;
ALTER TABLE sites ADD COLUMN IF NOT EXISTS watch_excluded boolean NOT NULL DEFAULT false;

INSERT INTO schema_migrations (name) VALUES ('migration_site_watch')
ON CONFLICT (name) DO NOTHING;

COMMIT;
