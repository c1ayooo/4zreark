-- 漏洞复核工作流：状态流转台账 + 复核人/复核意见字段。
-- 原有 vulnerabilities.status 只有五个取值，没有"谁在什么时候为什么改"的记录，
-- 复核结论无法追溯，误报与已修复也分不清是谁定的。本迁移补上这两块。
BEGIN;
CREATE TABLE IF NOT EXISTS vuln_reviews (
    id           bigserial PRIMARY KEY,
    vuln_id      char(24)     NOT NULL,
    workspace_id char(24)     NOT NULL DEFAULT '000000000000000000000000',
    from_status  text         NOT NULL DEFAULT '',
    to_status    text         NOT NULL,
    reviewer     text         NOT NULL DEFAULT '',
    note         text         NOT NULL DEFAULT '',
    auto         boolean      NOT NULL DEFAULT false,
    created_at   timestamptz  NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS vuln_reviews_vuln_idx ON vuln_reviews (vuln_id, created_at DESC);
CREATE INDEX IF NOT EXISTS vuln_reviews_status_idx ON vuln_reviews (workspace_id, to_status, created_at DESC);

ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS reviewer text NOT NULL DEFAULT '';
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS review_note text NOT NULL DEFAULT '';
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS reviewed_at timestamptz;
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS review_count integer NOT NULL DEFAULT 0;

INSERT INTO schema_migrations (name) VALUES ('migration_vuln_reviews')
ON CONFLICT (name) DO NOTHING;
COMMIT;
