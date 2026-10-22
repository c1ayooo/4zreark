-- 站点 ICP 备案/许可证号：存活验证探测时从页面正文提取（internal/extractor）。
-- icp 存归一化主号（多号逗号分隔），icp_seen_at 记录最近一次提取时间。
BEGIN;

ALTER TABLE sites ADD COLUMN IF NOT EXISTS icp text NOT NULL DEFAULT '';
ALTER TABLE sites ADD COLUMN IF NOT EXISTS icp_seen_at timestamptz;
CREATE INDEX IF NOT EXISTS sites_icp_idx ON sites (icp) WHERE icp <> '';

INSERT INTO schema_migrations (name) VALUES ('migration_sites_icp')
ON CONFLICT (name) DO NOTHING;

COMMIT;
