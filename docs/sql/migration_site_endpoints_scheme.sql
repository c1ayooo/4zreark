-- 端口扫描结果自动进资产域：site_endpoints 之前只允许 http/https，
-- 非 HTTP 端口（ssh/redis/...）无法落库。这里把 scheme 扩展为 http/https/tcp，
-- 具体服务名保留在 raw_records.evidence.service，不改变归并键与已有数据。
BEGIN;

ALTER TABLE site_endpoints DROP CONSTRAINT IF EXISTS endpoints_scheme_chk;
ALTER TABLE site_endpoints
    ADD CONSTRAINT endpoints_scheme_chk CHECK (scheme IN ('http','https','tcp'));

INSERT INTO schema_migrations (name, applied_at)
VALUES ('migration_site_endpoints_scheme', now())
ON CONFLICT (name) DO NOTHING;

COMMIT;
