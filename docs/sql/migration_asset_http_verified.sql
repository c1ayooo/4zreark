-- 资产列表补 last_http_verified_at：只记录 HTTP 探测确认，不混用人工 verified_at。
BEGIN;
ALTER TABLE sites ADD COLUMN IF NOT EXISTS last_http_verified_at timestamptz;
INSERT INTO schema_migrations (name) VALUES ('migration_asset_http_verified')
ON CONFLICT (name) DO NOTHING;
COMMIT;
