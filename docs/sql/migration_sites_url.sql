-- 站点层与入口层显式分离。
-- sites.value 历史上是「最近一条 https 证据的完整 URL」，会被后续采集覆盖，
-- 只适合展示/索引；新增 url 作为权威的可请求主入口，前端「打开主入口」、
-- 全量 CSV 的 url 列都改读它。value 保留兼容，避免 dedup_key 漂移与事件语义断裂。
BEGIN;

ALTER TABLE sites ADD COLUMN IF NOT EXISTS url TEXT NOT NULL DEFAULT '';

-- 历史站点回填；新装库无数据时空转。
UPDATE sites SET url = value WHERE url = '' AND value <> '';

INSERT INTO schema_migrations (name) VALUES ('migration_sites_url')
ON CONFLICT (name) DO NOTHING;

COMMIT;
