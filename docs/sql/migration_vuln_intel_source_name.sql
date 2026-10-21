-- 情报域：补 source_name（源引擎键）与轮询统计所需索引
--
-- 背景：vuln_intel 原表只有 source（展示名）。reconkit 的 vulnmonitor 同时产出
-- SourceName（provider key，如 threatbook / chaitin）用于按源统计与去重，
-- 展示名会变、键不会。这里按「新增列」演进，不重建表、不动既有列。
--
-- 口径：schema_init.sql 之后执行；可重复执行（IF NOT EXISTS）。

BEGIN;

ALTER TABLE vuln_intel
    ADD COLUMN IF NOT EXISTS source_name text NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS intel_source_name_idx
    ON vuln_intel (source_name);

-- 列表默认按 created_at DESC 排序，已有 intel_created_idx 覆盖。
-- 关键字检索用 ILIKE，title 上补 trgm 索引（pg_trgm 已在 migration_assets_p0 创建）。
CREATE INDEX IF NOT EXISTS intel_title_trgm_idx
    ON vuln_intel USING gin (title gin_trgm_ops);

COMMIT;
