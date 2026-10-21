-- T10：指纹规则表演进（只加列，不删既有列、不重建表）
--
-- 既有列：id/name/category/version/rules/enabled/source/condition_tree/dsl_version
-- 新增：
--   expression  reconkit 表达式（dddd/wappalyzer/webanalyze 同步写入）
--   rule_hash   sha256(name + expression)，用于幂等 upsert 与按源清理
--   fingerprint_sources  每个上游源的同步元数据
--
-- 旧规则（rules jsonb / condition_tree）继续保留，治理域的匹配器不受影响。

BEGIN;

ALTER TABLE fingerprint_rules ADD COLUMN IF NOT EXISTS expression text;
ALTER TABLE fingerprint_rules ADD COLUMN IF NOT EXISTS rule_hash  text;

CREATE UNIQUE INDEX IF NOT EXISTS fingerprint_rule_hash_uq
    ON fingerprint_rules (rule_hash) WHERE rule_hash IS NOT NULL;

CREATE TABLE IF NOT EXISTS fingerprint_sources (
    name          text        PRIMARY KEY,
    upstream_url  text        NOT NULL DEFAULT '',
    content_hash  text        NOT NULL DEFAULT '',
    rule_count    int         NOT NULL DEFAULT 0,
    skipped_count int         NOT NULL DEFAULT 0,
    fetched_at    timestamptz NOT NULL DEFAULT now()
);

INSERT INTO schema_migrations (name) VALUES ('migration_fingerprint_expression')
ON CONFLICT (name) DO NOTHING;

COMMIT;
