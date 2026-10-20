-- POC 的 template_id 是「Nuclei 模板 ID」，手工创建的 POC 根本没有这个值。
-- 原来的 inline UNIQUE 约束会把所有手工 POC 都挤在空串上：第二条就冲突。
-- 改成部分唯一索引，与 vulnerabilities 的 vuln_dedup_uq 口径一致。
--
-- 执行顺序：schema_init.sql 之后。可重复执行。

BEGIN;

ALTER TABLE pocs DROP CONSTRAINT IF EXISTS pocs_template_id_key;
CREATE UNIQUE INDEX IF NOT EXISTS pocs_template_uq ON pocs (template_id) WHERE template_id <> '';

INSERT INTO schema_migrations (name) VALUES ('schema_poc_template_optional')
ON CONFLICT (name) DO NOTHING;

COMMIT;
