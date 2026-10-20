-- 指纹域增量：条件树与命中落库（ScopesHub 复刻 G3）
-- 前置：schema_init.sql（fingerprint_rules 已有 rules jsonb 扁平数组）→ 本文件
-- 口径：老规则（dsl_version=1）保持扁平数组不变；新规则写 condition_tree + dsl_version=2。
--       两种规则都能被 governance 的匹配器执行，互不覆盖。

BEGIN;

-- 条件树：{"and":[...]} / {"or":[...]} / {"not":{...}} / 叶子
-- 叶子：{"type":"header|body|title|server|status|icon_hash","key":"server","op":"contains|equals|regex|prefix","value":"nginx"}
ALTER TABLE fingerprint_rules ADD COLUMN IF NOT EXISTS condition_tree jsonb;
ALTER TABLE fingerprint_rules ADD COLUMN IF NOT EXISTS dsl_version    smallint NOT NULL DEFAULT 1;

-- 匹配器只取启用的规则，部分索引足够
CREATE INDEX IF NOT EXISTS fingerprint_enabled_idx ON fingerprint_rules (enabled) WHERE enabled;

-- 命中表要跟着站点和规则一起走：否则删项目/删规则后留一堆孤儿行，
-- 而且 app= 查询会 join 到不存在的站点。先清历史孤儿，再补外键。
DELETE FROM fingerprint_hits
 WHERE site_id NOT IN (SELECT id FROM sites)
    OR rule_id NOT IN (SELECT id FROM fingerprint_rules);

ALTER TABLE fingerprint_hits DROP CONSTRAINT IF EXISTS fingerprint_hits_site_fk;
ALTER TABLE fingerprint_hits ADD  CONSTRAINT fingerprint_hits_site_fk
    FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE;

ALTER TABLE fingerprint_hits DROP CONSTRAINT IF EXISTS fingerprint_hits_rule_fk;
ALTER TABLE fingerprint_hits ADD  CONSTRAINT fingerprint_hits_rule_fk
    FOREIGN KEY (rule_id) REFERENCES fingerprint_rules(id) ON DELETE CASCADE;

INSERT INTO schema_migrations (name) VALUES ('schema_fingerprint')
ON CONFLICT (name) DO NOTHING;

COMMIT;
