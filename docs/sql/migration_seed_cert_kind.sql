-- 种子类型补齐 cert（证书组织）：Go 层（governance/seed_expand/seed_catalog/前端）
-- 自 c1a3cbc 起全链路支持 cert，但 seeds 的 CHECK 约束未同步，创建 cert 种子
-- 会被 23514 拒绝。此处放宽约束对齐代码层白名单。
BEGIN;

ALTER TABLE seeds DROP CONSTRAINT seeds_kind_chk;

ALTER TABLE seeds ADD CONSTRAINT seeds_kind_chk
    CHECK (kind IN ('domain','cidr','company','repo','app','dict','cert'));

INSERT INTO schema_migrations (name) VALUES ('migration_seed_cert_kind')
ON CONFLICT (name) DO NOTHING;

COMMIT;
