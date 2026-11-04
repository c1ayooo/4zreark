-- ICP 查询结果回灌种子：查询任务上记录"是否自动转种子"和导入量。
--
-- 背景：icp_filings 此前只写不读，工信部查到的几十个备案域名停在快照里，
-- 不生成种子、不进批次、不探活，整条链路断在最后一公里。加这三列后，
-- 查询完成时可以自动把域名转成 domain 种子并建监控计划。
--
-- 执行顺序：migration_icp_queries.sql 之后。幂等，可重复执行。
BEGIN;

alter table icp_queries
    add column if not exists auto_promote boolean not null default false;

-- 转成种子时同时建的监控计划周期（小时）；0 表示只建种子、不建计划。
alter table icp_queries
    add column if not exists promote_interval_hours integer not null default 24;

-- 本次查询最终转成种子的条数（重复的域名不计）。
alter table icp_queries
    add column if not exists promoted_count integer not null default 0;

INSERT INTO schema_migrations (name) VALUES ('migration_icp_promote')
ON CONFLICT (name) DO NOTHING;

COMMIT;
