-- sites 补登记：扫描结果入库依赖的 5 个富集列。
--
-- 背景：repo/assets_repo.go 的站点 upsert（第 552 行）固定写 body_hash /
-- cert_org / cookie_names / js_frameworks / api_hosts，但 docs/sql 里从未定义
-- 过这些列。结果是每次任务结束时的「发现即落库」都报
--   ERROR: column "body_hash" of relation "sites" does not exist
-- 而错误只进一行日志、任务照旧标 completed —— 平台看起来跑完了，
-- sites / raw_records 永远是 0，指纹、技术栈没有任何落点。
--
-- 幂等：可重复执行。

alter table sites add column if not exists body_hash      text;
alter table sites add column if not exists cert_org       text;
alter table sites add column if not exists cookie_names   jsonb;
alter table sites add column if not exists js_frameworks  jsonb;
alter table sites add column if not exists api_hosts      jsonb;

-- 内容指纹用于「页面是否变化」判定，巡航 v2 与变更检测都按它比较。
create index if not exists idx_sites_body_hash on sites (body_hash) where body_hash is not null;
