-- 信息收集分阶段编排：父计划 / 阶段子任务的操作列。
-- 依赖 schema_init.sql 的 tasks 表；apply_all.sh 会在核心表之后执行本文件。
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS plan_id char(24);
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS parent_id char(24);
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS stage text NOT NULL DEFAULT '';
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS collection_mode text NOT NULL DEFAULT '';

-- tasks_type_chk 是 IN 列表；新增 collection 类型必须重建约束，否则插入直接失败。
ALTER TABLE tasks DROP CONSTRAINT IF EXISTS tasks_type_chk;
ALTER TABLE tasks ADD CONSTRAINT tasks_type_chk CHECK (type IN (
    'asset_discovery','port_scan','fingerprint','vuln_scan','subdomain','takeover',
    'dir_scan','crawler','bruteforce','monitor','full','custom','collection',
    'service_identify','service_detect','exposure_scan','clue_hunt'
));

CREATE INDEX IF NOT EXISTS tasks_plan_stage_idx ON tasks (plan_id, stage);
CREATE INDEX IF NOT EXISTS tasks_parent_idx     ON tasks (parent_id);
