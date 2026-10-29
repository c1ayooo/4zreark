-- 任务执行认领：executor_id 是跨执行器的分配凭证——master 本地执行与 worker
-- 节点执行都先原子认领（update ... where executor_id=''），认领失败的执行直接放弃，
-- 根治 River 重试/重复投递导致的同一任务双跑（双倍耗时、重复产出）。
BEGIN;

ALTER TABLE tasks ADD COLUMN IF NOT EXISTS executor_id text NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS tasks_executor_idx ON tasks (executor_id) WHERE executor_id <> '';

INSERT INTO schema_migrations (name) VALUES ('migration_tasks_executor_id')
ON CONFLICT (name) DO NOTHING;

COMMIT;
