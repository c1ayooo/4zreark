-- 收尾三域（plugin / node / cruise）需要的增量结构。
-- 执行顺序：schema_init.sql 之后。可重复执行。

BEGIN;

-- Plugin 模型里有 Config（map），旧 Mongo 文档带这个字段，PG 表当初漏了。
ALTER TABLE plugins ADD COLUMN IF NOT EXISTS config jsonb NOT NULL DEFAULT '{}'::jsonb;

-- 巡航日志按 (cruise_id, task_id) 定位同一次执行并回填结束状态。
CREATE INDEX IF NOT EXISTS cruise_logs_task_idx ON cruise_logs (cruise_id, task_id);

-- 节点做「找最闲的可用节点」时要按 current_tasks 排序。
CREATE INDEX IF NOT EXISTS nodes_capacity_idx ON scanner_nodes (status, current_tasks);

INSERT INTO schema_migrations (name) VALUES ('schema_ops_finalize')
ON CONFLICT (name) DO NOTHING;

COMMIT;
