-- 任务归属项目：扫描结果按项目自动归并成资产。
--
-- 之前 tasks 只有 workspace_id，与资产域的项目（projects）没有关系；
-- 扫描结果只写 scan_results，永远不会进 sites/raw_records。
-- 这里补上归属字段：0 表示未归属（历史任务兼容，跳过自动入资产）。

BEGIN;

ALTER TABLE tasks
    ADD COLUMN IF NOT EXISTS project_id bigint NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS tasks_project_idx ON tasks (project_id, created_at DESC);

COMMIT;
