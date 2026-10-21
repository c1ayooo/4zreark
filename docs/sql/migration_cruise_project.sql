-- 巡航任务项目化：绑定项目 + 目标来源（fixed / 项目整体资产派生）
-- 执行顺序：schema_init.sql 之后执行一次；可重复运行。

BEGIN;

ALTER TABLE cruise_tasks
    ADD COLUMN IF NOT EXISTS project_id bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS target_source text NOT NULL DEFAULT 'static';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'cruise_target_source_chk'
    ) THEN
        ALTER TABLE cruise_tasks
            ADD CONSTRAINT cruise_target_source_chk
            CHECK (target_source IN ('static','project'));
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS cruise_project_idx ON cruise_tasks (project_id);

COMMIT;
