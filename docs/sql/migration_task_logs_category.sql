-- 任务日志升级为统一动作日志：加功能分类列（子域名/端口/指纹/爬虫/漏洞/
-- 服务识别/暴露面/存量线索/ICP查询/企业采集/系统），供任务日志页按功能筛选。
BEGIN;

ALTER TABLE task_logs ADD COLUMN IF NOT EXISTS category text NOT NULL DEFAULT 'system';

CREATE INDEX IF NOT EXISTS task_logs_category_idx ON task_logs (category, created_at DESC);

INSERT INTO schema_migrations (name) VALUES ('migration_task_logs_category')
ON CONFLICT (name) DO NOTHING;

COMMIT;
