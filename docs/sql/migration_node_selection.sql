-- 扫描节点选择：默认节点 + 任务可选节点。
BEGIN;

-- 单行系统设置表（复用：默认节点、其它单例配置后续都放这里）。
CREATE TABLE IF NOT EXISTS app_settings (
    key        text        PRIMARY KEY,
    value      jsonb       NOT NULL DEFAULT '{}'::jsonb,
    updated_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO schema_migrations (name) VALUES ('migration_node_selection')
ON CONFLICT (name) DO NOTHING;

COMMIT;
