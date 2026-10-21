-- 报告类型与交付模板：vuln_reports 同时承载漏洞交付报告与信息收集/资产测绘报告。
BEGIN;
ALTER TABLE vuln_reports ADD COLUMN IF NOT EXISTS report_kind text NOT NULL DEFAULT 'vuln';
ALTER TABLE vuln_reports ADD COLUMN IF NOT EXISTS template text NOT NULL DEFAULT 'standard';
ALTER TABLE vuln_reports ADD COLUMN IF NOT EXISTS delivery jsonb NOT NULL DEFAULT '{}'::jsonb;
INSERT INTO schema_migrations (name) VALUES ('migration_report_kind_template')
ON CONFLICT (name) DO NOTHING;
COMMIT;
