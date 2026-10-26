-- 站点资产治理四件套：星标 / 标签 / 备注 / 忽略。
-- 运行一次；后端启动时另有 ADD COLUMN IF NOT EXISTS 兜底（repo/site_governance_repo.go）。
ALTER TABLE sites ADD COLUMN IF NOT EXISTS starred BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE sites ADD COLUMN IF NOT EXISTS tags JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE sites ADD COLUMN IF NOT EXISTS note TEXT NOT NULL DEFAULT '';
ALTER TABLE sites ADD COLUMN IF NOT EXISTS ignored BOOLEAN NOT NULL DEFAULT FALSE;

-- 星标筛选：部分索引只覆盖已标星行，列表页「只看星标」走这里。
CREATE INDEX IF NOT EXISTS idx_sites_starred ON sites (project_id, last_seen DESC) WHERE starred;
-- 标签等值/包含检索的 gin 支持：tag="重点" 走 jsonb contains。
CREATE INDEX IF NOT EXISTS idx_sites_tags ON sites USING gin (tags jsonb_path_ops);
-- 「已忽略」视图：忽略的一般是误报/非目标资产，量小走部分索引。
CREATE INDEX IF NOT EXISTS idx_sites_ignored ON sites (project_id, last_seen DESC) WHERE ignored;
