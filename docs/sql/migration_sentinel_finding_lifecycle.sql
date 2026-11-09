-- 发现生命周期 + 产物链（v0.3 §11.8 MVP）
--
-- finding.status 与前端枚举对齐：open / confirmed / ignored / resolved
--   （原注释里的 verifying/dismissed 从未有过写入方，废弃）
-- artifact 补齐产物链三件套：
--   title    展示名（patch: <sha8> / 模板 id）
--   status   产物状态机 draft → pending_review → verified / rejected → deprecated
--            铁律沿用文档：非 verified 产物不可下载、不可发布到 PoC 库
--   updated_at 状态流转时间
-- kind 扩展：poc / nuclei / report / patch / repro_log（schema 注释原只有 poc/repro_log/patch）

ALTER TABLE artifact ADD COLUMN IF NOT EXISTS title      text NOT NULL DEFAULT '';
ALTER TABLE artifact ADD COLUMN IF NOT EXISTS status     text NOT NULL DEFAULT 'draft';
ALTER TABLE artifact ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now();

COMMENT ON COLUMN artifact.kind IS 'poc / nuclei / report / patch / repro_log';
COMMENT ON COLUMN finding.status IS 'open / confirmed / ignored / resolved';
