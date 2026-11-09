-- 判定结果增强（审计质量优化）：
--   attack_path / impact / fix_evidence：命中安全修复时模型展开的
--   「攻击路径 → 影响 → 修复依据」三段式说明，替代原先一句话 reasoning；
--   evidence_snippets：模型从 diff 摘录的关键代码行（JSON 数组），
--   后端做防幻觉校验，摘录对不上真实 diff 会降低置信度。
-- 旧判定记录自然兼容（默认空值），不做数据回填；想重刷需走重判入口。

ALTER TABLE judgment ADD COLUMN IF NOT EXISTS attack_path       text NOT NULL DEFAULT '';
ALTER TABLE judgment ADD COLUMN IF NOT EXISTS impact            text NOT NULL DEFAULT '';
ALTER TABLE judgment ADD COLUMN IF NOT EXISTS fix_evidence      text NOT NULL DEFAULT '';
ALTER TABLE judgment ADD COLUMN IF NOT EXISTS evidence_snippets jsonb NOT NULL DEFAULT '[]'::jsonb;

COMMENT ON COLUMN judgment.attack_path       IS '命中时的攻击路径：入口 → 传播 → 汇聚点（非安全修复为空）';
COMMENT ON COLUMN judgment.impact            IS '命中时的影响与可利用条件（非安全修复为空）';
COMMENT ON COLUMN judgment.fix_evidence      IS '修复 diff 消除了攻击链哪一环（非安全修复为空）';
COMMENT ON COLUMN judgment.evidence_snippets IS '模型摘录的 diff 关键代码行数组，后端做防幻觉校验';
