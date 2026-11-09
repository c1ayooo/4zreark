-- 预评分排序 + 分级（watchlist 种子 v1.0）
-- commit.score：high_signal/敏感路径/downgrade 关键词预评分（只影响判定优先级，不跳过）
-- finding.grade：S/A/B/C 分级（S=自动生成 PoC 候选，A=等人工确认，B=周报，C=仅记录）
ALTER TABLE commit ADD COLUMN IF NOT EXISTS score integer NOT NULL DEFAULT 0;
ALTER TABLE finding ADD COLUMN IF NOT EXISTS grade text NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS commit_score_idx ON commit (status, score DESC, id DESC);
