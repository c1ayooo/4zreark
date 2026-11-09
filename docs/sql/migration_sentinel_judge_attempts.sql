-- AI 判定失败状态机：记录尝试次数、错误与下次重试时间，
-- 避免「失败不改 commit.status」导致调度器每轮无限重投，也避免 partial
-- 直接沉底后再无人捡起。
ALTER TABLE commit ADD COLUMN IF NOT EXISTS judge_attempts   integer     NOT NULL DEFAULT 0;
ALTER TABLE commit ADD COLUMN IF NOT EXISTS last_judge_error text        NOT NULL DEFAULT '';
ALTER TABLE commit ADD COLUMN IF NOT EXISTS next_judge_at    timestamptz;

-- 待判定偏索引与查询口径对齐：pending 与可重试 failed 都纳入。
DROP INDEX IF EXISTS commit_pending_idx;
CREATE INDEX IF NOT EXISTS commit_pending_idx ON commit (status, next_judge_at, committed_at DESC)
    WHERE status IN ('pending', 'failed');
