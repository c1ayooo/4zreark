-- pocsmith 差分复现（v0.3 §7.6-7.9）
--
-- finding.verified_at / verified_by：机器复现通过的定格标记。
-- status=confirmed 表示人工确认；verified_at 非空表示 pocsmith 差分验证
-- 通过（differential-ok），两者正交：人工可以先确认，机器后复现，
-- 机器复现也可以在未确认的发现上通过。
-- run_type='repro' 复用既有 run 表枚举（schema_sentinel.sql），无需新表。

ALTER TABLE finding ADD COLUMN IF NOT EXISTS verified_at timestamptz;
ALTER TABLE finding ADD COLUMN IF NOT EXISTS verified_by text NOT NULL DEFAULT '';
