-- 巡航计划增加触发方式：固定周期 / 资产变化 / 两者。
-- on_change 由 asset_events 触发，配一个冷却窗口避免一次采集风暴刷出一串批次；
-- interval 保持原有行为，仅 interval/both 参与到期扫描。
BEGIN;
ALTER TABLE monitoring_plans ADD COLUMN IF NOT EXISTS trigger_mode text NOT NULL DEFAULT 'interval';
ALTER TABLE monitoring_plans ADD COLUMN IF NOT EXISTS change_cooldown_minutes integer NOT NULL DEFAULT 10;

ALTER TABLE monitoring_plans DROP CONSTRAINT IF EXISTS plans_trigger_mode_chk;
ALTER TABLE monitoring_plans ADD CONSTRAINT plans_trigger_mode_chk
    CHECK (trigger_mode IN ('interval', 'on_change', 'both'));
ALTER TABLE monitoring_plans DROP CONSTRAINT IF EXISTS plans_change_cooldown_chk;
ALTER TABLE monitoring_plans ADD CONSTRAINT plans_change_cooldown_chk
    CHECK (change_cooldown_minutes BETWEEN 1 AND 1440);

CREATE INDEX IF NOT EXISTS plans_change_idx ON monitoring_plans (trigger_mode)
    WHERE enabled AND trigger_mode IN ('on_change', 'both');

INSERT INTO schema_migrations (name) VALUES ('migration_cycle_change_trigger')
ON CONFLICT (name) DO NOTHING;
COMMIT;
