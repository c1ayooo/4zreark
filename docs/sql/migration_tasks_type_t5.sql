-- tasks.type 约束补录 T5/T7 任务类型：service_identify（含历史值 service_detect）、
-- exposure_scan、clue_hunt。这些类型上线时只改了 Go 侧枚举，
-- pgsql 的 CHECK 约束没同步，导致独立任务落库报 tasks_type_chk 违约。
BEGIN;

ALTER TABLE tasks DROP CONSTRAINT tasks_type_chk;

ALTER TABLE tasks ADD CONSTRAINT tasks_type_chk
    CHECK (type IN ('asset_discovery','port_scan','fingerprint','vuln_scan','subdomain',
                    'takeover','dir_scan','crawler','bruteforce','monitor','full','custom',
                    'service_identify','service_detect','exposure_scan','clue_hunt'));

INSERT INTO schema_migrations (name) VALUES ('migration_tasks_type_t5')
ON CONFLICT (name) DO NOTHING;

COMMIT;
