-- 用户「必须改密」标记：admin 创建时或仍持有默认口令时置 true，
-- 中间件据此只放行 profile/password/logout，直到完成改密（改密时清除）。
BEGIN;

ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password boolean NOT NULL DEFAULT false;

INSERT INTO schema_migrations (name) VALUES ('migration_user_must_change_password')
ON CONFLICT (name) DO NOTHING;

COMMIT;
