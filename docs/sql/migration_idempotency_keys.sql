-- 写操作幂等键（v4 §15.1：Idempotency-Key 24h 去重）。
-- 无 Redis，直接落 PG；过期行在 Reserve 时顺带清理。
BEGIN;

CREATE TABLE IF NOT EXISTS idempotency_keys (
    key          text        PRIMARY KEY,
    user_id      text        NOT NULL DEFAULT '',
    method       text        NOT NULL,
    path         text        NOT NULL,
    status       int         NOT NULL DEFAULT 0,
    content_type text        NOT NULL DEFAULT 'application/json',
    body         bytea       NOT NULL DEFAULT '\x'::bytea,
    processing   boolean     NOT NULL DEFAULT true,
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS idempotency_keys_expiry_idx
    ON idempotency_keys (expires_at);

INSERT INTO schema_migrations (name) VALUES ('migration_idempotency_keys')
ON CONFLICT (name) DO NOTHING;

COMMIT;
