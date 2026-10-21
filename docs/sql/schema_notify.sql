-- 通知域：渠道配置持久化 + 站内通知与已读状态
-- 执行顺序：schema_init.sql 之后，可与其它延展层脚本并行执行（幂等）。
BEGIN;

-- 渠道配置。config 存 NotifyConfig 的 JSON 形态，敏感字段由 API 层脱敏返回。
CREATE TABLE IF NOT EXISTS notify_configs (
    id         bigserial   PRIMARY KEY,
    name       text        NOT NULL,
    type       text        NOT NULL,
    enabled    boolean     NOT NULL DEFAULT true,
    config     jsonb       NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (name, type)
);

-- 站内通知：所有经过 NotifyManager.Send 的消息都落一条，页面铃铛与通知页共用。
CREATE TABLE IF NOT EXISTS notifications (
    id         bigserial   PRIMARY KEY,
    level      text        NOT NULL DEFAULT 'info',
    title      text        NOT NULL,
    content    text        NOT NULL DEFAULT '',
    source     text        NOT NULL DEFAULT '',
    extra      jsonb       NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS notifications_created_idx ON notifications (created_at DESC, id DESC);

-- 已读状态按用户记录；通知本身是广播，不复制 N 份。
CREATE TABLE IF NOT EXISTS notification_reads (
    notification_id bigint      NOT NULL REFERENCES notifications(id) ON DELETE CASCADE,
    user_id         char(24)    NOT NULL,
    read_at         timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (notification_id, user_id)
);

CREATE INDEX IF NOT EXISTS notification_reads_user_idx ON notification_reads (user_id);

INSERT INTO schema_migrations (name) VALUES ('schema_notify')
ON CONFLICT (name) DO NOTHING;

COMMIT;
