-- 节点密钥：节点用可吊销 token 连接平台，不再把数据库账号放在节点侧。
-- 执行顺序：schema_init.sql 之后执行一次；全部 ADD COLUMN IF NOT EXISTS，可重复运行。

BEGIN;

ALTER TABLE scanner_nodes
    ADD COLUMN IF NOT EXISTS token_hash char(64) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS revoked_at timestamptz;

CREATE UNIQUE INDEX IF NOT EXISTS nodes_token_uq
    ON scanner_nodes (token_hash) WHERE token_hash <> '';

COMMIT;
