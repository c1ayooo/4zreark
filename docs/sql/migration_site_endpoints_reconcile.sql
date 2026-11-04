-- site_endpoints 结构对齐。
--
-- 背景：早期版本把 site_endpoints 定义成「一站一行入口表」，带 project_id /
-- method / path / url / source / first_seen / last_seen 等 NOT NULL 列；现行
-- repo/assets_repo.go 只写 (site_id, scheme, host, port, status_code)，并依赖
-- UNIQUE (site_id, scheme, port) 做 on conflict 归并，时间戳列名是 last_seen_at。
--
-- 因为建表语句是 CREATE TABLE IF NOT EXISTS，老库不会自动改结构，于是：
--   ERROR: column "last_seen_at" of relation "site_endpoints" does not exist
-- 每次落库都在这一步失败，端口入口一条都写不进去。
--
-- 处理：site_endpoints 是可由 raw_records 重建的派生投影，这里把旧结构改名留档、
-- 按现行定义重建、把能搬的字段搬过来，最后删掉旧表。
-- 幂等：可重复执行。

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
         WHERE table_name = 'site_endpoints' AND column_name = 'project_id'
    ) AND to_regclass('site_endpoints_legacy') IS NULL THEN
        ALTER TABLE site_endpoints RENAME TO site_endpoints_legacy;
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS site_endpoints (
    id           bigserial   PRIMARY KEY,
    site_id      bigint      NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    scheme       text        NOT NULL,
    host         text        NOT NULL,
    port         integer     NOT NULL,
    status_code  integer,
    verified_at  timestamptz,
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT endpoints_scheme_chk CHECK (scheme IN ('http','https','tcp')),
    UNIQUE (site_id, scheme, port)
);

CREATE INDEX IF NOT EXISTS site_endpoints_site_idx ON site_endpoints (site_id, port);

DO $$
BEGIN
    IF to_regclass('site_endpoints_legacy') IS NOT NULL THEN
        INSERT INTO site_endpoints (site_id, scheme, host, port, status_code, last_seen_at)
        SELECT l.site_id, l.scheme, l.host, l.port, coalesce(l.status_code, 0),
               coalesce(l.last_seen, now())
          FROM site_endpoints_legacy l
         WHERE l.site_id IS NOT NULL
           AND l.scheme IN ('http','https','tcp')
        ON CONFLICT (site_id, scheme, port) DO NOTHING;

        DROP TABLE site_endpoints_legacy;
    END IF;
END $$;
