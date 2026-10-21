-- 资产路由：爬虫采到的 URL 按 host 归到站点下。
--
-- 为什么单独建表：site_endpoints 只有 (scheme, host, port)，是「入口」粒度；
-- 爬虫产出的是 path 粒度（/api/user、/admin/login），两者不是一回事。
--
-- 归属：site_id → sites.id（站点按 host 归并），project_id 冗余一列用于按项目筛选。
-- 去重：同一站点下 (method, path) 唯一，重复采集只刷新 last_seen。

BEGIN;

CREATE TABLE IF NOT EXISTS site_routes (
    id          bigserial   PRIMARY KEY,
    site_id     bigint      NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    project_id  bigint      NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    method      text        NOT NULL DEFAULT 'GET',
    path        text        NOT NULL,
    status_code integer     NOT NULL DEFAULT 0,
    source      text        NOT NULL DEFAULT '',
    first_seen  timestamptz NOT NULL DEFAULT now(),
    last_seen   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (site_id, method, path)
);

CREATE INDEX IF NOT EXISTS site_routes_site_idx    ON site_routes (site_id, last_seen DESC);
CREATE INDEX IF NOT EXISTS site_routes_project_idx ON site_routes (project_id);
CREATE INDEX IF NOT EXISTS site_routes_path_trgm_idx ON site_routes USING gin (path gin_trgm_ops);

COMMIT;
