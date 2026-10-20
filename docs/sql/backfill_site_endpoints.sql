-- 一次性回填：把已有 raw_records 的入口信息补进 site_endpoints
-- 幂等：ON CONFLICT (site_id, scheme, port) DO UPDATE，可重复执行
-- 用途：schema_governance.sql 建表之后补历史数据；日常导入由 repo/assets_repo.go 直接写。

BEGIN;

WITH picked AS (
    SELECT DISTINCT ON (r.site_id, r.protocol, r.port)
           r.site_id, r.protocol AS scheme, r.host, r.port, r.status_code, r.observed_at
      FROM raw_records r
     WHERE r.site_id IS NOT NULL
       AND r.protocol IN ('http', 'https')
       AND r.port > 0
     ORDER BY r.site_id, r.protocol, r.port, r.observed_at DESC
)
INSERT INTO site_endpoints (site_id, scheme, host, port, status_code, last_seen_at)
SELECT site_id, scheme, host, port, status_code, observed_at FROM picked
ON CONFLICT (site_id, scheme, port) DO UPDATE
   SET status_code = CASE WHEN EXCLUDED.status_code > 0 THEN EXCLUDED.status_code
                          ELSE site_endpoints.status_code END,
       last_seen_at = GREATEST(site_endpoints.last_seen_at, EXCLUDED.last_seen_at);

COMMIT;
