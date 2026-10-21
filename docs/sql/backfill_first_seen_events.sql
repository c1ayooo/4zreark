-- G5：为存量站点补 first_seen 事件（幂等）。
-- 事件功能上线前导入的站点没有事件；回填的 created_at 用站点 first_seen，
-- record_id 取该站点最早的一条原始记录（没有则为空）。
--
-- 可重复执行：已存在同站点 first_seen 事件的行不会再插入。

BEGIN;

INSERT INTO asset_events (project_id, site_id, record_id, event_type, title, before, after, created_at)
SELECT s.project_id,
       s.id,
       (SELECT r.id FROM raw_records r WHERE r.site_id = s.id ORDER BY r.observed_at ASC LIMIT 1),
       'first_seen',
       '首次发现资产',
       '{}'::jsonb,
       jsonb_build_object(
         'host', s.host,
         'ip', coalesce(s.ip::text, ''),
         'title', coalesce(s.title, ''),
         'http_status', s.http_status,
         'backfilled', true
       ),
       s.first_seen
  FROM sites s
 WHERE NOT EXISTS (
         SELECT 1 FROM asset_events e
          WHERE e.site_id = s.id AND e.event_type = 'first_seen'
       );

INSERT INTO schema_migrations (name) VALUES ('backfill_first_seen_events')
ON CONFLICT (name) DO NOTHING;

COMMIT;
