-- 读侧权限码（v4 §17.1：viewer 只读概览/项目/资产/事件，
-- 关系、指纹、数据源、执行、字典、设置、用户、种子/计划/批次只对运营方开放）。
BEGIN;

INSERT INTO permissions (id, name, code, description, module) VALUES
 (substr(md5('perm-gov-read'),1,24),       '治理读取', 'governance:read',   '种子/计划/批次/关系只读', 'governance'),
 (substr(md5('perm-fp-read'),1,24),        '指纹读取', 'fingerprint:read',  '指纹规则与命中只读', 'fingerprint'),
 (substr(md5('perm-source-read'),1,24),    '数据源读取', 'source:read',     '数据源列表与配置只读（凭据仍不回显）', 'source'),
 (substr(md5('perm-dict-read'),1,24),      '字典读取', 'dictionary:read',   '字典与条目只读', 'dictionary'),
 (substr(md5('perm-digital-read'),1,24),   '数字资产读取', 'digital:read',  '名单/文档/企业线索/ICP 查询只读', 'digital'),
 (substr(md5('perm-settings-read'),1,24),  '设置读取', 'settings:read',     '保留策略等设置只读', 'settings'),
 (substr(md5('perm-task-read'),1,24),      '任务读取', 'task:read',         '任务/日志/结果只读', 'task')
ON CONFLICT (code) DO NOTHING;

-- admin 全量（实际中间件对 admin 直接放行，这里保持表数据自洽）
UPDATE roles
   SET permissions = ARRAY(SELECT DISTINCT unnest(permissions || ARRAY[
       'governance:read','fingerprint:read','source:read','dictionary:read',
       'digital:read','settings:read','task:read']::text[])),
       updated_at = now()
 WHERE name = 'admin';

-- operator：可读治理/指纹/数据源/字典/数字资产/任务，但不能读设置与用户。
UPDATE roles
   SET permissions = ARRAY(SELECT DISTINCT unnest(permissions || ARRAY[
       'governance:read','fingerprint:read','source:read','dictionary:read',
       'digital:read','task:read']::text[])),
       updated_at = now()
 WHERE name = 'operator';

INSERT INTO schema_migrations (name) VALUES ('migration_rbac_read')
ON CONFLICT (name) DO NOTHING;

COMMIT;
