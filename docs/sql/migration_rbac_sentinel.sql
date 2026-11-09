-- CommitSentinel RBAC：只新增 sentinel:read / sentinel:write 两个权限点，
-- 并追加到 admin/operator/user/viewer 的 permissions 数组（数组去重，可重复执行）。
BEGIN;

INSERT INTO permissions (id, name, code, description, module) VALUES
 (substr(md5('perm-sentinel-read'),1,24),  '提交哨兵读取', 'sentinel:read',  '读取仓库/提交/判定/发现', 'sentinel'),
 (substr(md5('perm-sentinel-write'),1,24), '提交哨兵维护', 'sentinel:write', '仓库增删改/立即采集/重新判定', 'sentinel')
ON CONFLICT (code) DO NOTHING;

-- 角色升级用「并集」而不是覆盖：管理员后续手工调整的权限不能被迁移重置。
UPDATE roles
   SET permissions = (
         SELECT array_agg(DISTINCT p ORDER BY p)
           FROM unnest(permissions || ARRAY['sentinel:read','sentinel:write']) AS p
       ),
       updated_at = now()
 WHERE name IN ('admin','operator');

UPDATE roles
   SET permissions = (
         SELECT array_agg(DISTINCT p ORDER BY p)
           FROM unnest(permissions || ARRAY['sentinel:read']) AS p
       ),
       updated_at = now()
 WHERE name IN ('user','viewer');

INSERT INTO schema_migrations (name) VALUES ('migration_rbac_sentinel')
ON CONFLICT (name) DO NOTHING;

COMMIT;
