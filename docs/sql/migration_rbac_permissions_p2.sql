-- RBAC 权限补齐（20261022 评审）：节点/漏洞/POC/报告/通知/监控/巡航等域的
-- 写操作此前只要求「任意登录用户」，普通用户可删除扫描节点、清空 POC。
-- 本迁移补种缺失的动作权限码，并把新码并进 operator 角色（admin 在代码层直通，
-- user/viewer 维持只读）。仅新增/合并，不覆盖管理员手工调整。
BEGIN;

INSERT INTO permissions (id, name, code, description, module) VALUES
 (substr(md5('perm-node-write'),1,24),   '节点维护',   'node:write',    '扫描节点注册/编辑/删除/心跳', 'node'),
 (substr(md5('perm-vuln-write'),1,24),   '漏洞维护',   'vuln:write',    '漏洞新建/编辑/状态流转/复核/验证', 'vuln'),
 (substr(md5('perm-vuln-del'),1,24),     '漏洞删除',   'vuln:delete',   '删除漏洞', 'vuln'),
 (substr(md5('perm-poc-write'),1,24),    'POC 维护',   'poc:write',     'POC/Nuclei 模板增删改/导入/启停', 'vuln'),
 (substr(md5('perm-report-write'),1,24), '报告生成',   'report:write',  '生成/新建报告', 'report'),
 (substr(md5('perm-report-del'),1,24),   '报告删除',   'report:delete', '删除报告', 'report'),
 (substr(md5('perm-notify-write'),1,24), '通知维护',   'notify:write',  '通知渠道配置增删改/测试/发送', 'notify'),
 (substr(md5('perm-monitor-write'),1,24),'监控维护',   'monitor:write', '页面监控增删改/立即检查', 'monitor'),
 (substr(md5('perm-cruise-write'),1,24), '巡航维护',   'cruise:write',  '巡航任务 CRUD/启停/立即执行', 'cruise')
ON CONFLICT (code) DO NOTHING;

-- 新码并入 operator（运营）：数组去重合并，不改其他角色。
UPDATE roles
   SET permissions = (
       SELECT array_agg(DISTINCT x) FROM unnest(
           permissions || ARRAY[
             'node:write','vuln:write','vuln:delete','poc:write',
             'report:write','report:delete','notify:write','monitor:write','cruise:write'
           ]) AS x)
 WHERE name = 'operator'
   AND NOT (permissions @> ARRAY[
       'node:write','vuln:write','vuln:delete','poc:write',
       'report:write','report:delete','notify:write','monitor:write','cruise:write']);

INSERT INTO schema_migrations (name) VALUES ('migration_rbac_permissions_p2')
ON CONFLICT (name) DO NOTHING;

COMMIT;
