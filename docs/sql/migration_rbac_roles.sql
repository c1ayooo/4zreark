-- 角色 → 动作权限码（v4 §18.2）。仅新增/补种，不覆盖管理员后续手工调整。
BEGIN;

INSERT INTO permissions (id, name, code, description, module) VALUES
 (substr(md5('perm-project-read'),1,24),  '项目读取', 'project:read',        '读取项目与采集态', 'project'),
 (substr(md5('perm-project-write'),1,24), '项目维护', 'project:write',       '新建/编辑/暂停/恢复项目', 'project'),
 (substr(md5('perm-project-del'),1,24),   '项目删除', 'project:delete',      '永久删除项目', 'project'),
 (substr(md5('perm-seed-write'),1,24),    '种子维护', 'seed:write',          '新建/删除/重建种子', 'governance'),
 (substr(md5('perm-plan-write'),1,24),    '计划维护', 'plan:write',          '新建/编辑/删除监控计划', 'governance'),
 (substr(md5('perm-run-exec'),1,24),      '执行批次', 'run:execute',         '触发计划/执行批次', 'governance'),
 (substr(md5('perm-gov-write'),1,24),     '治理维护', 'governance:write',    '关系重建/回放/治理动作', 'governance'),
 (substr(md5('perm-asset-read'),1,24),    '资产读取', 'asset:read',          '读取资产/事件/关系', 'asset'),
 (substr(md5('perm-asset-write'),1,24),   '资产维护', 'asset:write',         '导入/验证/探测/保护/归档', 'asset'),
 (substr(md5('perm-asset-del'),1,24),     '资产删除', 'asset:delete',        '删除失联资产', 'asset'),
 (substr(md5('perm-recheck'),1,24),       '强制复验', 'verification:recheck','重置验证预算并复验', 'asset'),
 (substr(md5('perm-fp-write'),1,24),      '指纹维护', 'fingerprint:write',   '指纹规则增删改/同步', 'fingerprint'),
 (substr(md5('perm-source-write'),1,24),  '数据源维护', 'source:write',      '数据源与凭据维护', 'source'),
 (substr(md5('perm-dict-write'),1,24),    '字典维护', 'dictionary:write',    '字典导入/删除', 'dictionary'),
 (substr(md5('perm-digital-write'),1,24), '数字资产维护', 'digital:write',   '名单/文档/企业线索导入', 'digital'),
 (substr(md5('perm-task-write'),1,24),    '任务维护', 'task:write',          '任务 CRUD 与生命周期', 'task'),
 (substr(md5('perm-node-write'),1,24),    '节点维护', 'node:write',          '扫描节点注册/编辑/删除/心跳', 'node'),
 (substr(md5('perm-vuln-write'),1,24),    '漏洞维护', 'vuln:write',          '漏洞新建/编辑/状态流转/复核/验证', 'vuln'),
 (substr(md5('perm-vuln-del'),1,24),      '漏洞删除', 'vuln:delete',         '删除漏洞', 'vuln'),
 (substr(md5('perm-poc-write'),1,24),     'POC 维护', 'poc:write',           'POC/Nuclei 模板增删改/导入/启停', 'vuln'),
 (substr(md5('perm-report-write'),1,24),  '报告生成', 'report:write',        '生成/新建报告', 'report'),
 (substr(md5('perm-report-del'),1,24),    '报告删除', 'report:delete',       '删除报告', 'report'),
 (substr(md5('perm-notify-write'),1,24),  '通知维护', 'notify:write',        '通知渠道配置增删改/测试/发送', 'notify'),
 (substr(md5('perm-monitor-write'),1,24), '监控维护', 'monitor:write',       '页面监控增删改/立即检查', 'monitor'),
 (substr(md5('perm-cruise-write'),1,24),  '巡航维护', 'cruise:write',        '巡航任务 CRUD/启停/立即执行', 'cruise'),
 (substr(md5('perm-user-manage'),1,24),   '用户管理', 'user:manage',         '用户/注册码管理', 'user'),
 (substr(md5('perm-audit-read'),1,24),    '审计读取', 'audit:read',          '读取操作日志', 'audit'),
 (substr(md5('perm-settings-write'),1,24),'设置维护', 'settings:write',      '保留策略与系统设置', 'settings')
ON CONFLICT (code) DO NOTHING;

INSERT INTO roles (id, name, description, permissions) VALUES
 (substr(md5('role-admin'),1,24), 'admin', '管理员（全部权限）', ARRAY[
   'project:read','project:write','project:delete','seed:write','plan:write','run:execute',
   'governance:write','asset:read','asset:write','asset:delete','verification:recheck',
   'fingerprint:write','source:write','dictionary:write','digital:write','task:write',
   'node:write','vuln:write','vuln:delete','poc:write','report:write','report:delete',
   'notify:write','monitor:write','cruise:write',
   'user:manage','audit:read','settings:write']),
 (substr(md5('role-operator'),1,24), 'operator', '运营（项目/治理/资产，不可改数据源与用户）', ARRAY[
   'project:read','project:write','seed:write','plan:write','run:execute','governance:write',
   'asset:read','asset:write','asset:delete','verification:recheck','fingerprint:write',
   'dictionary:write','digital:write','task:write',
   'node:write','vuln:write','vuln:delete','poc:write','report:write','report:delete',
   'notify:write','monitor:write','cruise:write']),
 (substr(md5('role-user'),1,24), 'user', '普通用户（只读资产）', ARRAY['project:read','asset:read']),
 (substr(md5('role-viewer'),1,24), 'viewer', '只读访客', ARRAY['project:read','asset:read'])
ON CONFLICT (name) DO NOTHING;

INSERT INTO schema_migrations (name) VALUES ('migration_rbac_roles')
ON CONFLICT (name) DO NOTHING;

COMMIT;
