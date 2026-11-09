-- 美团src（project_id=1）业务数据清空。
-- 保留 projects 行、用户/角色/字典/全局设置/api_keys/监控规则。
-- 单事务；任一步失败整体回滚。执行前已有 reports/meituan-before-20261110/zreark.dump。
\set ON_ERROR_STOP on
BEGIN;

-- 队列与任务
DELETE FROM zre.river_job
 WHERE kind = 'scan_task'
   AND args->>'task_id' IN (SELECT id FROM zre.tasks WHERE project_id::text = '1');
DELETE FROM zre.task_jobs
 WHERE task_id IN (SELECT id FROM zre.tasks WHERE project_id::text = '1');
DELETE FROM zre.cruise_logs
 WHERE task_id IN (SELECT id FROM zre.tasks WHERE project_id::text = '1');
DELETE FROM zre.collection_stages
 WHERE plan_id IN (SELECT id FROM zre.collection_plans WHERE project_id::text = '1');
DELETE FROM zre.collection_plans WHERE project_id::text = '1';
DELETE FROM zre.task_logs
 WHERE task_id IN (SELECT id FROM zre.tasks WHERE project_id::text = '1');
DELETE FROM zre.result_dedup
 WHERE task_id IN (SELECT id FROM zre.tasks WHERE project_id::text = '1');
DELETE FROM zre.vulnerabilities
 WHERE task_id IN (SELECT id FROM zre.tasks WHERE project_id::text = '1');
DELETE FROM zre.scan_results
 WHERE task_id IN (SELECT id FROM zre.tasks WHERE project_id::text = '1');

-- 资产与站点
DELETE FROM zre.site_endpoints
 WHERE site_id IN (SELECT id FROM zre.sites WHERE project_id::text = '1');
DELETE FROM zre.fingerprint_hits
 WHERE site_id IN (SELECT id FROM zre.sites WHERE project_id::text = '1');
DELETE FROM zre.verifications
 WHERE site_id IN (SELECT id FROM zre.sites WHERE project_id::text = '1');
DELETE FROM zre.site_routes WHERE project_id::text = '1';
DELETE FROM zre.asset_events WHERE project_id::text = '1';
DELETE FROM zre.discovery_runs WHERE project_id::text = '1';
DELETE FROM zre.cruise_tasks WHERE project_id::text = '1';
DELETE FROM zre.collection_assessment_snapshots WHERE project_id::text = '1';
DELETE FROM zre.import_batches WHERE project_id::text = '1';
DELETE FROM zre.digital_assets WHERE project_id::text = '1';
DELETE FROM zre.digital_candidates WHERE project_id::text = '1';
DELETE FROM zre.relations WHERE project_id::text = '1';
DELETE FROM zre.seed_collection_jobs WHERE project_id::text = '1';
DELETE FROM zre.vulnverify_jobs WHERE project_id::text = '1';
DELETE FROM zre.icp_filings WHERE project_id::text = '1';
DELETE FROM zre.icp_queries WHERE project_id::text = '1';

-- AI 数据面
DELETE FROM zre.raw_snapshots
 WHERE task_id IN (SELECT id FROM zre.tasks WHERE project_id::text = '1');
DELETE FROM zre.ai_gate_verdicts
 WHERE raw_id IN (SELECT id::text FROM zre.raw_records WHERE project_id::text = '1');
DELETE FROM zre.ai_items
 WHERE raw_id IN (SELECT id::text FROM zre.raw_records WHERE project_id::text = '1');
DELETE FROM zre.diff_jobs WHERE entity_id LIKE '%meituan%';
DELETE FROM zre.raw_records WHERE project_id::text = '1';
DELETE FROM zre.asset_candidates WHERE project_id::text = '1';

-- 任务与种子（最后删，避免外键悬挂）
DELETE FROM zre.tasks WHERE project_id::text = '1';
DELETE FROM zre.seeds WHERE project_id::text = '1';
DELETE FROM zre.sites WHERE project_id::text = '1';

-- 重新开始：只保留主域一个种子
INSERT INTO zre.seeds (project_id, kind, value, capability, enabled)
VALUES (1, 'domain', 'meituan.com', '{}'::jsonb, true)
ON CONFLICT DO NOTHING;

COMMIT;
