-- 资产探索记录视图的关键字搜索按 r.evidence::text ILIKE '%kw%' 过滤，
-- 列侧强转令任何普通索引失效，raw_records 大了以后每页都是全表序列化 JSONB。
-- 表达式 trgm 索引与查询里的表达式完全一致，planner 可以直接用，代码零改动。
--
-- 注意：CONCURRENTLY 不能在事务里跑，所以本文件没有 BEGIN/COMMIT；
-- 建索引期间持有 SHARE UPDATE EXCLUSIVE 锁，不阻塞读写，但耗时与表大小成正比，
-- 建议低峰期执行。pg_trgm 已在 schema_init 使用，无需再装。
CREATE INDEX CONCURRENTLY IF NOT EXISTS raw_records_evidence_trgm
	ON raw_records USING gin ((evidence::text) gin_trgm_ops);

INSERT INTO schema_migrations (name) VALUES ('migration_raw_records_evidence_trgm')
ON CONFLICT (name) DO NOTHING;
