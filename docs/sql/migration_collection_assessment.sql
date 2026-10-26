-- 采集完成综合评估快照：按采集批次落一行 stats，供项目资产面趋势查询。
BEGIN;

CREATE TABLE IF NOT EXISTS collection_assessment_snapshots (
    id         bigserial   PRIMARY KEY,
    project_id bigint      NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    taken_at   timestamptz NOT NULL DEFAULT now(),
    stats      jsonb       NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS collection_assessment_snapshots_project_idx
    ON collection_assessment_snapshots (project_id, taken_at DESC);

INSERT INTO schema_migrations (name) VALUES ('migration_collection_assessment')
ON CONFLICT (name) DO NOTHING;

COMMIT;
