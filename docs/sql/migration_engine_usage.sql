-- 引擎查询额度的按天记账。master 侧（种子展开等）查询前查余额、查询后落账；
-- worker 侧实际消耗随 scan_done 上报回 master 落账。worker 崩溃会少记——
-- 记账是防超烧的保护性措施，不追求审计级精确。
BEGIN;

CREATE TABLE IF NOT EXISTS engine_query_usage (
    day       date   NOT NULL,
    engine    text   NOT NULL,
    queries   int    NOT NULL DEFAULT 0,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (day, engine)
);

INSERT INTO schema_migrations (name) VALUES ('migration_engine_usage')
ON CONFLICT (name) DO NOTHING;

COMMIT;
