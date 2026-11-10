-- GitHub 泄露命中按项目隔离。
-- 存量行按 rule_name 的「项目名: 规则名」前缀回填 project_id；
-- 回填不到的历史行保留 0，仅全局管理视图可见。
ALTER TABLE github_leak_findings
  ADD COLUMN IF NOT EXISTS project_id BIGINT NOT NULL DEFAULT 0;

UPDATE github_leak_findings f
   SET project_id = p.id
  FROM projects p
 WHERE f.project_id = 0
   AND f.rule_name LIKE p.name || ':%';

CREATE INDEX IF NOT EXISTS github_leak_findings_project_idx
  ON github_leak_findings(project_id, last_seen_at DESC);

-- 同一仓库/路径/密钥若被多个项目规则命中，应各自保留一条，
-- 因此唯一键必须包含 project_id。
DROP INDEX IF EXISTS github_leak_findings_identity_idx;
CREATE UNIQUE INDEX IF NOT EXISTS github_leak_findings_identity_idx
  ON github_leak_findings(project_id, repository, path, blob_sha, keyword,
                          secret_type, line_number, fingerprint);
