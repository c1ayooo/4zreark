-- 关系层补两列观测值：TLS 证书指纹与跳转后的最终 host。
-- 同证书边（same_cert）、C 段边（same_c_segment）、跳转边（redirect）都从这两列与 sites.ip 推导。
BEGIN;
ALTER TABLE sites ADD COLUMN IF NOT EXISTS cert_sha256 text;
ALTER TABLE sites ADD COLUMN IF NOT EXISTS final_host text;

ALTER TABLE relations DROP CONSTRAINT IF EXISTS relations_type_chk;
ALTER TABLE relations ADD CONSTRAINT relations_type_chk CHECK (
    type = ANY (ARRAY[
        'domain_parent', 'same_ip', 'same_cert', 'same_icon', 'same_fp',
        'cname', 'redirect', 'same_c_segment'
    ]::text[])
);

INSERT INTO schema_migrations (name) VALUES ('migration_relation_observations')
ON CONFLICT (name) DO NOTHING;
COMMIT;
