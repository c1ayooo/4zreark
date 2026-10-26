-- 证书到期监测：TLS NotAfter 落到站点行，供到期检测循环与资产详情展示。
-- 运行一次；后端启动时另有 ADD COLUMN IF NOT EXISTS 兜底（repo/site_governance_repo.go）。
ALTER TABLE sites ADD COLUMN IF NOT EXISTS cert_not_after TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_sites_cert_expiry ON sites (cert_not_after) WHERE cert_not_after IS NOT NULL;
