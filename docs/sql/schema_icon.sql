-- 图标域增量：字节入库（ScopesHub 复刻 G3 收尾）
-- 前置：schema_governance.sql（asset_icons 已有 sha256 / mmh3 / object_path / thumb_path）
-- 选择：图标字节直接进 bytea，不走文件系统。
--       理由是部署只有一个库、一个进程，落盘反而多一层「目录不存在/权限/清理」的失败面。
--       object_path 保留为空，将来要接对象存储时再迁。

BEGIN;

ALTER TABLE asset_icons ADD COLUMN IF NOT EXISTS data bytea;

-- sites 上只有 icon_sha256（TEXT），没有存 mmh3 的列。
-- icon_hash 查询要按 mmh3 比对（对齐外部资产库），所以在站点上落一份，
-- 免得每次查询都去 join asset_icons。
ALTER TABLE sites ADD COLUMN IF NOT EXISTS icon_mmh3 bigint;
CREATE INDEX IF NOT EXISTS sites_icon_idx ON sites (icon_sha256);

-- 缩略图暂时不做，保留列以免以后改表
COMMENT ON COLUMN asset_icons.data IS '图标原始字节；object_path 为空时从这里读';

INSERT INTO schema_migrations (name) VALUES ('schema_icon')
ON CONFLICT (name) DO NOTHING;

COMMIT;
