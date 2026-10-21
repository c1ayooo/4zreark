package repo

import (
	"context"
)

// UpdateSiteObservations 记录一次成功探测得到的关系层观测值：
// TLS 证书指纹与跳转后的最终 host。空值不覆盖已有值——
// 一次没跳到别处，不能把之前记录的跳转关系清掉。
func (a *AssetRepo) UpdateSiteObservations(ctx context.Context, siteID int64, certSHA256, finalHost string) error {
	if a == nil || a.r == nil {
		return errUninitialized()
	}
	if certSHA256 == "" && finalHost == "" {
		return nil
	}
	_, err := a.r.pool.Exec(ctx, `
UPDATE sites SET
    cert_sha256 = CASE WHEN $2 <> '' THEN $2 ELSE cert_sha256 END,
    final_host  = CASE WHEN $3 <> '' THEN $3 ELSE final_host END
 WHERE id = $1`, siteID, certSHA256, finalHost)
	return err
}
