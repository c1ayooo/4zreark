package repo

import "testing"

// siteColumns 与 scanSite 的顺序必须严格一致：新增 coalesce(s.url,”) 后，
// 第 9 列必须落到 Site.URL，否则整张资产表的所有字段都会错位。
func TestScanSiteURLColumnOrder(t *testing.T) {
	var gotLen int
	site, err := scanSite(func(dest ...any) error {
		gotLen = len(dest)
		if gotLen != 41 {
			t.Fatalf("scanSite 列数 = %d，期望 41（新增 url 后）", gotLen)
		}
		*(dest[8].(*string)) = "https://unit.example.com"
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if site.URL != "https://unit.example.com" {
		t.Fatalf("第 9 列未映射到 Site.URL: %q", site.URL)
	}
	if site.Host != "" || site.Value != "" {
		t.Fatalf("相邻字段不应被 url 值污染: host=%q value=%q", site.Host, site.Value)
	}
}
