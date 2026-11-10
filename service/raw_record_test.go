package service

import "testing"

// S1/domain_only 阶段的子域没有 URL、status=0，此前被 rawRecordFromScan 静默丢弃，
// 导致结果页有、资产页没有。现在按 host 兜底建站点并标记 dns_only。
func TestRawRecordFromScanDNSOnly(t *testing.T) {
	rec, ok := rawRecordFromScan("", "a.example.com", "https", 0, "", "1.2.3.4", nil)
	if !ok {
		t.Fatal("纯 DNS 子域应生成资产记录")
	}
	if rec.Host != "a.example.com" || rec.Value != "https://a.example.com" {
		t.Fatalf("兜底 URL/Host 不正确: host=%q value=%q", rec.Host, rec.Value)
	}
	if rec.Protocol != "https" || rec.StatusCode != 0 || rec.IP != "1.2.3.4" {
		t.Fatalf("兜底字段不正确: %+v", rec)
	}
	if rec.Evidence["dns_only"] != true || rec.Evidence["verified"] != false {
		t.Fatalf("纯 DNS 记录应标记未验证: %+v", rec.Evidence)
	}
}

// 爬虫路径传 host=""、URL 为空时必须继续拒绝，避免写出无主记录。
func TestRawRecordFromScanRejectsEmpty(t *testing.T) {
	if _, ok := rawRecordFromScan("", "", "https", 0, "", "", nil); ok {
		t.Fatal("无 URL 且无 host 应拒绝")
	}
	if rec, ok := rawRecordFromScan("https://b.example.com/x", "", "https", 200, "", "", nil); !ok || rec.Evidence["dns_only"] != nil {
		t.Fatalf("有 URL 的已探活记录不应被标成 dns_only: ok=%v evidence=%v", ok, rec.Evidence)
	}
}
