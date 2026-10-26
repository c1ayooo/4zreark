package report

import (
	"strings"
	"testing"
)

func TestLookupProfile(t *testing.T) {
	cases := []struct {
		id       string
		wantID   string
		wantType string
		ok       bool
	}{
		{"", "standard", "vuln", true},
		{"standard", "standard", "vuln", true},
		{" SRC ", "src", "vuln", true},
		{"brief", "brief", "vuln", true},
		{"asset-full", "asset-full", "asset", true},
		{"asset-src", "asset-src", "asset", true},
		{"asset-brief", "asset-brief", "asset", true},
		{"nope", "", "", false},
	}
	for _, c := range cases {
		p, ok := LookupProfile(c.id)
		if ok != c.ok {
			t.Fatalf("LookupProfile(%q) ok=%v，期望 %v", c.id, ok, c.ok)
		}
		if !ok {
			continue
		}
		if p.ID != c.wantID || p.Type != c.wantType {
			t.Errorf("LookupProfile(%q) = %s/%s，期望 %s/%s", c.id, p.ID, p.Type, c.wantID, c.wantType)
		}
	}
}

func TestProfilesByType(t *testing.T) {
	vuln := ProfilesByType("vuln")
	if len(vuln) != 3 {
		t.Fatalf("vuln 模板应为 3 套，实际 %d", len(vuln))
	}
	asset := ProfilesByType("asset")
	if len(asset) != 3 {
		t.Fatalf("asset 模板应为 3 套，实际 %d", len(asset))
	}
	for _, p := range asset {
		if p.MaxRows <= 0 {
			t.Errorf("资产模板 %s 必须设置 MaxRows", p.ID)
		}
	}
}

func TestFilterSectionsBySeverity(t *testing.T) {
	vs := []VulnSection{
		{Title: "c", Severity: "critical"},
		{Title: "h", Severity: "high"},
		{Title: "m", Severity: "medium"},
		{Title: "i", Severity: "info"},
	}
	if got := FilterSectionsBySeverity(vs, ""); len(got) != 4 {
		t.Fatalf("空等级过滤应保留全部，实际 %d", len(got))
	}
	if got := FilterSectionsBySeverity(vs, "high"); len(got) != 2 {
		t.Fatalf("high 及以上应为 2 条，实际 %d", len(got))
	}
	if got := FilterSectionsBySeverity(vs, "critical"); len(got) != 1 || got[0].Title != "c" {
		t.Fatalf("critical 过滤结果错误: %+v", got)
	}
}

func TestAssetSectionNumbersContiguous(t *testing.T) {
	p := assetProfiles["asset-full"]
	no := p.SectionNumbers()
	want := []string{"一、", "二、", "三、", "四、", "五、"}
	got := []string{no.Summary, no.Scope, no.Stats, no.Domains, no.Sites}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("章节编号[%d]=%q，期望 %q", i, got[i], want[i])
		}
	}
}

func TestRenderAssetHTMLHidesEmptyListsAndShowsDelivery(t *testing.T) {
	doc := &AssetReport{
		Title:       "示例项目 信息收集报告",
		ProjectName: "示例项目",
		ProjectCode: "demo",
		GeneratedAt: "2026-10-21 12:00:00",
		Range:       "项目全量资产（域名种子 1 条）",
		Delivery: DeliveryInfo{
			ClientName:     "示例客户",
			ReportNo:       "RPT-001",
			Classification: "内部",
		},
		Profile: assetProfiles["asset-full"],
		Summary: AssetSummary{
			Domains: 2, Sites: 3, Endpoints: 4, Reachable: 2, SeedCount: 1,
			FirstSeen: "2026-10-01", LastSeen: "2026-10-21", CollectState: "采集中，周期 30 天",
		},
		Domains: []AssetDomainRow{
			{Host: "example.com", SiteCount: 2, Reachable: 1, IsSeedBase: true},
			{Host: "api.example.com", SiteCount: 1, Reachable: 1},
		},
		Sites: []AssetSiteRow{
			{Host: "example.com", IP: "203.0.113.10", Scheme: "https", Port: 443, State: "reachable", Title: "Home"},
		},
	}
	out, err := RenderAssetHTML(doc)
	if err != nil {
		t.Fatalf("渲染失败: %v", err)
	}
	html := string(out)
	for _, want := range []string{
		"信息收集报告", "示例客户", "RPT-001", "五、站点清单", "example.com", "203.0.113.10",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("HTML 缺少 %q", want)
		}
	}
	if strings.Contains(html, "漏洞明细") {
		t.Error("资产报告不应出现漏洞明细章节")
	}
}

func TestRenderAssetMarkdownRespectsProfile(t *testing.T) {
	doc := &AssetReport{
		Title:       "示例项目 资产简报",
		ProjectName: "示例项目",
		ProjectCode: "demo",
		Range:       "项目全量资产",
		Profile:     assetProfiles["asset-brief"],
		Summary:     AssetSummary{Domains: 1, Sites: 1, CollectState: "采集中"},
		Domains:     []AssetDomainRow{{Host: "example.com", SiteCount: 1, Reachable: 1, IsSeedBase: true}},
		Sites:       []AssetSiteRow{{Host: "example.com", Scheme: "https", Port: 443, State: "reachable"}},
	}
	out, err := RenderAssetMarkdown(doc)
	if err != nil {
		t.Fatalf("渲染失败: %v", err)
	}
	md := string(out)
	for _, want := range []string{"执行摘要", "域名清单", "站点清单", "内部资产简报"} {
		if !strings.Contains(md, want) {
			t.Errorf("Markdown 缺少 %q", want)
		}
	}
}

func TestRenderVulnHTMLOmitsEvidenceForBrief(t *testing.T) {
	doc := &Report{
		Title:       "漏洞简报",
		ProjectName: "示例项目",
		GeneratedAt: "2026-10-21",
		Profile:     vulnProfiles["brief"],
		Stats:       Stats{Total: 1, BySeverity: map[string]int{"high": 1}, TopSeverity: "high"},
		Vulns: []VulnSection{{
			Number: 1, Title: "示例漏洞", Severity: "high", Status: "new",
			EvidencePacket: &EvidenceItem{ID: "ev1", Kind: "http", Title: "报文", ReqText: "GET /"},
		}},
	}
	out, err := RenderHTML(doc)
	if err != nil {
		t.Fatalf("渲染失败: %v", err)
	}
	html := string(out)
	if strings.Contains(html, "报文") || strings.Contains(html, "POC / 证据") {
		t.Error("brief 模板不应渲染证据报文")
	}
	for _, absent := range []string{"事实与未确认线索", "工具执行统计", "攻击链"} {
		if strings.Contains(html, absent) {
			t.Errorf("brief 模板不应出现章节 %q", absent)
		}
	}
}
