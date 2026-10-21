package componentprofile

import "testing"

func TestMineCVEEdges(t *testing.T) {
	templates := []TemplateIndexEntry{
		{ID: "CVE-2024-0001", Tech: "apache tomcat", CVEs: []string{"cve-2024-0001"}},
		{ID: "CVE-2024-0002", Tech: "nginx", CVEs: []string{"CVE-2024-0002"}},
		{ID: "no-tech", Tech: "", CVEs: []string{"CVE-2024-0003"}},
	}
	profiles := []Profile{
		{Product: "apache-tomcat", DisplayName: "Apache Tomcat"},
		{Product: "nginx", DisplayName: "nginx"},
	}
	edges := MineCVEEdges(templates, profiles)
	if len(edges) != 2 {
		t.Fatalf("期望 2 条边，实际 %d: %+v", len(edges), edges)
	}
	if edges[0].Kind != KindCVE || edges[0].Review != ReviewAuto || edges[0].Source != SourceNucleiCVE {
		t.Fatalf("边字段不符: %+v", edges[0])
	}
}

func TestParseTemplateIndex(t *testing.T) {
	raw := []byte(`{"templates":[{"id":"x","tech":"WordPress","cves":["CVE-2024-1"]}]}`)
	got, err := ParseTemplateIndex(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Tech != "WordPress" {
		t.Fatalf("解析结果不符: %+v", got)
	}
}
