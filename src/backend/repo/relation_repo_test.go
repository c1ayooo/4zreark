package repo

import "testing"

func TestBuildRelationPairs(t *testing.T) {
	rec1, rec2, rec4, rec5, rec7 := int64(101), int64(102), int64(104), int64(105), int64(107)
	sites := []relationSite{
		{ID: 1, ProjectID: 1, Host: "a.example.com", IP: "10.0.0.1", Tech: []string{"nginx"}, RecordID: &rec1},
		{ID: 2, ProjectID: 1, Host: "b.example.com", IP: "10.0.0.1", RecordID: &rec2},
		{ID: 3, ProjectID: 1, Host: "c.example.com", IP: "10.0.0.1"}, // 无原始记录 -> 不出边
		{ID: 4, ProjectID: 1, Host: "www.example.com", RecordID: &rec4},
		{ID: 5, ProjectID: 1, Host: "example.com", RecordID: &rec5},
		{ID: 6, ProjectID: 2, Host: "x.example.com", IP: "10.0.0.1", RecordID: &rec2}, // 跨项目
		{ID: 7, ProjectID: 1, Host: "api.example.com", Tech: []string{"nginx"}, RecordID: &rec7},
	}

	pairs := buildRelationPairs(sites)
	type key struct {
		typ         string
		left, right int64
	}
	got := map[key]relationPair{}
	for _, p := range pairs {
		if p.Left.ID >= p.Right.ID {
			t.Fatalf("关系方向错误: %+v", p)
		}
		if p.Left.RecordID == nil || p.Right.RecordID == nil {
			t.Fatalf("关系缺少证据: %+v", p)
		}
		got[key{p.Type, p.Left.ID, p.Right.ID}] = p
	}

	want := []key{
		{"same_ip", 1, 2},
		{"same_c_segment", 1, 2}, // 10.0.0.1 与 10.0.0.1 同 /24
		{"same_fp", 1, 7},
		{"domain_parent", 1, 5}, // a.example.com -> example.com
		{"domain_parent", 2, 5}, // b.example.com -> example.com
		{"domain_parent", 4, 5}, // www.example.com -> example.com
		{"domain_parent", 5, 7}, // api.example.com -> example.com
	}
	for _, k := range want {
		if _, ok := got[k]; !ok {
			t.Fatalf("缺少关系 %+v（实际 %v）", k, got)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("关系数量不符: 实际 %d，期望 %d（%v）", len(got), len(want), got)
	}
	// 无原始记录的 c.example.com 不能出现在 same_ip 边里
	for k := range got {
		if k.typ == "same_ip" && (k.left == 3 || k.right == 3) {
			t.Fatalf("无证据站点不应参与关系: %+v", k)
		}
	}
}

func TestCSegment(t *testing.T) {
	cases := []struct {
		ip   string
		want string
	}{
		{"10.0.1.5", "10.0.1."},
		{"192.168.100.200", "192.168.100."},
		{"2001:db8::1", ""},
		{"", ""},
		{"10.0.1", ""},
	}
	for _, c := range cases {
		if got := cSegment(c.ip); got != c.want {
			t.Errorf("cSegment(%q) = %q，期望 %q", c.ip, got, c.want)
		}
	}
}

// 证书 / C 段 / 跳转三类边：都要求两侧都有 raw_record，且不出现"跳回自身"。
func TestBuildRelationPairsObservations(t *testing.T) {
	rec1, rec2 := int64(201), int64(202)
	sites := []relationSite{
		{ID: 1, ProjectID: 1, Host: "a.test", IP: "10.0.1.5", IconSHA256: "icon-1",
			CertSHA256: "cert-1", Tech: []string{"nginx"}, FinalHost: "b.test", RecordID: &rec1},
		{ID: 2, ProjectID: 1, Host: "b.test", IP: "10.0.1.5", IconSHA256: "icon-1",
			CertSHA256: "cert-1", Tech: []string{"nginx"}, RecordID: &rec2},
		{ID: 3, ProjectID: 1, Host: "c.test", IP: "10.0.1.9", RecordID: nil}, // 无证据
	}

	got := map[string]int{}
	for _, p := range buildRelationPairs(sites) {
		got[p.Type]++
		if p.Left.ID >= p.Right.ID {
			t.Errorf("边方向错误: %s %d->%d", p.Type, p.Left.ID, p.Right.ID)
		}
		if p.Left.ID == 3 || p.Right.ID == 3 {
			t.Errorf("无证据站点不应出边: %s", p.Type)
		}
	}
	for _, typ := range []string{"same_ip", "same_c_segment", "same_cert", "same_icon", "same_fp", "redirect"} {
		if got[typ] == 0 {
			t.Errorf("缺少关系类型 %s（实际 %v）", typ, got)
		}
	}
}

// 跳回自身不建边：final_host == host 时没有信息量。
func TestBuildRelationPairsSelfRedirectSkipped(t *testing.T) {
	rec1 := int64(301)
	sites := []relationSite{
		{ID: 1, ProjectID: 1, Host: "a.test", IP: "10.0.3.1", FinalHost: "a.test", RecordID: &rec1},
	}
	for _, p := range buildRelationPairs(sites) {
		if p.Type == "redirect" {
			t.Error("跳回自身不应产生 redirect 边")
		}
	}
}
