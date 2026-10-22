package repo

import (
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/internal/fpscore"
)

func fpScoreRowFor(id int64, host string, hits []fpscore.Hit) *FpScore {
	res := fpscore.Compute(hits)
	tech := []string{}
	for _, h := range hits {
		if h.Source == fpscore.SourceTech {
			tech = append(tech, h.Name)
		}
	}
	return &FpScore{
		ID: id, Host: host, Value: host, Tech: tech,
		Categories: res.Categories, Score: res.Score, Level: res.Level,
		Matches: res.Matches, LastSeen: time.Now(),
	}
}

func TestPaginateFpScoresSortsByScoreThenHost(t *testing.T) {
	rows := []*FpScore{
		fpScoreRowFor(1, "a.example.com", nil),                                                      // 0 分
		fpScoreRowFor(2, "b.example.com", []fpscore.Hit{{Name: "OA", Category: "OA"}}),              // 40
		fpScoreRowFor(3, "c.example.com", []fpscore.Hit{{Name: "OA2", Category: "OA"}}),             // 40 同分
		fpScoreRowFor(4, "d.example.com", []fpscore.Hit{{Name: "FW", Category: "Security-Device"}}), // 55
	}

	items, total := paginateFpScores(rows, FpScoreQuery{Page: 1, PageSize: 10})
	if total != 4 {
		t.Fatalf("total=%d，期望 4", total)
	}
	wantHosts := []string{"d.example.com", "b.example.com", "c.example.com", "a.example.com"}
	for i, want := range wantHosts {
		if items[i].Host != want {
			t.Fatalf("第 %d 位期望 %s，实际 %s", i, want, items[i].Host)
		}
	}

	// 分页切片：取第二页只应剩下两条
	page2, total2 := paginateFpScores(rows, FpScoreQuery{Page: 2, PageSize: 2})
	if total2 != 4 || len(page2) != 2 || page2[0].Host != "c.example.com" {
		t.Fatalf("第二页不符合预期: %+v", page2)
	}
}

func TestPaginateFpScoresFilters(t *testing.T) {
	rows := []*FpScore{
		fpScoreRowFor(1, "a.example.com", nil),
		fpScoreRowFor(2, "b.example.com", []fpscore.Hit{{Name: "FW", Category: "Security-Device"}}),
		fpScoreRowFor(3, "c.example.com", []fpscore.Hit{{Name: "Nginx", Category: "Web-Server"}}),
	}

	cases := []struct {
		name      string
		q         FpScoreQuery
		wantHosts []string
	}{
		{name: "按档位 high", q: FpScoreQuery{Level: "high"}, wantHosts: nil},
		{name: "按档位 none", q: FpScoreQuery{Level: "none"}, wantHosts: []string{"a.example.com"}},
		{name: "分数下限", q: FpScoreQuery{MinScore: 30}, wantHosts: []string{"b.example.com"}},
		{name: "分数上限", q: FpScoreQuery{MaxScore: 10}, wantHosts: []string{"c.example.com", "a.example.com"}},
		{name: "分类筛选", q: FpScoreQuery{Category: "Security-Device"}, wantHosts: []string{"b.example.com"}},
		{name: "分类大小写不敏感", q: FpScoreQuery{Category: "security-device"}, wantHosts: []string{"b.example.com"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.q.Page, tc.q.PageSize = 1, 10
			items, _ := paginateFpScores(rows, tc.q)
			if len(items) != len(tc.wantHosts) {
				t.Fatalf("命中 %d 条，期望 %d 条: %+v", len(items), len(tc.wantHosts), items)
			}
			for i, want := range tc.wantHosts {
				if items[i].Host != want {
					t.Fatalf("第 %d 位期望 %s，实际 %s", i, want, items[i].Host)
				}
			}
		})
	}
}

func TestPaginateFpScoresSortModes(t *testing.T) {
	rows := []*FpScore{
		fpScoreRowFor(1, "z.example.com", []fpscore.Hit{{Name: "Nginx", Category: "Web-Server"}}),
		fpScoreRowFor(2, "a.example.com", []fpscore.Hit{{Name: "OA", Category: "OA"}, {Name: "Nginx", Category: "Web-Server"}}),
	}

	byHost, _ := paginateFpScores(rows, FpScoreQuery{Page: 1, PageSize: 10, Sort: "host"})
	if byHost[0].Host != "a.example.com" {
		t.Fatalf("按主机名排序应升序: %+v", byHost)
	}
	byAssets, _ := paginateFpScores(rows, FpScoreQuery{Page: 1, PageSize: 10, Sort: "assets"})
	if byAssets[0].Host != "a.example.com" {
		t.Fatalf("按指纹数排序应把两条命中的资产放前面: %+v", byAssets)
	}
}

func TestBuildFpScoreFacets(t *testing.T) {
	rows := []*FpScore{
		fpScoreRowFor(1, "a.example.com", nil),
		fpScoreRowFor(2, "b.example.com", []fpscore.Hit{{Name: "FW", Category: "Security-Device"}}),
		fpScoreRowFor(3, "c.example.com", []fpscore.Hit{{Name: "FW2", Category: "Security-Device"}}),
		fpScoreRowFor(4, "d.example.com", []fpscore.Hit{{Name: "Nginx", Category: "Web-Server"}}),
	}
	f := buildFpScoreFacets(rows)

	if f.Total != 4 || f.Scored != 3 {
		t.Fatalf("总数/有分数数不符合预期: %+v", f)
	}
	band := map[string]int64{}
	for _, b := range f.Bands {
		band[b.Level] = b.Count
	}
	if band[fpscore.LevelNone] != 1 || band[fpscore.LevelMedium] != 2 || band[fpscore.LevelLow] != 1 {
		t.Fatalf("分档计数错误: %+v", band)
	}
	if len(f.Categories) != 2 || f.Categories[0].Name != "security-device" || f.Categories[0].AssetCnt != 2 {
		t.Fatalf("分类计数应按资产数倒序: %+v", f.Categories)
	}
	if f.Categories[0].Label != "安防设备" {
		t.Fatalf("分类应带中文展示名: %+v", f.Categories[0])
	}
	if len(f.Fingerprints) != 3 {
		t.Fatalf("指纹计数应覆盖全部命中: %+v", f.Fingerprints)
	}
	wantAvg := (0 + 55 + 55 + 10 + 2) / 4 // 四舍五入到整数
	if f.AvgScore != wantAvg {
		t.Fatalf("平均分=%d，期望 %d", f.AvgScore, wantAvg)
	}
}

func TestNormalizeFpQueryInputs(t *testing.T) {
	if got := normalizeFpLevel("High"); got != "high" {
		t.Fatalf("normalizeFpLevel(High)=%q，期望 high", got)
	}
	if got := normalizeFpLevel("bogus"); got != "" {
		t.Fatalf("非法档位应回落空值，实际 %q", got)
	}
	min, max := normalizeFpScoreRange(120, -5)
	if min != 100 || max != 0 {
		t.Fatalf("normalizeFpScoreRange=(%d,%d)，期望 (100,0)", min, max)
	}
}

func TestBuildFpScore(t *testing.T) {
	s := buildFpScore(fpScoreRow{
		ID: 7, Host: "fw.example.com", Value: "https://fw.example.com",
		Title: "防火墙", HTTPStatus: 200, State: "reachable",
		Tech:      []byte(`["Nginx"]`),
		RuleNames: []byte(`[["Sangfor-Firewall","Security-Device"]]`),
		LastSeen:  time.Now(),
	})
	if s.Score != 60 || s.Level != fpscore.LevelMedium {
		t.Fatalf("评分=%d 档位=%s，期望 60/medium", s.Score, s.Level)
	}
	if len(s.Matches) != 2 || s.Matches[0].Name != "Sangfor-Firewall" {
		t.Fatalf("命中明细应按分值倒序: %+v", s.Matches)
	}
	if len(s.Categories) != 2 || !hasCategory(s.Categories, "Security-Device") || !hasCategory(s.Categories, "Web-Server") {
		t.Fatalf("分类应同时包含规则分类与技术栈推断分类: %+v", s.Categories)
	}
	if len(s.Tech) != 1 || s.Tech[0] != "Nginx" {
		t.Fatalf("技术栈应原样保留: %+v", s.Tech)
	}
}

func TestBuildFpScoreHandlesNullJSONB(t *testing.T) {
	s := buildFpScore(fpScoreRow{ID: 8, Host: "h", Tech: []byte("null"), RuleNames: []byte("null")})
	if s.Score != 0 || s.Level != fpscore.LevelNone || len(s.Tech) != 0 {
		t.Fatalf("空指纹应得 0 分: %+v", s)
	}
}
