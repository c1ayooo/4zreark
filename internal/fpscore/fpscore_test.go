package fpscore

import "testing"

func TestComputeLevels(t *testing.T) {
	cases := []struct {
		name      string
		hits      []Hit
		wantScore int
		wantLevel string
	}{
		{name: "无指纹", hits: nil, wantScore: 0, wantLevel: LevelNone},
		{name: "空名称忽略", hits: []Hit{{Name: "  "}}, wantScore: 0, wantLevel: LevelNone},
		{
			name:      "安防设备单指纹",
			hits:      []Hit{{Name: "Sangfor-Firewall", Category: "Security-Device", Source: SourceRule}},
			wantScore: 55,
			wantLevel: LevelMedium,
		},
		{
			name: "高风险产品压过分类分",
			hits: []Hit{{Name: "Jenkins", Category: "Ops-Platform", Source: SourceTech}},
			// 分类 35，产品 55
			wantScore: 55,
			wantLevel: LevelMedium,
		},
		{
			name: "多指纹半量叠加封顶",
			hits: []Hit{
				{Name: "H3C-Firewall", Category: "Security-Device"},
				{Name: "OA-System", Category: "OA"},
				{Name: "HZERO", Category: "Java-Framework"},
			},
			// 55 + 40/2 + 25/2 = 87
			wantScore: 87,
			wantLevel: LevelHigh,
		},
		{
			name: "普通技术栈低分",
			hits: []Hit{
				{Name: "Nginx", Category: "Web-Server", Source: SourceTech},
				{Name: "React", Category: "JavaScript-Framework", Source: SourceTech},
			},
			// 10 + 10/2
			wantScore: 15,
			wantLevel: LevelLow,
		},
		{
			name:      "未知分类按缺省分",
			hits:      []Hit{{Name: "Custom-App", Category: "Something-Else"}},
			wantScore: defaultCategoryPoints,
			wantLevel: LevelLow,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Compute(tc.hits)
			if got.Score != tc.wantScore || got.Level != tc.wantLevel {
				t.Fatalf("Compute() = (%d, %s)，期望 (%d, %s)；明细 %+v",
					got.Score, got.Level, tc.wantScore, tc.wantLevel, got.Matches)
			}
			if got.Matches == nil || got.Categories == nil {
				t.Fatalf("结果切片不能为 nil: %+v", got)
			}
		})
	}
}

func TestComputeDedupesAndSorts(t *testing.T) {
	got := Compute([]Hit{
		{Name: "Nginx", Category: "Web-Server", Source: SourceTech},
		{Name: "nginx", Category: "Web-Server", Source: SourceRule},
		{Name: "Jenkins", Source: SourceRule},
	})
	if len(got.Matches) != 2 {
		t.Fatalf("重名指纹应去重，实际 %d 条: %+v", len(got.Matches), got.Matches)
	}
	if got.Matches[0].Name != "Jenkins" {
		t.Fatalf("分值最高的命中应排第一，实际 %+v", got.Matches)
	}
	// 55 + 10/2 = 60
	if got.Score != 60 || got.Level != LevelMedium {
		t.Fatalf("评分不符合预期: %+v", got)
	}
}

func TestComputeRuleHitUpgradesTechHit(t *testing.T) {
	got := Compute([]Hit{
		{Name: "Jenkins", Source: SourceTech},                           // 先出现的通用技术栈，6 分
		{Name: "jenkins", Category: "Ops-Platform", Source: SourceRule}, // 规则命中带分类，应覆盖
	})
	if len(got.Matches) != 1 {
		t.Fatalf("同名指纹应合并成一条: %+v", got.Matches)
	}
	m := got.Matches[0]
	if m.Source != SourceRule || m.Category != "Ops-Platform" || m.Points != 55 {
		t.Fatalf("规则命中应覆盖技术栈命中: %+v", m)
	}
	if len(got.Categories) != 1 || got.Categories[0] != "Ops-Platform" {
		t.Fatalf("分类应来自规则: %+v", got.Categories)
	}
}

func TestNormalizeCategory(t *testing.T) {
	cases := map[string]string{
		"Security-Device":    "security-device",
		"Video Surveillance": "video-surveillance",
		"video_surveillance": "video-surveillance",
		"  OA  ":             "oa",
	}
	for in, want := range cases {
		if got := normalizeCategory(in); got != want {
			t.Fatalf("normalizeCategory(%q)=%q，期望 %q", in, got, want)
		}
	}
}

func TestLevelBounds(t *testing.T) {
	cases := map[int]string{
		0: LevelNone, 1: LevelLow, 39: LevelLow,
		40: LevelMedium, 69: LevelMedium,
		70: LevelHigh, 100: LevelHigh,
	}
	for score, want := range cases {
		if got := Level(score); got != want {
			t.Fatalf("Level(%d)=%s，期望 %s", score, got, want)
		}
	}
}
