package repo

import "testing"

func TestSortByRiskScoreDescThenIDDesc(t *testing.T) {
	rows := []riskOrder{
		{ID: 1, Score: 40},
		{ID: 3, Score: 90},
		{ID: 2, Score: 40},
		{ID: 4, Score: 90},
	}
	sortByRisk(rows)

	want := []int64{4, 3, 2, 1}
	for i, id := range want {
		if rows[i].ID != id {
			t.Fatalf("第 %d 位期望 id=%d，实际 %d（完整顺序 %+v）", i, id, rows[i].ID, rows)
		}
	}
}

func TestNormalizeSortFallsBack(t *testing.T) {
	cases := map[string]string{
		"risk":     "risk",
		"priority": "risk",
		"":         "",
		"RISK":     "",
		"bogus":    "",
	}
	for in, want := range cases {
		if got := normalizeSort(in); got != want {
			t.Fatalf("normalizeSort(%q)=%q，期望 %q", in, got, want)
		}
	}
}

func TestComputeSiteRiskUsesObservations(t *testing.T) {
	empty := riskInputRow{Host: "quiet.example.com"}
	emptyScore, emptyLevel, emptyFactors := computeSiteRisk(empty, vulnStat{})
	if len(emptyFactors) != 0 {
		t.Fatalf("无观测输入不应产生因子: %+v", emptyFactors)
	}

	risky := riskInputRow{
		Host:       "redis.example.com",
		Title:      "管理后台",
		Ports:      []int{6379},
		HTTPStatus: 200,
		State:      "reachable",
	}
	riskyScore, riskyLevel, riskyFactors := computeSiteRisk(risky, vulnStat{})
	if riskyScore <= emptyScore {
		t.Fatalf("有高危端口/后台语义的资产分数应更高: %d vs %d", riskyScore, emptyScore)
	}
	if riskyLevel == "p4" || emptyLevel != "p4" {
		t.Fatalf("档位不符合预期: risky=%s empty=%s", riskyLevel, emptyLevel)
	}
	var hasExposure, hasConsole bool
	for _, f := range riskyFactors {
		if f.Factor == "exposure" && f.Points > 0 {
			hasExposure = true
		}
		if f.Factor == "admin_console" && f.Points > 0 {
			hasConsole = true
		}
	}
	if !hasExposure {
		t.Fatalf("应暴露暴露面因子: %+v", riskyFactors)
	}
	if !hasConsole {
		t.Fatalf("应暴露管理后台因子: %+v", riskyFactors)
	}

	withVuln, withVulnLevel, withVulnFactors := computeSiteRisk(risky, vulnStat{Severity: 5, Count: 1})
	if withVuln < riskyScore {
		t.Fatalf("关联 critical 漏洞后分数下降: %d -> %d", riskyScore, withVuln)
	}
	if levelRankForTest(withVulnLevel) > levelRankForTest(riskyLevel) {
		t.Fatalf("关联 critical 漏洞后档位变差: %s -> %s", riskyLevel, withVulnLevel)
	}
	var hasVuln bool
	for _, f := range withVulnFactors {
		if f.Factor == "vuln" && f.Points == 25 {
			hasVuln = true
		}
	}
	if !hasVuln {
		t.Fatalf("应暴露漏洞实证因子: %+v", withVulnFactors)
	}
}

func levelRankForTest(level string) int {
	switch level {
	case "p0":
		return 0
	case "p1":
		return 1
	case "p2":
		return 2
	case "p3":
		return 3
	default:
		return 4
	}
}
