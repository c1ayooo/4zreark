package score

import "testing"

func baseInput() Input {
	return Input{
		OpenPorts:    []int{80, 443},
		Server:       "nginx/1.24.0",
		Title:        "管理后台",
		Fingerprints: []string{"nginx"},
		HTTPStatus:   200,
		HTTPSeen:     true,
		HasOwner:     true,
	}
}

func TestComputeDeterministic(t *testing.T) {
	in := baseInput()
	first, firstLevel, _ := Compute(in)
	second, secondLevel, _ := Compute(in)
	if first != second || firstLevel != secondLevel {
		t.Fatalf("同一输入两次结果不一致: %d/%s vs %d/%s", first, firstLevel, second, secondLevel)
	}
}

func TestCriticalVulnNeverLowersPriority(t *testing.T) {
	base, baseLevel, _ := Compute(baseInput())

	in := baseInput()
	in.VulnSeverity = 5
	in.VulnCount = 1
	withVuln, vulnLevel, _ := Compute(in)

	if withVuln < base {
		t.Fatalf("加入 critical 漏洞后分数下降: %d -> %d", base, withVuln)
	}
	if levelRank(vulnLevel) > levelRank(baseLevel) {
		t.Fatalf("加入 critical 漏洞后优先级变差: %s -> %s", baseLevel, vulnLevel)
	}
}

func TestLevelCoversAllScores(t *testing.T) {
	valid := map[string]bool{"p0": true, "p1": true, "p2": true, "p3": true, "p4": true}
	seen := map[string]bool{}
	for s := 0; s <= 100; s++ {
		lv := Level(s)
		if !valid[lv] {
			t.Fatalf("分数 %d 映射到非法档位 %q", s, lv)
		}
		seen[lv] = true
	}
	for lv := range valid {
		if !seen[lv] {
			t.Fatalf("0..100 之间没有任何分数落到 %s", lv)
		}
	}
}

func TestWildcardHalvesScore(t *testing.T) {
	base, _, _ := Compute(baseInput())
	in := baseInput()
	in.IsWildcard = true
	halved, _, _ := Compute(in)
	if want := base - base/2; halved != want { // 实现是整数除法后再减，13 -> 7
		t.Fatalf("泛解析应减半: %d -> %d（期望 %d）", base, halved, want)
	}
}

// levelRank 把 p0..p4 变成 0..4，便于比较「优先级是否变差」。
func levelRank(level string) int {
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
