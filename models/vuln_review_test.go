package models

import "testing"

// 复核状态机：流转表必须精确，错一步就会出现"误报改成已修复"这种无法追溯的结论。
func TestVulnTransitionAllowed(t *testing.T) {
	cases := []struct {
		from, to VulnStatus
		want     bool
	}{
		{VulnStatusNew, VulnStatusConfirmed, true},
		{VulnStatusNew, VulnStatusFixed, true},
		{VulnStatusNew, VulnStatusFalse, true},
		{VulnStatusNew, VulnStatusIgnored, true},
		{VulnStatusNew, VulnStatusNew, false},

		{VulnStatusConfirmed, VulnStatusNew, true},
		{VulnStatusConfirmed, VulnStatusFixed, true},
		{VulnStatusConfirmed, VulnStatusFalse, true},
		{VulnStatusConfirmed, VulnStatusIgnored, true},
		{VulnStatusConfirmed, VulnStatusConfirmed, false},

		// 终态之间不得互相流转。
		{VulnStatusFixed, VulnStatusConfirmed, false},
		{VulnStatusFixed, VulnStatusFalse, false},
		{VulnStatusFixed, VulnStatusIgnored, false},
		{VulnStatusFixed, VulnStatusNew, true},

		{VulnStatusFalse, VulnStatusFixed, false},
		{VulnStatusFalse, VulnStatusConfirmed, false},
		{VulnStatusFalse, VulnStatusNew, true},

		{VulnStatusIgnored, VulnStatusFixed, false},
		{VulnStatusIgnored, VulnStatusNew, true},

		// 非法目标状态一律拒绝。
		{VulnStatusNew, VulnStatus("nope"), false},
		{VulnStatusNew, VulnStatus(""), false},
	}
	for _, c := range cases {
		if got := VulnTransitionAllowed(c.from, c.to); got != c.want {
			t.Errorf("VulnTransitionAllowed(%s -> %s) = %v，期望 %v", c.from, c.to, got, c.want)
		}
	}
}

func TestValidVulnStatus(t *testing.T) {
	for _, s := range []VulnStatus{VulnStatusNew, VulnStatusConfirmed, VulnStatusFixed, VulnStatusIgnored, VulnStatusFalse} {
		if !ValidVulnStatus(s) {
			t.Errorf("%s 应合法", s)
		}
	}
	for _, s := range []VulnStatus{"", "open", "reopened", "NEW"} {
		if ValidVulnStatus(s) {
			t.Errorf("%q 应非法", s)
		}
	}
}

func TestVulnStatusLabel(t *testing.T) {
	want := map[VulnStatus]string{
		VulnStatusNew:       "待复核",
		VulnStatusConfirmed: "已确认",
		VulnStatusFixed:     "已修复",
		VulnStatusIgnored:   "已忽略",
		VulnStatusFalse:     "误报",
	}
	for s, label := range want {
		if got := VulnStatusLabel(s); got != label {
			t.Errorf("VulnStatusLabel(%s) = %q，期望 %q", s, got, label)
		}
	}
}
