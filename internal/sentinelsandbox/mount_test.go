package sentinelsandbox

import "testing"

func TestPocMountSource(t *testing.T) {
	cases := []struct {
		name     string
		workdir  string
		source   string
		expected string
	}{
		{"宿主机直跑用 workdir", "/var/lib/pocsmith", "", "/var/lib/pocsmith"},
		{"DooD 用命名卷", "/poc", "zreark_pocsmith_work", "zreark_pocsmith_work"},
		{"空白 source 回退 workdir", "/poc", "   ", "/poc"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := pocMountSource(c.workdir, c.source); got != c.expected {
				t.Fatalf("pocMountSource(%q, %q) = %q, want %q", c.workdir, c.source, got, c.expected)
			}
		})
	}
}
