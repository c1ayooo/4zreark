package repo

import "testing"

func TestWebSurfaceFlags(t *testing.T) {
	cases := []struct {
		title   string
		def     bool
		dir     bool
		errPage bool
	}{
		{"Welcome to OpenResty!", true, false, false},
		{"Index of /backup", false, true, false},
		{"Whitelabel Error Page", false, false, true},
		{"phpinfo()", false, false, true},
		{"美团酒店EBooking", false, false, false},
	}
	for _, c := range cases {
		def, dir, errPage := webSurfaceFlags(c.title)
		if def != c.def || dir != c.dir || errPage != c.errPage {
			t.Fatalf("webSurfaceFlags(%q)=%v/%v/%v，期望 %v/%v/%v",
				c.title, def, dir, errPage, c.def, c.dir, c.errPage)
		}
	}
}
