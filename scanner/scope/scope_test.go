package scope

import "testing"

func TestScope(t *testing.T) {
	s := New([]string{"example.com", "10.0.0.0/24", "192.0.2.10", "https://api.other.test/x"})

	cases := map[string]bool{
		"example.com":                  true,
		"www.example.com":              true,
		"a.b.example.com":              true,
		"notexample.com":               false,
		"10.0.0.9":                     true,
		"10.0.1.9":                     false,
		"192.0.2.10":                   true,
		"192.0.2.11":                   false,
		"api.other.test":               true,
		"other.test":                   false,
		"https://x.example.com:8443/a": true,
	}
	for host, want := range cases {
		if got := s.AllowsURL(host); got != want {
			t.Fatalf("AllowsURL(%q)=%v，期望 %v", host, got, want)
		}
	}
}

func TestEmptyScopeAllows(t *testing.T) {
	s := New(nil)
	if !s.AllowsHost("anything.test") {
		t.Fatal("空 scope 应放行")
	}
}
