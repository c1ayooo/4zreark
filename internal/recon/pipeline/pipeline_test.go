package pipeline

import "testing"

func TestSubsetOf(t *testing.T) {
	baseline := map[string]bool{"10.0.0.1": true, "10.0.0.2": true}
	if !subsetOf([]string{"10.0.0.1"}, baseline) {
		t.Fatal("single baseline IP should be a subset")
	}
	if subsetOf([]string{"10.0.0.1", "10.0.0.9"}, baseline) {
		t.Fatal("non-baseline IP must break the subset")
	}
	if subsetOf(nil, baseline) {
		t.Fatal("empty set is not a subset for wildcard filtering")
	}
}

func TestParentDomain(t *testing.T) {
	domains := []string{"example.com", "example.org"}
	if got := parentDomain("api.example.com", domains); got != "example.com" {
		t.Fatalf("got %q", got)
	}
	if got := parentDomain("unknown.example.net", domains); got != "example.com" {
		t.Fatalf("fallback should be the first domain, got %q", got)
	}
}
