package githubsearch

import "testing"

func TestTemplatesAndBuildQuery(t *testing.T) {
	if len(Templates()) == 0 {
		t.Fatal("built-in dork templates are empty")
	}
	tpl, ok := TemplateByID("org-aws")
	if !ok {
		t.Fatal("org-aws template missing")
	}
	if got := BuildQuery(tpl, "target-org", ""); got != "org:target-org AKIA" {
		t.Fatalf("unexpected query: %q", got)
	}
	if _, ok := TemplateByID("no-such-template"); ok {
		t.Fatal("unknown template must not resolve")
	}
}
