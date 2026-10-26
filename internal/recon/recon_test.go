package recon_test

import (
	"testing"

	"github.com/c1ayooo/4zreark/internal/recon/fingerprint"
	"github.com/c1ayooo/4zreark/internal/recon/saasdetect"
)

// TestEmbeddedResources guards the self-contained assets: the dddd snapshot and
// seed rules are embedded in fingerprint, and the SaaS table is embedded in
// saasdetect. Neither may depend on the process working directory.
func TestEmbeddedResources(t *testing.T) {
	if n := len(fingerprint.DefaultRules()); n == 0 {
		t.Fatal("fingerprint.DefaultRules() returned no rules")
	}
	m, err := saasdetect.LoadBuiltin()
	if err != nil {
		t.Fatalf("saasdetect.LoadBuiltin(): %v", err)
	}
	if _, ok := m.Match("foo.slack.com"); !ok {
		t.Fatal("saasdetect builtin table did not match a known SaaS domain")
	}
}
