package githubleak

import (
	"strings"
	"testing"
	"time"
)

func TestBuildListWhereSupportsFindingDeepLinks(t *testing.T) {
	// strpos 语义：包含匹配（无 LIKE 通配符转义），参数小写化
	filter := ListFilter{Query: `finding%_id`}
	where, args := buildListWhere(filter)
	if !strings.Contains(where, `LOWER(id||' '||fingerprint||' '||repository`) {
		t.Fatalf("query fields do not include id and fingerprint: %s", where)
	}
	if len(args) != 1 || args[0] != `finding%_id` {
		t.Fatalf("query argument = %#v", args)
	}
	if !strings.Contains(where, "strpos(") {
		t.Fatalf("expected strpos containment match: %s", where)
	}
}

func TestValidateCandidateUsesTrustedURLLine(t *testing.T) {
	rule, err := newKeywordRule([]string{"storage-service", "vendor.example"})
	if err != nil {
		t.Fatal(err)
	}
	base := Candidate{
		Keyword:       rule.Query,
		Repository:    "owner/repo",
		Path:          "config.env",
		BlobSHA:       strings.Repeat("a", 40),
		Line:          12,
		SecretType:    "github_token",
		Confidence:    "likely",
		Severity:      "critical",
		Fingerprint:   strings.Repeat("b", 64),
		MaskedExcerpt: "token=<redacted:github_token>",
		HTMLURL:       "https://github.com/owner/repo/blob/main/config.env#L12",

		SourceUpdatedAt: time.Now().UTC(),
	}
	if _, err = validateCandidate(base); err != nil {
		t.Fatalf("valid candidate rejected: %v", err)
	}
	mismatched := base
	mismatched.Line = 13
	if _, err := validateCandidate(mismatched); err == nil {
		t.Fatal("candidate accepted a line not supported by its GitHub URL")
	}
	invalidSHA := base
	invalidSHA.BlobSHA = strings.Repeat("z", 40)
	if _, err := validateCandidate(invalidSHA); err == nil {
		t.Fatal("candidate accepted a non-hex blob SHA")
	}
}

func TestSafeErrorMasksCredentialLikeValues(t *testing.T) {
	raw := "Ab9/7Kp2_Qx4-Zm8+Rt6"
	got := safeError("upstream client_secret=" + raw + " failed")
	if strings.Contains(got, raw) || !strings.Contains(got, "<redacted:oauth_client_secret>") {
		t.Fatalf("error was not safely redacted: %q", got)
	}
}
