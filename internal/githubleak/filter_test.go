package githubleak

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestIsNoisePath(t *testing.T) {
	noise := []string{
		"test/config.env", "tests/main.go", "testdata/keys.json",
		"examples/demo.env", "docs/guide.md", "README.md",
		"internal/app/handler_test.go", "app.test.js", "user.spec.ts",
		"mock-server.py", "fixtures/db.yaml", "sample.env", "example.json",
		"vendor/lib/creds.go", "node_modules/pkg/index.js",
		".github/workflows/ci.yml", "package-lock.json", "go.sum",
		"settings.example.yml", ".env.example", "notes.txt",
	}
	for _, p := range noise {
		if !isNoisePath(p) {
			t.Errorf("isNoisePath(%q) = false, want true", p)
		}
	}
	keep := []string{
		"config.env", "app/config/settings.py", "latest.properties",
		"deploy/production.env", "src/protest/handler.go", "attest/config.yaml",
		"latest.py", "manifesto.md.x", "infrastructure/terraform/main.tf",
	}
	for _, p := range keep {
		if isNoisePath(p) {
			t.Errorf("isNoisePath(%q) = true, want false", p)
		}
	}
}

func TestIsKnownNonSecretValue(t *testing.T) {
	known := []string{
		"sk_test_51H8xQkExampleCharsHere123",
		"django-insecure-abc123",
		"AKIAIOSFODNN7EXAMPLE",
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}
	for _, v := range known {
		if !isKnownNonSecretValue(v) {
			t.Errorf("isKnownNonSecretValue(%q) = false, want true", v)
		}
	}
	if isKnownNonSecretValue("Q7v2Lm9R4x8Nc6Wp3Za5Kd2F") {
		t.Errorf("普通高熵值不应被放行")
	}
}

func TestIsJWTShape(t *testing.T) {
	if !isJWTShape("eyJhbGciOiJIUzI1NiJ9.Q7v2Lm9R4x8N.c6Wp3Za5Kd2F") {
		t.Errorf("标准 JWT 应命中")
	}
	for _, v := range []string{"Q7v2Lm9R4x8Nc6Wp3Za5Kd2F", "a.b", "a.b.c.d", "eyJ..Q7v2Lm9R"} {
		if isJWTShape(v) {
			t.Errorf("isJWTShape(%q) = true, want false", v)
		}
	}
}

func TestDetectorRejectsJWTBearerAndKnownSamples(t *testing.T) {
	d, err := NewDetector(Settings{Token: strings.Repeat("a", 40)})
	if err != nil {
		t.Fatal(err)
	}
	item := SearchItem{
		Repository: "owner/repo", Path: "config.env", BlobSHA: strings.Repeat("a", 40),
		HTMLURL: "https://github.com/owner/repo/blob/main/config.env",
		Fragments: []string{
			"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.Q7v2Lm9R4x8N.c6Wp3Za5Kd2F",
			`STRIPE_KEY="sk_test_51H8xQkExampleCharsHere123"`,
		},
	}
	if got := d.Detect("fp", item); len(got) != 0 {
		t.Fatalf("candidates = %+v, want none (JWT/known-sample 均应放行)", got)
	}
}

func TestCredibleDatabaseURL(t *testing.T) {
	fps := []string{
		"postgres://postgres:postgres@db:5432/app",
		"mysql://user:password@localhost:3306/app",
		"redis://default:changeme@redis-master:6379",
		"mongodb://root:example@mongo:27017",
		"postgres://user:$DB_PASS@db.internal/app",
	}
	for _, v := range fps {
		if credibleDatabaseURL(v) {
			t.Errorf("credibleDatabaseURL(%q) = true, want false（教学样板）", v)
		}
	}
	real := "postgres://svc_app:Zt8xQ2mVr7Pw4Kd1@db.prod.example.com:5432/appdb"
	if !credibleDatabaseURL(real) {
		t.Errorf("真实连接串被误放行: %s", real)
	}
}

func TestSuppressionMatching(t *testing.T) {
	list := []Suppression{
		{PatternType: SuppressionRepo, Pattern: "Course/Template-Repo"},
		{PatternType: SuppressionOrg, Pattern: "university-lab/*"},
		{PatternType: SuppressionPathGlob, Pattern: "config/**/*.bak.env"},
		{PatternType: SuppressionFingerprintPrefix, Pattern: strings.Repeat("ab", 8)},
	}
	set, skipped := compileSuppressions(list)
	if skipped != 0 {
		t.Fatalf("skipped = %d, want 0", skipped)
	}
	if !set.suppressItem("course/template-repo", "main.go") {
		t.Errorf("repo 静默未命中")
	}
	if !set.suppressItem("University-Lab/anything", "a/b.env") {
		t.Errorf("org 静默未命中")
	}
	if !set.suppressItem("other/repo", "config/prod/x.bak.env") {
		t.Errorf("path glob 静默未命中")
	}
	if set.suppressItem("other/repo", "config/x.env") {
		t.Errorf("path glob 误命中")
	}
	if !set.suppressCandidate(strings.Repeat("AB", 8) + "ff00") {
		t.Errorf("指纹前缀静默未命中")
	}
	if set.suppressCandidate(strings.Repeat("cd", 8) + "ff00") {
		t.Errorf("指纹前缀误命中")
	}
}

func TestFilterBoilerplateStorm(t *testing.T) {
	svc := &Service{logger: nil}
	mk := func(repo, path, kind, conf string) Candidate {
		return Candidate{Repository: repo, Path: path, SecretType: kind, Confidence: conf, Fingerprint: repo}
	}
	// 同路径同类型跨 5 仓库的 suspected 候选 → 整组丢弃
	var candidates []Candidate
	for _, repo := range []string{"a/x", "b/x", "c/x", "d/x", "e/x"} {
		candidates = append(candidates, mk(repo, ".env.production", "api_key", "suspected"))
	}
	// likely 强特征不受影响 + 其它路径不受影响
	candidates = append(candidates,
		mk("f/x", ".env.production", "github_token", "likely"),
		mk("g/x", "other.env", "api_key", "suspected"),
	)
	got, dropped := svc.filterBoilerplateStorm("r", candidates, 5)
	if dropped != 5 {
		t.Fatalf("dropped = %d, want 5", dropped)
	}
	if len(got) != 2 {
		t.Fatalf("kept = %d, want 2（样板组丢弃+强特征/他路径保留）", len(got))
	}
	for _, c := range got {
		if c.Confidence == "suspected" && c.Path == ".env.production" {
			t.Errorf("样板组未被丢弃")
		}
	}
}

func TestDetectorBase64Rescan(t *testing.T) {
	d, err := NewDetector(Settings{Token: strings.Repeat("c", 40)})
	if err != nil {
		t.Fatal(err)
	}
	secret := `token := "ghp_Ab9Qx4Lm7Nc2Rt8Vk5Za3Qw6Yh1Ui4Op2As7"`
	encoded := base64.StdEncoding.EncodeToString([]byte(secret))
	if len(encoded) < 40 {
		t.Fatalf("编码块过短: %d", len(encoded))
	}
	item := SearchItem{
		Repository: "owner/repo", Path: "config.env", BlobSHA: strings.Repeat("d", 40),
		HTMLURL:   "https://github.com/owner/repo/blob/main/config.env",
		Fragments: []string{encoded},
	}
	candidates := d.Detect("b64", item)
	found := false
	for _, c := range candidates {
		if c.SecretType == "github_token" {
			found = true
		}
	}
	if !found {
		t.Fatalf("base64 编码的 github_token 未被补扫检出")
	}
}
