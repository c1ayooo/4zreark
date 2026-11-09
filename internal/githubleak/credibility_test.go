package githubleak

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/internal/lz"
)

// credibility_test.go — R8-4 来源可信度加权 / R8-5 时效加权 / R6 定向规则模板
// 的回归（docs/GitHub敏感信息监控改进建议.md）。

func TestCredScore(t *testing.T) {
	now := time.Now().UTC()
	old := now.AddDate(-1, 0, 0)
	fresh := now.Add(-24 * time.Hour)

	cases := []struct {
		name string
		item SearchItem
		want int
	}{
		{"normal repo no signals", SearchItem{Repository: "owner/app", Path: "src/main.py", RepoStars: 3, RepoCreatedAt: old}, 0},
		{"collection repo name", SearchItem{Repository: "evil/leaked-keys", Path: "src/main.py", RepoStars: 3, RepoCreatedAt: old}, -2},
		{"awesome tutorial repo", SearchItem{Repository: "edu/awesome-tutorial", Path: "a.py", RepoStars: 3, RepoCreatedAt: old}, -2},
		{"zero stars only", SearchItem{Repository: "owner/app", Path: "a.py", RepoCreatedAt: old}, -1},
		{"zero stars + fresh repo", SearchItem{Repository: "owner/app", Path: "a.py", RepoCreatedAt: fresh}, -2},
		{"archived + zero stars", SearchItem{Repository: "owner/app", Path: "a.py", RepoCreatedAt: old, RepoArchived: true}, -2},
		{"notebook + zero stars", SearchItem{Repository: "owner/app", Path: "out.ipynb", RepoCreatedAt: old}, -2},
		{"env file cancels one", SearchItem{Repository: "owner/app", Path: ".env", RepoCreatedAt: old}, 0},
		{"env file caps at zero", SearchItem{Repository: "evil/leaked-keys", Path: "x/.env", RepoStars: 3, RepoCreatedAt: old}, -1},
		{"zero stars stacks with collection name", SearchItem{Repository: "evil/leaked-keys", Path: "a.py", RepoCreatedAt: old}, -3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := credScore(tc.item, now); got != tc.want {
				t.Fatalf("credScore = %d, want %d", got, tc.want)
			}
		})
	}
}

// R8-4：可信分 ≤ -2 的来源，likely 候选降级 suspected；正常来源不受影响。
func TestDowngradeLowCredibility(t *testing.T) {
	service := &Service{logger: lz.NewNop()}
	item := SearchItem{Repository: "evil/leaked-keys", Path: "config/prod.py", RepoStars: 2, RepoCreatedAt: time.Now().AddDate(-1, 0, 0)}
	candidates := []Candidate{
		{Repository: item.Repository, SecretType: "aws_access_key_id", Confidence: "likely"},
		{Repository: item.Repository, SecretType: "generic_secret_assignment", Confidence: "suspected"},
	}
	if n := service.downgradeLowCredibility(item, candidates); n != 1 {
		t.Fatalf("downgraded = %d, want 1", n)
	}
	if candidates[0].Confidence != "suspected" {
		t.Fatalf("likely not downgraded: %s", candidates[0].Confidence)
	}
	if candidates[1].Confidence != "suspected" {
		t.Fatalf("suspected should stay suspected: %s", candidates[1].Confidence)
	}

	normal := SearchItem{Repository: "owner/app", Path: "src/main.py", RepoStars: 5, RepoCreatedAt: time.Now().AddDate(-1, 0, 0)}
	if n := service.downgradeLowCredibility(normal, candidates); n != 0 {
		t.Fatalf("normal repo downgraded %d candidates", n)
	}
}

// R8-5：AWS 类命中文件超过 30 天未提交 → 降级；窗口内与其他类别不受影响。
func TestDowngradeStaleSecrets(t *testing.T) {
	service := &Service{logger: lz.NewNop()}
	stale := time.Now().UTC().AddDate(0, 0, -40)
	fresh := time.Now().UTC().AddDate(0, 0, -10)

	staleCandidates := []Candidate{
		{SecretType: "aws_access_key_id", Confidence: "likely"},
		{SecretType: "wechat_pay_secret", Confidence: "likely"},
	}
	if n := service.downgradeStaleSecrets(staleCandidates, stale); n != 1 {
		t.Fatalf("stale downgraded = %d, want 1", n)
	}
	if staleCandidates[0].Confidence != "suspected" {
		t.Fatalf("stale AWS key = %s, want suspected", staleCandidates[0].Confidence)
	}
	if staleCandidates[1].Confidence != "likely" {
		t.Fatalf("no-quarantine vendor = %s, want likely kept", staleCandidates[1].Confidence)
	}

	freshCandidates := []Candidate{{SecretType: "aws_access_key_id", Confidence: "likely"}}
	if n := service.downgradeStaleSecrets(freshCandidates, fresh); n != 0 {
		t.Fatalf("fresh AWS key downgraded %d", n)
	}
	if n := service.downgradeStaleSecrets(freshCandidates, time.Time{}); n != 0 {
		t.Fatalf("zero updatedAt downgraded %d", n)
	}
}

// provider 从 code search 响应解析 stars/created_at（R8-4 元数据来源）。
func TestProviderParsesCredibilityMetadata(t *testing.T) {
	created := time.Now().UTC().AddDate(-2, 0, 0).Truncate(time.Second)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `{"total_count":1,"incomplete_results":false,"items":[{"path":"config.env","sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","html_url":"https://github.com/owner/repo/blob/main/config.env","repository":{"full_name":"owner/repo","node_id":"R_unit","private":false,"visibility":"public","created_at":%q,"stargazers_count":42,"pushed_at":%q},"text_matches":[{"fragment":"ordinary fixture"}]}]}`,
			created.Format(time.RFC3339), created.Format(time.RFC3339))
	}))
	defer server.Close()

	client := providerClientForServer(t, server, newProviderTestClock())
	result, err := client.Search(context.Background(), `"fixture"`, "", 30)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Items) != 1 {
		t.Fatalf("items = %d, want 1", len(result.Items))
	}
	if result.Items[0].RepoStars != 42 {
		t.Fatalf("RepoStars = %d, want 42", result.Items[0].RepoStars)
	}
	if result.Items[0].RepoCreatedAt.IsZero() || !result.Items[0].RepoCreatedAt.Equal(created) {
		t.Fatalf("RepoCreatedAt = %v, want %v", result.Items[0].RepoCreatedAt, created)
	}
}

// R6：AddAutoRules 生成定向模板（目标域 × 厂商凭据特征词）。
func TestAddAutoRulesGeneratesTargetedTemplates(t *testing.T) {
	store := newServiceTestPersistence()
	service, err := newService(store, serviceSettings(true, "storage-service"), &quotaProbingProvider{}, serviceTestDetector{}, lz.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	fresh, added, err := service.AddAutoRules("target.example", "targetorg")
	if err != nil {
		t.Fatal(err)
	}
	if added == 0 || len(fresh) != added {
		t.Fatalf("added = %d fresh = %d", added, len(fresh))
	}
	names := map[string]bool{}
	for _, r := range fresh {
		names[r.Name] = true
	}
	for _, want := range []string{"auto:target.example/targetorg:域名×AKIA", "auto:target.example/targetorg:域名×LTAI", "auto:target.example/targetorg:组织×token"} {
		if !names[want] {
			t.Fatalf("missing generated rule %q; got %v", want, names)
		}
	}
}
