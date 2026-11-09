package githubtokens

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

type fakePoolStore struct {
	tokens       []Token
	refreshCalls int
}

func (f *fakePoolStore) List(context.Context) ([]Token, error) { return f.tokens, nil }

func (f *fakePoolStore) RefreshAll(context.Context, *http.Client) []error {
	f.refreshCalls++
	return nil
}

func newTestPool(tokens ...Token) (*Pool, *fakePoolStore) {
	store := &fakePoolStore{tokens: tokens}
	return &Pool{store: store, http: &http.Client{}}, store
}

// 额度未知（未采集）时必须轮转，而不是固定用列表第一个号。
func TestPoolPickRotatesWhenRatesUnknown(t *testing.T) {
	pool, _ := newTestPool(
		Token{Token: "tok-a", Enabled: true, RateRemaining: -1},
		Token{Token: "tok-b", Enabled: true, RateRemaining: -1},
	)
	var got []string
	for i := 0; i < 4; i++ {
		got = append(got, pool.Pick(context.Background()))
	}
	want := "[tok-a tok-b tok-a tok-b]"
	if fmt.Sprint(got) != want {
		t.Fatalf("pick sequence = %v, want %s", got, want)
	}
}

// 额度已知且不等时优先剩余最多的号；持平时轮转。
func TestPoolPickPrefersKnownMaxAndRotatesTies(t *testing.T) {
	pool, _ := newTestPool(
		Token{Token: "tok-a", Enabled: true, RateRemaining: 100},
		Token{Token: "tok-b", Enabled: true, RateRemaining: 50},
	)
	if got := pool.Pick(context.Background()); got != "tok-a" {
		t.Fatalf("pick = %q, want tok-a（额度最多优先）", got)
	}
	if got := pool.Pick(context.Background()); got != "tok-a" {
		t.Fatalf("pick = %q, want tok-a（持续优先）", got)
	}

	tiePool, _ := newTestPool(
		Token{Token: "tok-a", Enabled: true, RateRemaining: 100},
		Token{Token: "tok-b", Enabled: true, RateRemaining: 100},
	)
	if a, b := tiePool.Pick(context.Background()), tiePool.Pick(context.Background()); a == b {
		t.Fatalf("持平额度未轮转: %q, %q", a, b)
	}
}

// 打满/停用的号跳过；无可用返回空。
func TestPoolPickSkipsExhaustedAndDisabled(t *testing.T) {
	pool, _ := newTestPool(
		Token{Token: "full", Enabled: true, RateRemaining: 0},
		Token{Token: "off", Enabled: false, RateRemaining: -1},
		Token{Token: "ok", Enabled: true, RateRemaining: -1},
	)
	if got := pool.Pick(context.Background()); got != "ok" {
		t.Fatalf("pick = %q, want ok", got)
	}

	empty, _ := newTestPool(
		Token{Token: "full", Enabled: true, RateRemaining: 0},
		Token{Token: "off", Enabled: false, RateRemaining: -1},
	)
	if got := empty.Pick(context.Background()); got != "" {
		t.Fatalf("pick = %q, want empty", got)
	}
}

// 已知额度优先于未知号（未知号可能已打满）。
func TestPoolPickPrefersKnownOverUnknown(t *testing.T) {
	pool, _ := newTestPool(
		Token{Token: "unknown", Enabled: true, RateRemaining: -1},
		Token{Token: "known", Enabled: true, RateRemaining: 10},
	)
	if got := pool.Pick(context.Background()); got != "known" {
		t.Fatalf("pick = %q, want known", got)
	}
}

func TestPoolRefreshRatesDelegates(t *testing.T) {
	pool, store := newTestPool(Token{Token: "tok-a", Enabled: true, RateRemaining: -1})
	if errs := pool.RefreshRates(context.Background()); len(errs) != 0 {
		t.Fatalf("refresh errs = %v", errs)
	}
	if store.refreshCalls != 1 {
		t.Fatalf("refresh calls = %d, want 1", store.refreshCalls)
	}
}

func TestLooksLikePlaceholderToken(t *testing.T) {
	real := []string{
		"ghp_" + strings.Repeat("Ab3dEf9", 5),         // 40 字符 PAT 主体
		"github_pat_" + strings.Repeat("aB3dEf9_", 6), // 细粒度 PAT
		"gho_" + strings.Repeat("Zx9Qw2", 6),
		"some-enterprise-token-9f3a7c2b1e5d", // 未知形状但无占位限定词 → 放行
	}
	for _, tok := range real {
		if LooksLikePlaceholderToken(tok) {
			t.Errorf("真实 token 被判为占位: %q", tok)
		}
	}
	placeholders := []string{
		"", "   ", "YOUR_GITHUB_TOKEN", "your-token-here", "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		"<your token>", "CHANGEME", "example_pat", "REPLACE_WITH_YOUR_TOKEN", "TODO",
	}
	for _, tok := range placeholders {
		if !LooksLikePlaceholderToken(tok) {
			t.Errorf("占位值未被识别: %q", tok)
		}
	}
}

func TestValidateNewToken(t *testing.T) {
	real := "ghp_" + strings.Repeat("Ab3dEf9", 5)
	if err := validateNewToken(real, nil); err != nil {
		t.Fatalf("新号应通过校验: %v", err)
	}
	if err := validateNewToken("YOUR_GITHUB_TOKEN", nil); err == nil {
		t.Fatal("占位值应被拒绝")
	}
	existing := []Token{{Label: "主号", Token: real}}
	if err := validateNewToken(real, existing); err == nil {
		t.Fatal("同号重复应被拒绝（否则会被当成两个额度号轮换）")
	}
	if err := validateNewToken("ghp_"+strings.Repeat("Zx9Qw2", 6), existing); err != nil {
		t.Fatalf("不同号应通过: %v", err)
	}
}
