package service

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/config"
	reconfp "github.com/c1ayooo/4zreark/internal/recon/fingerprint"
	"github.com/c1ayooo/4zreark/repo"
)

// 上游同步：内容哈希不变不重导、变更后按 source 全量对齐、
// 上游不可达时有快照的来源回落内置快照。
func TestFingerprintUpstreamSync(t *testing.T) {
	if os.Getenv("ZRE_PG_PASSWORD") == "" {
		t.Skip("跳过：未设置 ZRE_PG_PASSWORD")
	}
	cfg := config.LoadConfig("../config/config.yaml")
	r, err := repo.Open(context.Background(), &cfg.Postgres)
	if err != nil {
		t.Fatalf("连接 PG 失败: %v", err)
	}
	t.Cleanup(r.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	prefix := fmt.Sprintf("t-up-%d", time.Now().UnixNano())
	source := "test-upstream-" + prefix

	var body atomic.Value
	name1 := prefix + "Tech"
	body.Store([]byte(fmt.Sprintf(`{"apps":{%q:{"html":%q}}}`, name1, "pattern-one-"+prefix)))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = w.Write(body.Load().([]byte))
	}))
	defer srv.Close()

	cleanup := func(sourceName string) {
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM fingerprint_rules WHERE source = $1`, sourceName)
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM fingerprint_sources WHERE name = $1`, sourceName)
	}
	t.Cleanup(func() {
		cleanup(source)
		cleanup("test-upstream-fallback-" + prefix)
	})

	svc := NewFingerprintUpstreamService()
	svc.client = srv.Client()
	svc.sources = []FpUpstreamSource{{
		Name:  source,
		URLs:  []string{srv.URL},
		Parse: reconfp.ParseWappalyzergoFingerprints,
	}}

	outcomes, err := svc.SyncUpstream(ctx, false)
	if err != nil {
		t.Fatalf("首次同步失败: %v", err)
	}
	if len(outcomes) != 1 || outcomes[0].Reason != "imported" || outcomes[0].Imported < 1 {
		t.Fatalf("首次同步结果不符: %+v", outcomes)
	}
	counts, err := r.FingerprintSync().CountBySource(ctx)
	if err != nil || counts[source] != 1 {
		t.Fatalf("首次同步后来源计数不符: %v err=%v", counts, err)
	}

	outcomes, err = svc.SyncUpstream(ctx, false)
	if err != nil {
		t.Fatalf("二次同步失败: %v", err)
	}
	if outcomes[0].Reason != "unchanged" || outcomes[0].Imported != 0 {
		t.Fatalf("内容未变时不应重导: %+v", outcomes[0])
	}

	name2 := prefix + "Tech2"
	body.Store([]byte(fmt.Sprintf(`{"apps":{%q:{"html":%q},%q:{"html":%q}}}`,
		name1, "pattern-one-"+prefix, name2, "pattern-two-"+prefix)))
	outcomes, err = svc.SyncUpstream(ctx, false)
	if err != nil {
		t.Fatalf("变更同步失败: %v", err)
	}
	if outcomes[0].Reason != "imported" || outcomes[0].Imported != 2 {
		t.Fatalf("变更后应导入 2 条: %+v", outcomes[0])
	}
	counts, _ = r.FingerprintSync().CountBySource(ctx)
	if counts[source] != 2 {
		t.Fatalf("变更后来源应有 2 条，实际 %d", counts[source])
	}

	// 上游全部不可达：有快照的来源回落快照
	fallbackSource := "test-upstream-fallback-" + prefix
	fallbackName := prefix + "Fallback"
	fallback := NewFingerprintUpstreamService()
	fallback.client = &http.Client{Timeout: time.Second}
	fallback.sources = []FpUpstreamSource{{
		Name:  fallbackSource,
		URLs:  []string{"http://127.0.0.1:1/unreachable"},
		Parse: reconfp.ParseWappalyzergoFingerprints,
		Snapshot: []reconfp.Rule{{
			Name: fallbackName, Category: "fallback", Expression: `body="fallback"`,
		}},
	}}
	outcomes, err = fallback.SyncUpstream(ctx, false)
	if err != nil {
		t.Fatalf("快照同步失败: %v", err)
	}
	if outcomes[0].Reason != "snapshot" || outcomes[0].Imported != 1 {
		t.Fatalf("不可达时应回落快照: %+v", outcomes[0])
	}
	if _, err := r.Fingerprints().GetRuleByName(ctx, fallbackName); err != nil {
		t.Fatalf("快照规则应已落库: %v", err)
	}
}
