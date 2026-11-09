package githubleak

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/internal/testutil/testpostgres"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// openTestDB 直连 pgx stdlib（迁移自 4zreco 的 database.NewDB 包装：测试只需要裸 *sql.DB）。
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("pgx", testpostgres.DSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestStorePersistsCombinedRuleStateThroughApplicationPostgresWrapper(t *testing.T) {
	db := openTestDB(t)
	store, err := NewStore(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	rule, err := newKeywordRule([]string{"storage-service", "vendor.example"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	want := KeywordState{
		Keyword: rule.Query, ETag: `W/"integration"`, LastAttemptAt: &now,
		LastSuccessAt: &now, LastStatus: "partial", Incomplete: true, Truncated: true,
	}
	if err = store.SaveKeywordState(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	got, err := store.KeywordState(context.Background(), rule.Query)
	if err != nil {
		t.Fatal(err)
	}
	if got.Keyword != want.Keyword || got.ETag != want.ETag || got.LastStatus != want.LastStatus || !got.Incomplete || !got.Truncated || got.LastAttemptAt == nil || got.LastSuccessAt == nil {
		t.Fatalf("persisted state = %+v", got)
	}
}

func TestStoreMigratesExistingFindingsAndKeepsDistinctFingerprints(t *testing.T) {
	db := openTestDB(t)
	_, err := db.ExecContext(context.Background(), `
CREATE TABLE github_leak_findings (
 id TEXT PRIMARY KEY,status TEXT NOT NULL DEFAULT 'new',keyword TEXT NOT NULL,repository TEXT NOT NULL,path TEXT NOT NULL,
 blob_sha TEXT NOT NULL,line_number INTEGER NOT NULL DEFAULT 0,secret_type TEXT NOT NULL,confidence TEXT NOT NULL,severity TEXT NOT NULL,
 fingerprint TEXT NOT NULL,masked_excerpt TEXT NOT NULL,html_url TEXT NOT NULL,first_seen_at TIMESTAMPTZ NOT NULL,last_seen_at TIMESTAMPTZ NOT NULL
);
CREATE UNIQUE INDEX github_leak_findings_identity_idx ON github_leak_findings(repository,path,blob_sha,keyword,secret_type,line_number);
CREATE TABLE github_leak_keyword_state (
 keyword TEXT PRIMARY KEY,etag TEXT NOT NULL DEFAULT '',last_attempt_at TIMESTAMPTZ,last_success_at TIMESTAMPTZ,
 last_status TEXT NOT NULL DEFAULT 'idle',last_error TEXT NOT NULL DEFAULT '',incomplete BOOLEAN NOT NULL DEFAULT FALSE,updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE github_leak_runs (
 id TEXT PRIMARY KEY,status TEXT NOT NULL,error TEXT NOT NULL DEFAULT '',started_at TIMESTAMPTZ NOT NULL,finished_at TIMESTAMPTZ,
 rate_remaining INTEGER NOT NULL DEFAULT -1,rate_reset_at TIMESTAMPTZ,processed INTEGER NOT NULL DEFAULT 0,detected INTEGER NOT NULL DEFAULT 0
);
INSERT INTO github_leak_findings
 (id,status,keyword,repository,path,blob_sha,line_number,secret_type,confidence,severity,fingerprint,masked_excerpt,html_url,first_seen_at,last_seen_at)
SELECT 'legacy-'||g,'new','"clientid" AND "vendor.example" in:file','owner/repo','legacy-'||g||'.env',repeat('a',40),0,
 'oauth_client_id','suspected','low',repeat(md5(g::text),2),'clientId=<redacted:oauth_client_id>',
 'https://github.com/owner/repo/blob/main/legacy-'||g||'.env',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP FROM generate_series(1,3) g;
`)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	var count int
	var minRule string
	if err = db.QueryRowContext(context.Background(), `SELECT COUNT(*),MIN(rule_name) FROM github_leak_findings WHERE id LIKE 'legacy-%'`).Scan(&count, &minRule); err != nil {
		t.Fatal(err)
	}
	if count != 3 || minRule != "legacy" {
		t.Fatalf("migrated legacy rows = count:%d rule:%q", count, minRule)
	}
	rule, err := newKeywordRule([]string{"vendor.example", "clientid"})
	if err != nil {
		t.Fatal(err)
	}
	base := Candidate{
		RuleName: "example-corp-clientid", Keyword: rule.Query, Repository: "owner/new-repo", Path: "config.env",
		BlobSHA: strings.Repeat("b", 40), SecretType: "oauth_client_id", Confidence: "suspected", Severity: "low",
		MaskedExcerpt: "clientId=<redacted:oauth_client_id>", HTMLURL: "https://github.com/owner/new-repo/blob/main/config.env",
		SourceUpdatedAt: time.Now().UTC(),
	}
	first, second := base, base
	first.Fingerprint, second.Fingerprint = strings.Repeat("c", 64), strings.Repeat("d", 64)
	inserted, updated, err := store.UpsertCandidates(context.Background(), []Candidate{first, second}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(inserted) != 2 || updated != 0 {
		t.Fatalf("fingerprint identity = inserted:%d updated:%d", len(inserted), updated)
	}
	var requests, truncated, sourceUpdated, freshnessColumns int
	if err = db.QueryRowContext(context.Background(), `SELECT
 (SELECT COUNT(*) FROM information_schema.columns WHERE table_name='github_leak_runs' AND column_name='requests'),
 (SELECT COUNT(*) FROM information_schema.columns WHERE table_name='github_leak_keyword_state' AND column_name='truncated'),
 (SELECT COUNT(*) FROM information_schema.columns WHERE table_name='github_leak_findings' AND column_name='source_updated_at'),
 (SELECT COUNT(*) FROM information_schema.columns WHERE table_name='github_leak_keyword_state'
   AND column_name IN ('freshness_policy','freshness_checked_at','freshness_cursor','freshness_cursor_etag'))`).
		Scan(&requests, &truncated, &sourceUpdated, &freshnessColumns); err != nil {
		t.Fatal(err)
	}
	if requests != 1 || truncated != 1 || sourceUpdated != 1 || freshnessColumns != 4 {
		t.Fatalf("migration columns = requests:%d truncated:%d source_updated_at:%d freshness:%d", requests, truncated, sourceUpdated, freshnessColumns)
	}
}

// PurgeExpiredFindings 回归：只清处置完结且超期的行（曾引用不存在的
// updated_at/seen_at 列导致永远清理失败）；未处置行必须保留。
func TestStorePurgeExpiredFindingsKeepsActiveRows(t *testing.T) {
	dsn := testpostgres.DSN(t)
	sqlDB, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer sqlDB.Close()
	store, err := NewStore(context.Background(), sqlDB)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Now().UTC()
	base := Candidate{
		RuleName: "purge-rule", Keyword: `"purge" in:file`, Repository: "owner/purge",
		BlobSHA: strings.Repeat("a", 40), SecretType: "api_key", Confidence: "suspected", Severity: "medium",
		MaskedExcerpt: "key=<redacted>", SourceUpdatedAt: now,
	}
	names := []string{"old-fp.env", "old-active.env", "fresh-fp.env"}
	candidates := make([]Candidate, 0, len(names))
	for i, name := range names {
		c := base
		c.Path = name
		c.HTMLURL = "https://github.com/owner/purge/blob/main/" + name
		c.Fingerprint = strings.Repeat(string(rune('a'+i)), 64)
		candidates = append(candidates, c)
	}
	if _, _, err = store.UpsertCandidates(ctx, candidates, now); err != nil {
		t.Fatal(err)
	}
	// old-fp：已置误报且 200 天未再出现；old-active：未处置但同样陈旧（必须保留）；
	// fresh-fp：已置误报但刚出现。
	for _, update := range []struct {
		path     string
		status   string
		lastSeen time.Time
	}{
		{"old-fp.env", "false_positive", now.AddDate(0, 0, -200)},
		{"old-active.env", "new", now.AddDate(0, 0, -200)},
		{"fresh-fp.env", "false_positive", now.Add(-time.Hour)},
	} {
		if _, err = sqlDB.ExecContext(ctx,
			`UPDATE github_leak_findings SET status=$2, last_seen_at=$3 WHERE path=$1`, update.path, update.status, update.lastSeen); err != nil {
			t.Fatal(err)
		}
	}
	purged, err := store.PurgeExpiredFindings(ctx, 180)
	if err != nil {
		t.Fatalf("purge failed: %v", err)
	}
	if purged != 1 {
		t.Fatalf("purged = %d, want 1", purged)
	}
	var remaining int
	if err = sqlDB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM github_leak_findings WHERE path IN ('old-active.env','fresh-fp.env')`).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 2 {
		t.Fatalf("remaining active/fresh rows = %d, want 2", remaining)
	}
}
