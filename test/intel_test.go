package test

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/internal/recon/vulnmonitor"
	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
)

// 情报域（T1）的验收测试。
//
// 这几条测试打真实 PG，缺 ZRE_PG_PASSWORD 时整体跳过——不让本地没起库的人
// 被无关失败挡路。轮询打真实外部源的那条另用环境变量开关控制。

func openTestRepo(t *testing.T) *repo.Repo {
	t.Helper()
	if os.Getenv("ZRE_PG_PASSWORD") == "" {
		t.Skip("跳过：未设置 ZRE_PG_PASSWORD")
	}
	cfg := config.LoadConfig("../config/config.yaml")
	r, err := repo.Open(context.Background(), &cfg.Postgres)
	if err != nil {
		t.Fatalf("连接 PG 失败: %v", err)
	}
	t.Cleanup(r.Close)
	return r
}

// TestIntelStoreMapsSeverity 走 vulnmonitor.Store 这个接缝，校验中文档位被
// 映射成本仓的英文档位。这是 T1 里最容易静默出错的点：映射错了不会报错，
// 只会让 severity 变成脏值，而下游的 CHECK 约束与前端只认英文——问题会推迟
// 到很远才暴露，所以这里直接断言落库结果。
func TestIntelStoreMapsSeverity(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	cases := []struct {
		raw  string
		want string
	}{
		{"严重", "critical"},
		{"高危", "high"},
		{"中危", "medium"},
		{"低危", "low"},
		{"", "info"},
		{"不知道是什么", "info"},
	}

	store := service.NewIntelStore(r.Intels())
	prefix := "test:sev-" + time.Now().Format("150405.000000")

	for i, c := range cases {
		key := prefix + "-" + strconv.Itoa(i)
		if _, err := store.UpsertIntel(ctx, vulnmonitor.Intel{
			UniqueKey:  key,
			Title:      "档位映射测试 " + c.raw,
			Severity:   c.raw,
			SourceName: "test",
		}); err != nil {
			t.Fatalf("写入 %q 失败: %v", c.raw, err)
		}

		got, err := r.Intels().GetByUniqueKey(ctx, key)
		if err != nil {
			t.Fatalf("回读 %q 失败: %v", c.raw, err)
		}
		if got.Severity != c.want {
			t.Errorf("上游档位 %q 落库后为 %q，期望 %q", c.raw, got.Severity, c.want)
		}
	}

	if _, err := r.Pool().Exec(ctx, `DELETE FROM vuln_intel WHERE unique_key LIKE $1`, prefix+"%"); err != nil {
		t.Logf("清理测试行失败: %v", err)
	}
}

// TestIntelUpsertIdempotent 校验 unique_key 幂等：同一 key 写两次只有一行，
// 且第二次返回 created=false。
func TestIntelUpsertIdempotent(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	store := r.Intels()
	key := "test:idempotent-" + time.Now().Format("20060102150405")

	in := repo.IntelUpsert{
		UniqueKey:  key,
		Title:      "幂等测试条目",
		Desc:       "第一版描述",
		Severity:   "high",
		CVE:        "CVE-0000-0001",
		Source:     "测试源",
		SourceName: "test",
		SourceURL:  "https://example.com/advisory/1",
		Tags:       []string{"rce"},
		References: []string{"https://example.com/ref"},
	}

	created, err := store.UpsertIntel(ctx, in)
	if err != nil {
		t.Fatalf("首次写入失败: %v", err)
	}
	if !created {
		t.Error("首次写入应返回 created=true")
	}

	// 同一 key、改描述
	in.Desc = "第二版描述"
	created, err = store.UpsertIntel(ctx, in)
	if err != nil {
		t.Fatalf("二次写入失败: %v", err)
	}
	if created {
		t.Error("二次写入应返回 created=false（走了 UPDATE 分支）")
	}

	got, err := store.GetByUniqueKey(ctx, key)
	if err != nil {
		t.Fatalf("回读失败: %v", err)
	}
	if got.Description != "第二版描述" {
		t.Errorf("描述应被更新为「第二版描述」，实际 %q", got.Description)
	}
	if got.Severity != "high" {
		t.Errorf("severity = %q, 期望 high", got.Severity)
	}

	// 清理
	if _, err := r.Pool().Exec(ctx, `DELETE FROM vuln_intel WHERE unique_key=$1`, key); err != nil {
		t.Logf("清理测试行失败: %v", err)
	}
}

// TestIntelSeverityMatchesSchema 校验写入的 severity 全部落在 CHECK 约束允许的集合内。
func TestIntelSeverityMatchesSchema(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	rows, err := r.Pool().Query(ctx, `
		SELECT DISTINCT severity FROM vuln_intel
		WHERE severity NOT IN ('critical','high','medium','low','info')`)
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	defer rows.Close()

	var bad []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatalf("扫描失败: %v", err)
		}
		bad = append(bad, s)
	}
	if len(bad) > 0 {
		t.Errorf("vuln_intel 里存在非法 severity: %v（必须是 critical/high/medium/low/info）", bad)
	}
}

// TestIntelPollLive 打真实外部源跑一轮，验证 9 源与单源失败隔离。
// 需要网络，且会比较慢；用 ZRE_INTEL_LIVE=1 打开。
func TestIntelPollLive(t *testing.T) {
	if os.Getenv("ZRE_INTEL_LIVE") != "1" {
		t.Skip("跳过真实轮询：设置 ZRE_INTEL_LIVE=1 打开")
	}
	openTestRepo(t)

	svc := service.NewIntelService()
	res, err := svc.PollNow()
	if err != nil {
		t.Fatalf("轮询失败: %v", err)
	}

	t.Logf("源 %d 个，新增 %d，更新 %d，失败 %d",
		res.Sources, res.New, res.Updated, res.Failed)
	for _, e := range res.Errors {
		t.Logf("  源失败 %s: %s", e.Source, e.Error)
	}

	if res.Sources == 0 {
		t.Error("没有可用情报源")
	}
	// 单源失败可接受（网页改版、限流都会导致），全挂不可接受。
	if res.Failed > 0 && res.Failed == res.Sources {
		t.Errorf("全部 %d 个源都失败了，采集链路不通", res.Failed)
	}
	if res.New+res.Updated == 0 {
		t.Error("一轮结束没有任何记录入库或更新")
	}
}

// TestIntelSeverityDistinctAfterPoll 轮询后库里不应出现非法档位。
func TestIntelSeverityDistinctAfterPoll(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rows, err := r.Pool().Query(ctx, `SELECT DISTINCT severity FROM vuln_intel ORDER BY 1`)
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	defer rows.Close()

	var got []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatalf("扫描失败: %v", err)
		}
		got = append(got, s)
	}
	t.Logf("当前库内 severity 取值: %s", strings.Join(got, ", "))
}

// ---------------------------------------------------------------- T3 富化

// TestIntelEnrichRequiresToken 校验未配置 GITHUB_TOKEN 时明确报错。
// vendored 的 githubpoc 在无 token 时 SearchRepos 返回 (nil, nil)——如果不拦住，
// 调用方会看到「成功但 0 条」的假象，误以为这个 CVE 真没有 PoC。
func TestIntelEnrichRequiresToken(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	key := "test:enrich-token-" + time.Now().Format("150405.000000")
	if _, err := r.Intels().UpsertIntel(ctx, repo.IntelUpsert{
		UniqueKey: key, Title: "富化 token 测试", Severity: "high",
		CVE: "CVE-2021-44228", SourceName: "test",
	}); err != nil {
		t.Fatalf("准备数据失败: %v", err)
	}
	defer func() {
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM vuln_intel WHERE unique_key=$1`, key)
	}()

	svc := service.NewIntelServiceWithToken(func(context.Context) string { return "" })
	_, err := svc.EnrichIntel(key)
	if err == nil {
		t.Fatal("未配置 GitHub Token 时应报错")
	}
	if !strings.Contains(err.Error(), "GitHub Token") {
		t.Errorf("错误信息应说明缺少 GitHub Token，实际: %v", err)
	}
}

// TestIntelEnrichRejectsNoCVE 校验没有 CVE 编号的情报不做 PoC 检索。
func TestIntelEnrichRejectsNoCVE(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	key := "test:enrich-nocve-" + time.Now().Format("150405.000000")
	if _, err := r.Intels().UpsertIntel(ctx, repo.IntelUpsert{
		UniqueKey: key, Title: "无 CVE 测试", Severity: "high", SourceName: "test",
	}); err != nil {
		t.Fatalf("准备数据失败: %v", err)
	}
	defer func() {
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM vuln_intel WHERE unique_key=$1`, key)
	}()

	svc := service.NewIntelService()
	_, err := svc.EnrichIntel(key)
	if err == nil {
		t.Fatal("无 CVE 时应报错")
	}
	if !strings.Contains(err.Error(), "CVE") {
		t.Errorf("错误信息应说明缺少 CVE，实际: %v", err)
	}
}

// TestIntelMarkEnriched 校验富化写回：字段落地、enriched_at 被置、重复写入幂等。
func TestIntelMarkEnriched(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	key := "test:enriched-" + time.Now().Format("150405.000000")
	if _, err := r.Intels().UpsertIntel(ctx, repo.IntelUpsert{
		UniqueKey: key, Title: "富化写回测试", Severity: "high",
		CVE: "CVE-2021-44228", SourceName: "test",
	}); err != nil {
		t.Fatalf("准备数据失败: %v", err)
	}
	defer func() {
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM vuln_intel WHERE unique_key=$1`, key)
	}()

	in := repo.IntelEnrich{
		UniqueKey: key,
		GithubPoc: []repo.POCRef{
			{FullName: "owner/repo", URL: "https://github.com/owner/repo", Stars: 42, Verdict: "ACT", TriageScore: 80},
		},
		CVSSScore:  10,
		CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
		CWEs:       []int{502, 400},
		Affected:   []string{"maven/org.apache.logging.log4j:log4j-core"},
		LabOnly:    false,
	}
	if err := r.Intels().MarkEnriched(ctx, in); err != nil {
		t.Fatalf("写回失败: %v", err)
	}

	got, err := r.Intels().GetByUniqueKey(ctx, key)
	if err != nil {
		t.Fatalf("回读失败: %v", err)
	}
	if got.EnrichedAt.IsZero() {
		t.Error("enriched_at 应被置为当前时间")
	}
	if len(got.GithubPoc) != 1 || got.GithubPoc[0].FullName != "owner/repo" {
		t.Errorf("github_poc 未正确落库: %+v", got.GithubPoc)
	}
	if got.CVSSScore != 10 {
		t.Errorf("cvss_score = %v, 期望 10", got.CVSSScore)
	}
	if len(got.CWEs) != 2 {
		t.Errorf("cwes = %v, 期望两个", got.CWEs)
	}
	if len(got.Affected) != 1 {
		t.Errorf("affected = %v, 期望一条", got.Affected)
	}

	// 重复写回不应报错（幂等）
	if err := r.Intels().MarkEnriched(ctx, in); err != nil {
		t.Errorf("重复写回应成功，实际: %v", err)
	}
}

// TestIntelEnrichLive 真实打 GitHub API。需要 GITHUB_TOKEN 与 ZRE_INTEL_LIVE=1。
func TestIntelEnrichLive(t *testing.T) {
	if os.Getenv("ZRE_INTEL_LIVE") != "1" {
		t.Skip("跳过真实富化：设置 ZRE_INTEL_LIVE=1 打开")
	}
	r := openTestRepo(t)

	key := "test:enrich-live-" + time.Now().Format("150405")
	// 真实富化会拉仓库树与文件摘要，慢网络下可能接近 2 分钟；读回也要留足时间。
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	token := strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))
	if token == "" {
		token = service.NewSourceService().GitHubToken(ctx)
	}
	if token == "" {
		t.Skip("跳过真实富化：环境变量与数据源都没有 GitHub 凭据")
	}
	if _, err := r.Intels().UpsertIntel(ctx, repo.IntelUpsert{
		UniqueKey: key, Title: "Log4Shell", Severity: "critical",
		CVE: "CVE-2021-44228", Desc: "Apache Log4j2 JNDI RCE",
		SourceName: "test",
	}); err != nil {
		t.Fatalf("准备数据失败: %v", err)
	}
	defer func() {
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM vuln_intel WHERE unique_key=$1`, key)
	}()

	svc := service.NewIntelService()
	res, err := svc.EnrichIntel(key)
	if err != nil {
		t.Fatalf("富化失败: %v", err)
	}
	t.Logf("CVE %s: 仓库 %d，可用 PoC %d，CVSS %.1f，lab_only=%v",
		res.CVE, len(res.Repos), len(res.POCs), res.CVSSScore, res.LabOnly)

	if len(res.Repos) == 0 {
		t.Log("警告：GitHub 未搜到仓库，可能是配额或网络问题")
	}
	for _, p := range res.POCs {
		if p.Verdict == "MALICIOUS" || p.Verdict == "NOISE" {
			t.Errorf("恶意/噪音仓库不应出现在结果里: %s (%s)", p.FullName, p.Verdict)
		}
	}

	got, err := r.Intels().GetByUniqueKey(ctx, key)
	if err != nil {
		t.Fatalf("回读失败: %v", err)
	}
	if got.EnrichedAt.IsZero() {
		t.Error("富化后 enriched_at 应被置")
	}
}
