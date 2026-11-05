package backup

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// fakeCounter 是 RowCounter 的假实现：按表名返回预置行数；errs 里的表名注入错误
// （优先于 counts）；两者都没有的表返回错误。单测用它替代真实 PG。
type fakeCounter struct {
	counts map[string]int64
	errs   map[string]error
}

func (f *fakeCounter) CountRow(ctx context.Context, table string) (int64, error) {
	if err := f.errs[table]; err != nil {
		return 0, err
	}
	if n, ok := f.counts[table]; ok {
		return n, nil
	}
	return 0, context.DeadlineExceeded // 预置之外的表视为查询失败
}

func TestCoreTablesWhitelist(t *testing.T) {
	// 白名单口径：repo.requiredTables 的核心业务子集（users/projects/sites/
	// site_endpoints/tasks/vulnerabilities 量级），固定清单、无重复、不含簿记表。
	want := []string{"users", "projects", "sites", "site_endpoints", "tasks", "vulnerabilities"}
	if len(CoreTables) != len(want) {
		t.Fatalf("CoreTables 应为 %v, 实得 %v", want, CoreTables)
	}
	seen := map[string]bool{}
	for _, table := range CoreTables {
		if seen[table] {
			t.Fatalf("CoreTables 含重复表名: %s", table)
		}
		seen[table] = true
	}
	for _, table := range want {
		if !seen[table] {
			t.Fatalf("CoreTables 缺少核心表 %s: %v", table, CoreTables)
		}
	}
}

func TestManifestRowCountsRoundtrip(t *testing.T) {
	five := int64(5)
	m := Manifest{
		Version:       FormatVersion,
		CreatedAt:     time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC),
		Tool:          toolName,
		Source:        SourceInfo{Host: "127.0.0.1", Port: 25433, User: "zre", DBName: "zreark", Schema: "zre"},
		RowCounts:     map[string]*int64{"users": &five, "tasks": nil},
		RowCountsNote: "以下核心表计数失败，记为 null: tasks",
	}
	var buf bytes.Buffer
	if err := WriteManifest(&buf, &m); err != nil {
		t.Fatal(err)
	}
	// tasks 采数失败要落成 JSON null，恢复端才能区分"没采到"与"0 行"
	if !strings.Contains(buf.String(), `"row_counts"`) || !strings.Contains(buf.String(), `"tasks": null`) {
		t.Fatalf("manifest JSON 缺少 row_counts 或 null 语义:\n%s", buf.String())
	}
	got, err := ReadManifest(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if got.RowCounts == nil || len(got.RowCounts) != 2 {
		t.Fatalf("row_counts roundtrip 丢失: %v", got.RowCounts)
	}
	if v := got.RowCounts["users"]; v == nil || *v != 5 {
		t.Fatalf("users 行数 roundtrip 不一致: %v", got.RowCounts["users"])
	}
	if got.RowCounts["tasks"] != nil {
		t.Fatalf("tasks 应保持 null, 实得 %v", *got.RowCounts["tasks"])
	}
	if !strings.Contains(got.RowCountsNote, "tasks") {
		t.Fatalf("row_counts_note roundtrip 丢失: %q", got.RowCountsNote)
	}

	// 旧格式备份：manifest 没有 row_counts 字段 → 解码后为 nil（恢复端据此跳过比对）
	var oldBuf bytes.Buffer
	oldBuf.WriteString(`{"version": 1, "source": {"dbname": "zreark"}}`)
	old, err := ReadManifest(&oldBuf)
	if err != nil {
		t.Fatal(err)
	}
	if old.RowCounts != nil {
		t.Fatalf("旧格式 manifest 的 row_counts 应为 nil, 实得 %v", old.RowCounts)
	}
}

func TestCollectRowCountsPartialFailure(t *testing.T) {
	// tasks 注入失败：该表记 null 并写进 note，其余表正常计数，不阻塞采集
	counter := &fakeCounter{
		counts: map[string]int64{"users": 3, "projects": 4, "sites": 5, "site_endpoints": 6, "vulnerabilities": 7},
		errs:   map[string]error{"tasks": context.DeadlineExceeded},
	}
	var warn bytes.Buffer
	counts, note := collectRowCounts(context.Background(), counter, &warn)

	if v := counts["users"]; v == nil || *v != 3 {
		t.Fatalf("users 行数应为 3, 实得 %v", counts["users"])
	}
	if counts["tasks"] != nil {
		t.Fatalf("计数失败的 tasks 应记 null, 实得 %d", *counts["tasks"])
	}
	if !strings.Contains(note, "tasks") {
		t.Fatalf("note 应注明失败的表, 实得 %q", note)
	}
	if !strings.Contains(warn.String(), "tasks") {
		t.Fatalf("告警应提到失败表名, 实得: %s", warn.String())
	}
	if len(counts) != len(CoreTables) {
		t.Fatalf("快照应覆盖全部核心表, 实得 %d/%d", len(counts), len(CoreTables))
	}
}

func TestCollectRowCountsWithoutCounter(t *testing.T) {
	// psql 缺失（counter == nil）：全部记 null 并在 note 说明，绝不报错
	var warn bytes.Buffer
	counts, note := collectRowCounts(context.Background(), nil, &warn)
	if len(counts) != len(CoreTables) {
		t.Fatalf("应为核心表全量建键, 实得 %d", len(counts))
	}
	for _, table := range CoreTables {
		if counts[table] != nil {
			t.Fatalf("无计数器时 %s 应记 null", table)
		}
	}
	if note == "" {
		t.Fatal("note 应注明未采集的原因")
	}
}

func TestVerifyRowCounts(t *testing.T) {
	five, eight := int64(5), int64(8)
	want := map[string]*int64{"users": &five, "tasks": &eight, "vulnerabilities": nil}
	counter := &fakeCounter{counts: map[string]int64{"users": 5, "tasks": 3, "vulnerabilities": 99}}
	var warn bytes.Buffer

	diffs := verifyRowCounts(context.Background(), counter, want, &warn)
	if len(diffs) != 1 {
		t.Fatalf("应只有 tasks 不一致, 实得 %v", diffs)
	}
	if diffs[0].Table != "tasks" || diffs[0].Expected != 8 || diffs[0].Actual != 3 {
		t.Fatalf("diff 内容不对: %+v", diffs[0])
	}
	if !strings.Contains(warn.String(), "tasks") {
		t.Fatalf("告警应提到不一致的表, 实得: %s", warn.String())
	}

	// 快照为 null 的表（vulnerabilities）与快照里没有的表（sites）不参与比对
	if strings.Contains(warn.String(), "vulnerabilities") || strings.Contains(warn.String(), "sites") {
		t.Fatal("null/缺失快照的表不应参与比对")
	}

	// 本机统计失败的表只告警，不列为不一致（区分恢复不完整与统计不出来）：
	// 快照里只有 users，统计失败后应零 diff
	var warn2 bytes.Buffer
	errCounter := &fakeCounter{errs: map[string]error{"users": context.DeadlineExceeded}}
	if diffs := verifyRowCounts(context.Background(), errCounter,
		map[string]*int64{"users": &five}, &warn2); len(diffs) != 0 {
		t.Fatalf("统计失败不应列为不一致, 实得 %v", diffs)
	}
	if !strings.Contains(warn2.String(), "users") {
		t.Fatalf("统计失败应有告警, 实得: %s", warn2.String())
	}
}

func TestPGRowCounterStub(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX 脚本桩，Windows 跳过")
	}
	// 桩只认 schema 限定且带双引号的形式（"zre"."users"），
	// 顺带锁住实现必须限定 schema、必须转义标识符。
	// 注意 sh 的 case 模式里引号会被剥掉，要写成 \" 才能匹配字面双引号。
	fakeDir := t.TempDir()
	script := `#!/bin/sh
case "$*" in
  *\"zre\".\"users\"*) echo 42 ;;
  *) echo "unexpected: $*" >&2; exit 7 ;;
esac
`
	psql := filepath.Join(fakeDir, "psql")
	if err := os.WriteFile(psql, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	c := &PGRowCounter{PsqlBin: psql, Target: Target{Host: "127.0.0.1", Port: 25433, User: "zre", DBName: "zreark", Schema: "zre"}}
	n, err := c.CountRow(context.Background(), "users")
	if err != nil {
		t.Fatal(err)
	}
	if n != 42 {
		t.Fatalf("CountRow = %d, 期望 42", n)
	}

	// psql 报错 → 返回错误且带上表名，便于 Create 侧记 null
	failing := filepath.Join(fakeDir, "psql-fail")
	if err := os.WriteFile(failing, []byte("#!/bin/sh\necho boom >&2\nexit 3\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	c.PsqlBin = failing
	if _, err := c.CountRow(context.Background(), "users"); err == nil || !strings.Contains(err.Error(), "users") {
		t.Fatalf("psql 失败应返回带表名的错误, 实得 %v", err)
	}
}

// writeStub 往 dir 里写一个可执行 shell 桩。
func writeStub(t *testing.T, dir, name, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX 脚本桩，Windows 跳过")
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// buildArchiveWithManifest 按 buildTestArchive 的套路手工打包 .zrebackup；
// mutate 允许用例定制 manifest（注入/省略 row_counts 等）。文件卷恒为空，
// 让 Restore 走"没有文件卷，跳过"分支，聚焦行数比对。
func buildArchiveWithManifest(t *testing.T, mutate func(m *Manifest)) string {
	t.Helper()
	tmp := t.TempDir()
	// 空文件卷成员（writeArchiveFile 要求三成员齐全）
	var filesBuf bytes.Buffer
	if _, err := ArchiveDirs(nil, &filesBuf, os.Stderr); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, entryFiles), filesBuf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	dbContent := []byte("fake-custom-format-dump")
	if err := os.WriteFile(filepath.Join(tmp, entryDB), dbContent, 0o644); err != nil {
		t.Fatal(err)
	}
	m := Manifest{
		Version:   FormatVersion,
		CreatedAt: time.Now(),
		Tool:      toolName,
		Source:    SourceInfo{Host: "127.0.0.1", Port: 25433, User: "zre", DBName: "zreark", Schema: "zre"},
		Entries: []EntryInfo{
			{Name: entryDB, Size: int64(len(dbContent)), SHA256: hashBytes(dbContent)},
			{Name: entryFiles, Size: int64(len(filesBuf.Bytes())), SHA256: hashBytes(filesBuf.Bytes())},
		},
	}
	if mutate != nil {
		mutate(&m)
	}
	mf, err := os.Create(filepath.Join(tmp, entryManifest))
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteManifest(mf, &m); err != nil {
		t.Fatal(err)
	}
	mf.Close()
	out := filepath.Join(t.TempDir(), "zre-rowcounts"+Ext)
	if err := writeArchiveFile(out, tmp); err != nil {
		t.Fatal(err)
	}
	return out
}

// pgDumpStubBody 生成 pg_dump 桩：把 fake dump 写到 --file= 指定的路径。
const pgDumpStubBody = `#!/bin/sh
for a in "$@"; do
  case "$a" in --file=*) printf 'fake-custom-format-dump' > "${a#--file=}" ;; esac
done
`

// countPsqlStubBody 生成按 schema 限定表名分发行数的 psql 桩：
// busy 检查回 0、扩展清单回空、表名→行数按 case 分发，fail 表注入 exit 1
// （模拟单表统计失败）。sh 的 case 模式里引号会被剥掉，要写成 \" 才匹配字面引号。
func countPsqlStubBody(counts map[string]int64, fail string) string {
	var b strings.Builder
	b.WriteString("#!/bin/sh\ncase \"$*\" in\n")
	b.WriteString("  *pg_stat_activity*) echo 0 ;;\n")
	b.WriteString("  *pg_extension*) ;;\n")
	for _, table := range CoreTables { // 固定顺序生成，桩输出确定
		if table == fail {
			fmt.Fprintf(&b, "  *\\\"zre\\\".\\\"%s\\\"*) exit 1 ;;\n", table)
			continue
		}
		if n, ok := counts[table]; ok {
			fmt.Fprintf(&b, "  *\\\"zre\\\".\\\"%s\\\"*) echo %d ;;\n", table, n)
		}
	}
	b.WriteString("  *) echo 0 ;;\nesac\n")
	return b.String()
}

func TestRowCountsCreateRestoreE2E(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX 脚本桩，Windows 跳过")
	}
	// 端到端：stub pg_dump/psql/pg_restore，走真实 Create/Restore 流程。
	// datadir.TmpDir/BinRoot 是进程级 once 缓存，用 env 钉在本测试的临时目录里。
	tree := writeTestTree(t)
	t.Chdir(tree)
	t.Setenv("ZRE_BIN_DIR", filepath.Join(tree, "data", "bin"))
	t.Setenv("ZRE_TMPDIR", filepath.Join(tree, "data", "tmp"))

	target := Target{Host: "127.0.0.1", Port: 25433, User: "zre", DBName: "zreark", Schema: "zre"}

	// --- Create：manifest 带上六张核心表的行数快照，跨 tar 持久化 ---
	createBin := t.TempDir()
	writeStub(t, createBin, "pg_dump", pgDumpStubBody)
	writeStub(t, createBin, "psql", countPsqlStubBody(map[string]int64{
		"users": 5, "projects": 6, "sites": 7, "site_endpoints": 8, "tasks": 2, "vulnerabilities": 10,
	}, ""))
	var cbuf bytes.Buffer
	res, err := Create(context.Background(), CreateOptions{
		Target:   target,
		OutDir:   filepath.Join(tree, "backups"),
		Name:     "zre-rowcounts",
		PGBinDir: createBin,
		Warn:     &cbuf,
	})
	if err != nil {
		t.Fatalf("Create 失败: %v\n%s", err, cbuf.String())
	}
	if res.Manifest.RowCounts == nil || len(res.Manifest.RowCounts) != len(CoreTables) {
		t.Fatalf("manifest 应记录全部核心表行数, 实得 %v", res.Manifest.RowCounts)
	}
	for table, want := range map[string]int64{
		"users": 5, "projects": 6, "sites": 7, "site_endpoints": 8, "tasks": 2, "vulnerabilities": 10,
	} {
		v := res.Manifest.RowCounts[table]
		if v == nil {
			t.Fatalf("%s 行数缺失（应为 %d）, 快照: %v", table, want, res.Manifest.RowCounts)
		}
		if *v != want {
			t.Fatalf("%s 行数应为 %d, 实得 %d", table, want, *v)
		}
	}
	if res.Manifest.RowCountsNote != "" {
		t.Fatalf("全部成功时 note 应为空, 实得 %q", res.Manifest.RowCountsNote)
	}
	// 从归档里读回 manifest，验证 row_counts 跨 tar 落盘
	persisted, err := ReadArchiveManifest(res.Path)
	if err != nil {
		t.Fatal(err)
	}
	if v := persisted.RowCounts["users"]; v == nil || *v != 5 {
		t.Fatalf("归档内 manifest 的 row_counts 不完整: %v", persisted.RowCounts)
	}

	// --- Create 降级：tasks 采数失败 → 记 null + note，备份本身不失败 ---
	degradedBin := t.TempDir()
	writeStub(t, degradedBin, "pg_dump", pgDumpStubBody)
	writeStub(t, degradedBin, "psql", countPsqlStubBody(map[string]int64{"users": 5}, "tasks"))
	var dbuf bytes.Buffer
	res2, err := Create(context.Background(), CreateOptions{
		Target:   target,
		OutDir:   filepath.Join(tree, "backups"),
		Name:     "zre-rowcounts-degraded",
		PGBinDir: degradedBin,
		Warn:     &dbuf,
	})
	if err != nil {
		t.Fatalf("计数失败不应阻塞备份: %v\n%s", err, dbuf.String())
	}
	if res2.Manifest.RowCounts["tasks"] != nil {
		t.Fatalf("tasks 计数失败应记 null, 实得 %d", *res2.Manifest.RowCounts["tasks"])
	}
	if v := res2.Manifest.RowCounts["users"]; v == nil || *v != 5 {
		t.Fatalf("其余表应照常计数: %v", res2.Manifest.RowCounts)
	}
	if !strings.Contains(res2.Manifest.RowCountsNote, "tasks") {
		t.Fatalf("note 应注明 tasks 失败: %q", res2.Manifest.RowCountsNote)
	}
	if !strings.Contains(dbuf.String(), "tasks") || !strings.Contains(dbuf.String(), "行数采集失败") {
		t.Fatalf("应有带表名的降级告警: %s", dbuf.String())
	}

	// --- Restore：恢复后行数与快照交叉比对，users 不一致 → discrepancies + 告警 ---
	restoreBin := t.TempDir()
	// pg_restore 桩：--list 出一行 TOC，其余调用直接成功
	writeStub(t, restoreBin, "pg_restore", `#!/bin/sh
if [ "$1" = "--list" ]; then echo "1; 0 0 TABLE DATA - zre users"; exit 0; fi
exit 0
`)
	// psql 桩（restore 侧）：users 回 9（快照是 5），其余与快照一致
	writeStub(t, restoreBin, "psql", countPsqlStubBody(map[string]int64{
		"users": 9, "projects": 6, "sites": 7, "site_endpoints": 8, "tasks": 2, "vulnerabilities": 10,
	}, ""))
	var rbuf bytes.Buffer
	res3, err := Restore(context.Background(), RestoreOptions{
		File:     res.Path,
		Target:   target,
		PGBinDir: restoreBin,
		Root:     filepath.Join(tree, "restored"),
		Warn:     &rbuf,
	})
	if err != nil {
		t.Fatalf("Restore 失败: %v\n%s", err, rbuf.String())
	}
	if res3.BusyConns != 0 {
		t.Fatalf("桩回 0 个活跃连接, 实得 %d", res3.BusyConns)
	}
	if res3.RowCountsSkipped {
		t.Fatal("新格式备份不应跳过行数比对")
	}
	if len(res3.RowCountDiffs) != 1 {
		t.Fatalf("应发现 1 处不一致, 实得 %v", res3.RowCountDiffs)
	}
	if d := res3.RowCountDiffs[0]; d.Table != "users" || d.Expected != 5 || d.Actual != 9 {
		t.Fatalf("diff 应为 users 期望 5 实际 9, 实得 %+v", d)
	}
	if !strings.Contains(rbuf.String(), "行数不一致") {
		t.Fatalf("不一致应有告警: %s", rbuf.String())
	}

	// --- 旧格式备份：manifest 没有 row_counts → 跳过比对并在结果注明，不报错 ---
	oldArchive := buildArchiveWithManifest(t, nil)
	var rbuf2 bytes.Buffer
	res4, err := Restore(context.Background(), RestoreOptions{
		File:     oldArchive,
		Target:   target,
		PGBinDir: restoreBin,
		Root:     filepath.Join(tree, "restored"),
		Warn:     &rbuf2,
	})
	if err != nil {
		t.Fatalf("旧格式备份应能继续恢复: %v\n%s", err, rbuf2.String())
	}
	if !res4.RowCountsSkipped {
		t.Fatal("旧格式备份应注明 skipped")
	}
	if len(res4.RowCountDiffs) != 0 {
		t.Fatalf("旧格式备份不应有 diff, 实得 %v", res4.RowCountDiffs)
	}
	if !strings.Contains(rbuf2.String(), "跳过行数交叉比对") {
		t.Fatalf("跳过应有说明: %s", rbuf2.String())
	}
}
