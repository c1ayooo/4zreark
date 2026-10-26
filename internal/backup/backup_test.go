package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

// writeTestTree 造一个带嵌套结构的源目录树，返回根路径。
func writeTestTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"config/dicts/txt/common.txt":       "admin\npassword\n",
		"config/dicts/yaml/fingerprint.yml": "name: test\n",
		"pocs/nuclei/demo.yaml":             "id: demo\n",
		"configs/verify-playbooks/a.json":   `{"k":1}`,
	}
	for rel, content := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestDefaultBackupName(t *testing.T) {
	// 固定时间 → 固定格式 zre-20261023-153000
	loc := time.FixedZone("CST", 8*3600)
	ts := time.Date(2026, 10, 23, 15, 30, 0, 0, loc)
	got := DefaultBackupName(ts)
	if got != "zre-20261023-153000" {
		t.Fatalf("DefaultBackupName = %q, 期望 zre-20261023-153000", got)
	}
	if !regexp.MustCompile(`^zre-\d{8}-\d{6}$`).MatchString(DefaultBackupName(time.Now())) {
		t.Fatalf("当前时间生成的名字不符合 zre-<8位日期>-<6位时间>: %q", DefaultBackupName(time.Now()))
	}
}

func TestManifestRoundtrip(t *testing.T) {
	m := Manifest{
		Version:       FormatVersion,
		CreatedAt:     time.Date(2026, 10, 23, 15, 30, 0, 0, time.UTC),
		Tool:          toolName,
		PgDumpVersion: "pg_dump (PostgreSQL) 16.15",
		Source:        SourceInfo{Host: "127.0.0.1", Port: 25433, User: "zre", DBName: "zreark", Schema: "zre"},
		Git:           GitInfo{Revision: "abc123", Modified: true},
		Entries: []EntryInfo{
			{Name: entryDB, Size: 123, SHA256: strings.Repeat("a", 64)},
			{Name: entryFiles, Size: 4, SHA256: strings.Repeat("b", 64)},
		},
		Files: []string{"config/dicts/txt/common.txt", "pocs/nuclei/demo.yaml"},
		Extensions: []ExtensionInfo{
			{Name: "pg_trgm", Schema: "zre"},
		},
	}
	var buf bytes.Buffer
	if err := WriteManifest(&buf, &m); err != nil {
		t.Fatal(err)
	}
	got, err := ReadManifest(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != m.Version || got.Source != m.Source || got.PgDumpVersion != m.PgDumpVersion {
		t.Fatalf("roundtrip 后字段不一致: %+v", got)
	}
	if len(got.Entries) != 2 || got.Entries[0].Name != entryDB || got.Entries[0].SHA256 != m.Entries[0].SHA256 {
		t.Fatalf("entries roundtrip 不一致: %+v", got.Entries)
	}
	if !got.CreatedAt.Equal(m.CreatedAt) {
		t.Fatalf("created_at roundtrip 不一致: %v vs %v", got.CreatedAt, m.CreatedAt)
	}
	if !got.Git.Modified {
		t.Fatalf("git.modified roundtrip 丢失")
	}
	if len(got.Extensions) != 1 || got.Extensions[0].Name != "pg_trgm" || got.Extensions[0].Schema != "zre" {
		t.Fatalf("extensions roundtrip 不一致: %+v", got.Extensions)
	}
}

func TestListSchemaExtensions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX 脚本桩，Windows 跳过")
	}
	// 用脚本桩模拟 psql 输出（tuples-only|no-align|field-separator=|）
	fakeDir := t.TempDir()
	script := "#!/bin/sh\necho 'pg_trgm|zre'\necho 'cube_ext|zre'\n"
	if err := os.WriteFile(filepath.Join(fakeDir, "psql"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	exts, err := ListSchemaExtensions(context.Background(), filepath.Join(fakeDir, "psql"),
		&Target{Host: "127.0.0.1", Port: 25433, User: "zre", DBName: "zreark", Schema: "zre"})
	if err != nil {
		t.Fatal(err)
	}
	if len(exts) != 2 || exts[0].Name != "pg_trgm" || exts[0].Schema != "zre" || exts[1].Name != "cube_ext" {
		t.Fatalf("扩展清单解析不对: %+v", exts)
	}
}

func TestReadManifestRejectsWrongVersion(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString(`{"version": 99}`)
	if _, err := ReadManifest(&buf); err == nil {
		t.Fatal("version=99 应当被拒绝")
	}
}

func TestArchiveExtractRoundtrip(t *testing.T) {
	root := writeTestTree(t)
	t.Chdir(root) // ArchiveDirs 按相对路径收集

	var buf bytes.Buffer
	files, err := ArchiveDirs(DefaultFileDirs, &buf, os.Stderr)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 4 {
		t.Fatalf("应收集 4 个文件, 实得 %d: %v", len(files), files)
	}
	for _, want := range []string{
		"config/dicts/txt/common.txt",
		"config/dicts/yaml/fingerprint.yml",
		"pocs/nuclei/demo.yaml",
		"configs/verify-playbooks/a.json",
	} {
		found := false
		for _, f := range files {
			if f == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("清单缺少 %s: %v", want, files)
		}
	}

	// 解包到另一个目录，逐文件比对内容
	dest := t.TempDir()
	got, err := ExtractTarGz(bytes.NewReader(buf.Bytes()), dest)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("解出 %d 个文件, 期望 4", len(got))
	}
	for _, rel := range files {
		orig, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		extract, err := os.ReadFile(filepath.Join(dest, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("解包缺少 %s: %v", rel, err)
		}
		if string(orig) != string(extract) {
			t.Fatalf("%s 内容不一致", rel)
		}
	}
}

func TestExtractRejectsPathTraversal(t *testing.T) {
	// 手工构造带 ../evil.txt 的恶意归档
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	hdr := &tar.Header{Name: "../evil.txt", Mode: 0o644, Size: 5, Typeflag: tar.TypeReg}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	tw.Write([]byte("pwned"))
	tw.Close()
	gz.Close()

	dest := t.TempDir()
	if _, err := ExtractTarGz(bytes.NewReader(buf.Bytes()), dest); err == nil {
		t.Fatal("../ 穿越条目应当被拒绝")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dest), "evil.txt")); err == nil {
		t.Fatal("穿越文件不应被写出")
	}
}

// buildTestArchive 在 tmpDir 里放好 manifest/db.dump/files.tar.gz 并打包为 .zrebackup。
// corruptDB 为 true 时让 db.dump 内容与 manifest 里登记的 sha256 不一致。
func buildTestArchive(t *testing.T, corruptDB bool) string {
	t.Helper()
	root := writeTestTree(t)
	t.Chdir(root)

	tmp := t.TempDir()
	// files.tar.gz
	var filesBuf bytes.Buffer
	fileList, err := ArchiveDirs(DefaultFileDirs, &filesBuf, os.Stderr)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, entryFiles), filesBuf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	// db.dump
	dbContent := []byte("fake-custom-format-dump")
	if corruptDB {
		dbContent = []byte("tampered-after-signing")
	}
	dbSum := hashBytes([]byte("fake-custom-format-dump")) // manifest 永远登记原始内容
	if err := os.WriteFile(filepath.Join(tmp, entryDB), dbContent, 0o644); err != nil {
		t.Fatal(err)
	}
	// manifest
	m := Manifest{
		Version:   FormatVersion,
		CreatedAt: time.Now(),
		Tool:      toolName,
		Source:    SourceInfo{Host: "127.0.0.1", Port: 25433, User: "zre", DBName: "zreark", Schema: "zre"},
		Entries: []EntryInfo{
			{Name: entryDB, Size: int64(len(dbContent)), SHA256: dbSum},
			{Name: entryFiles, Size: int64(len(filesBuf.Bytes())), SHA256: hashBytes(filesBuf.Bytes())},
		},
		Files: fileList,
	}
	mf, err := os.Create(filepath.Join(tmp, entryManifest))
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteManifest(mf, &m); err != nil {
		t.Fatal(err)
	}
	mf.Close()

	out := filepath.Join(t.TempDir(), "zre-test"+Ext)
	if err := writeArchiveFile(out, tmp); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestValidateArchiveOK(t *testing.T) {
	archive := buildTestArchive(t, false)
	m, err := ValidateArchive(archive)
	if err != nil {
		t.Fatalf("合法归档不应报错: %v", err)
	}
	if m.Source.DBName != "zreark" || m.Source.Schema != "zre" {
		t.Fatalf("manifest 源信息不对: %+v", m.Source)
	}
	if len(m.Files) != 4 {
		t.Fatalf("文件清单应有 4 项, 实得 %d", len(m.Files))
	}
	// 只读 manifest 的轻量路径也应成功
	m2, err := ReadArchiveManifest(archive)
	if err != nil || m2.Source.DBName != "zreark" {
		t.Fatalf("ReadArchiveManifest 失败: %v", err)
	}
}

func TestValidateArchiveDetectsCorruption(t *testing.T) {
	archive := buildTestArchive(t, true) // db.dump 内容与 manifest sha256 不一致
	if _, err := ValidateArchive(archive); err == nil {
		t.Fatal("被篡改的 db.dump 应当导致 sha256 校验失败")
	} else if !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("错误信息应提到 sha256, 实得: %v", err)
	}
}

func TestValidateArchiveRejectsForeignFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "not-a-backup"+Ext)
	os.WriteFile(p, []byte("plain text, not gzip"), 0o644)
	if _, err := ValidateArchive(p); err == nil {
		t.Fatal("非归档文件应当报错")
	}
}

func TestFindToolPrefersExtraDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX 脚本桩，Windows 跳过")
	}
	fakeDir := t.TempDir()
	script := "#!/bin/sh\necho fake\n"
	for _, name := range []string{"pg_dump", "psql"} {
		p := filepath.Join(fakeDir, name)
		if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	// --pg-bin 目录优先于 PATH：即使宿主机装了真 pg_dump 也返回桩
	got, err := FindTool("pg_dump", fakeDir)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(got) != fakeDir {
		t.Fatalf("应优先返回 -pg-bin 里的桩, 实得 %s", got)
	}

	// PATH 回退：extraDir 为空时能在系统 PATH 里找到 pg_dump（CI/本机装了 postgresql-client）
	got, err = FindTool("pg_dump", "")
	if err != nil {
		t.Skipf("宿主机未安装 pg_dump, 跳过 PATH 回退断言: %v", err)
	}
	if got == "" {
		t.Fatal("PATH 回退结果为空")
	}

	// 两者都找不到 → 中文可操作错误
	if _, err := FindTool("zre-no-such-tool-xyz", ""); err == nil {
		t.Fatal("不存在的工具应当报错")
	}
}

func TestToolMissingErrorIsActionable(t *testing.T) {
	err := toolMissingError("pg_dump", "", &Target{Host: "127.0.0.1", Port: 25433, User: "zre", DBName: "zreark", Schema: "zre"})
	msg := err.Error()
	for _, want := range []string{"postgresql-client", "-pg-bin", "docker exec", "pg_dump", "zreark"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("错误信息缺少可操作指引 %q:\n%s", want, msg)
		}
	}
}

func TestBackupExistingDirs(t *testing.T) {
	root := t.TempDir()
	dirs := []string{"config/dicts", "pocs"}
	for _, d := range dirs {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(d)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// 不存在的目录要被忽略
	ghost := "configs"
	if err := os.MkdirAll(filepath.Join(root, "elsewhere"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)

	now := time.Date(2026, 10, 23, 15, 30, 0, 0, time.UTC)
	backed := backupExistingDirs(append(dirs, ghost), now, os.Stderr)
	if len(backed) != 2 {
		t.Fatalf("应备份 2 个存在的目录, 实得 %v", backed)
	}
	for _, d := range dirs {
		want := d + ".bak-20261023-153000"
		if _, err := os.Stat(want); err != nil {
			t.Fatalf("旧目录应改名为 %s: %v", want, err)
		}
		if _, err := os.Stat(d); !os.IsNotExist(err) {
			t.Fatalf("原目录 %s 应已让位", d)
		}
	}

	// 同名 .bak 已占用时追加序号，不覆盖已有备份
	if err := os.MkdirAll("config/dicts", 0o755); err != nil {
		t.Fatal(err)
	}
	backed2 := backupExistingDirs([]string{"config/dicts"}, now, os.Stderr)
	if len(backed2) != 1 || !strings.HasSuffix(backed2[0], "-1") {
		t.Fatalf("重名备份应追加序号: %v", backed2)
	}
}

func TestOnlyBenignRestoreErrorsClassifier(t *testing.T) {
	benign := "pg_restore: error: could not execute query: ERROR:  schema \"zre\" already exists\n" +
		"pg_restore: error: could not execute query: ERROR:  cannot drop inherited constraint \"scan_results_2026_10_pkey\" of relation \"scan_results_2026_10\"\n" +
		"pg_restore: error: errors ignored on restore: 4\n"
	if !onlyBenignRestoreErrors(benign) {
		t.Fatal("schema 撞名/分区继承约束错误应判为可忽略")
	}
	fatal := benign + "pg_restore: error: could not execute query: ERROR:  relation \"zre.users\" does not exist\n"
	if onlyBenignRestoreErrors(fatal) {
		t.Fatal("含其他 SQL 错误时不应判为可忽略")
	}
	if onlyBenignRestoreErrors("") {
		t.Fatal("没有错误时不应走该分支")
	}
}

func TestHumanBytes(t *testing.T) {
	cases := map[int64]string{
		512:     "512 B",
		1024:    "1.0 KB",
		7834789: "7.5 MB",
		5 << 30: "5.0 GB",
	}
	for in, want := range cases {
		if got := humanBytes(in); got != want {
			t.Fatalf("humanBytes(%d) = %q, 期望 %q", in, got, want)
		}
	}
}
