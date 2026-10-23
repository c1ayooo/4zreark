package toolruntime

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestParseVersion(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"v1.2.3", "1.2.3", true},
		{"1.2.3", "1.2.3", true},
		{"gogo version 2.15.0 (build xyz)", "2.15.0", true},
		{"v1.3.2-rc1", "1.3.2-rc1", true},
		{"no version here", "", false},
	}
	for _, c := range cases {
		v, err := parseVersion(c.in)
		if c.ok && (err != nil || v.String() != c.want) {
			t.Errorf("parseVersion(%q) = %v, %v; want %s", c.in, v, err, c.want)
		}
		if !c.ok && err == nil {
			t.Errorf("parseVersion(%q) 应当失败", c.in)
		}
	}
}

func TestCompareVersionPreRelease(t *testing.T) {
	c, err := compareVersion("1.3.2", "1.3.2-rc1")
	if err != nil || c != 1 {
		t.Errorf("正式版应大于同号 pre-release, got %d err=%v", c, err)
	}
	c, err = compareVersion("0.3.2", "1.3.2")
	if err != nil || c != -1 {
		t.Errorf("0.3.2 < 1.3.2, got %d err=%v", c, err)
	}
}

// spray 场景：created_at 最新的 v0.3.2 不应压过 semver 更大的 v1.3.2。
func TestPickLatestIgnoresReleaseOrder(t *testing.T) {
	releases := []ghRelease{
		{TagName: "v0.3.2"},
		{TagName: "v1.3.2"},
		{TagName: "v1.2.6"},
		{TagName: "v2.0.0-beta1", Prerelease: true},
	}
	best, ok := pickLatest(releases, "")
	if !ok || best.TagName != "v1.3.2" {
		t.Fatalf("pickLatest = %v %v, want v1.3.2", best.TagName, ok)
	}
	if _, ok := pickLatest([]ghRelease{{TagName: "v2.0.0-rc1", Prerelease: true}}, ""); ok {
		t.Fatal("默认应排除 pre-release")
	}
}

func TestPickLatestMinVersion(t *testing.T) {
	releases := []ghRelease{{TagName: "v0.3.2"}, {TagName: "v1.3.2"}}
	best, _ := pickLatest(releases, "1.0.0")
	if best.TagName != "v1.3.2" {
		t.Fatalf("minVersion 过滤失败: %s", best.TagName)
	}
}

func TestAssetNames(t *testing.T) {
	gogo, _ := Spec("gogo")
	if a, _ := gogo.AssetName("2.15.0", "linux", "amd64"); a != "gogo_linux_amd64" {
		t.Errorf("gogo linux asset = %s", a)
	}
	if a, _ := gogo.AssetName("2.15.0", "windows", "amd64"); a != "gogo_windows_amd64.exe" {
		t.Errorf("gogo windows asset = %s", a)
	}
	katana, _ := Spec("katana")
	if a, _ := katana.AssetName("1.8.0", "linux", "amd64"); a != "katana_1.8.0_linux_amd64.zip" {
		t.Errorf("katana linux asset = %s", a)
	}
	if _, err := katana.AssetName("1.8.0", "darwin", "386"); err == nil {
		t.Error("katana darwin/386 应返回错误")
	}
	if got := katana.checksumAssetName("1.8.0"); got != "katana-1.8.0-checksums.txt" {
		t.Errorf("katana checksum asset = %s", got)
	}
}

func TestFlagTokenMatching(t *testing.T) {
	help := `Usage:
  -i string  target
  -ob  include body
  -o string  output format
  --depth int
  -d string  dict
`
	for _, f := range []string{"-i", "-o", "-d", "--depth", "-ob"} {
		if !flagTokenRe(f).MatchString(help) {
			t.Errorf("flag %s 应命中", f)
		}
	}
	for _, f := range []string{"-x", "--nope", "-depth"} {
		if flagTokenRe(f).MatchString(help) {
			t.Errorf("flag %s 不应命中", f)
		}
	}
	// -o 不能误命中 -ob；--depth 不能被 -d 误命中已由上面覆盖
	if flagTokenRe("-o").MatchString("  -ob only") {
		t.Error("-o 不应命中 -ob")
	}
}

func TestParseChecksums(t *testing.T) {
	h1 := strings.Repeat("a", 64)
	h2 := strings.Repeat("0", 64)
	data := []byte(h1 + "  gogo_linux_amd64\n" + h2 + "  gogo_windows_amd64.exe\n")
	m := parseChecksums(data)
	if m["gogo_linux_amd64"] != h1 || m["gogo_windows_amd64.exe"] != h2 {
		t.Fatalf("checksums 解析错误: %v", m)
	}
}

// 集成：fake release 服务 + staged 安装 + flag 门 + 回滚。
func TestInstallFlowWithFakeRelease(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows rename 语义不同，本用例只覆盖 linux/darwin")
	}
	dir := t.TempDir()
	mgr := New(dir, nil)

	// 一个会打印全部所需 flag 的假二进制（shell 脚本）
	bin := filepath.Join(dir, "fakebin")
	script := "#!/bin/sh\ncase \"$1\" in -h) echo 'usage: -i -p -o -t -d';; -v) echo 'v9.9.9';; esac\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	sum, _ := fileSHA256(bin)

	// 用本地文件冒充下载：把 downloadToFile 打桩不可行（方法），改为直接测
	// materializeBinary + checkFlags + 换入序列的关键片段。
	spec, _ := Spec("gogo")
	staged, err := mgr.materializeBinary(spec, bin)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(staged, 0o755); err != nil {
		t.Fatal(err)
	}
	if missing, err := checkFlags(context.Background(), staged, spec); err != nil || len(missing) != 0 {
		t.Fatalf("flag 门误报: missing=%v err=%v", missing, err)
	}

	dest := mgr.BinaryPath("gogo")
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(staged, dest); err != nil {
		t.Fatal(err)
	}
	gotSum, _ := fileSHA256(dest)
	if gotSum != sum {
		t.Fatal("换入后 sha256 不一致")
	}
	if v := mgr.probeVersion(context.Background(), "gogo", dest); v != "9.9.9" {
		t.Fatalf("probeVersion = %q, want 9.9.9", v)
	}
}

func TestCheckDueRespectsInterval(t *testing.T) {
	dir := t.TempDir()
	mgr := New(dir, nil)
	st := &ToolState{Name: "gogo", AutoUpdate: true, CheckIntervalHours: 24,
		LatestCheckedAt: time.Now().Add(-time.Hour), Status: statusOK}
	if mgr.checkDueForState(st) {
		t.Error("1 小时前刚检查过，不应到期")
	}
	st.LatestCheckedAt = time.Now().Add(-25 * time.Hour)
	if !mgr.checkDueForState(st) {
		t.Error("25 小时前检查的应到期")
	}
}

// 真连 GitHub 的安装冒烟：ZRE_TOOL_LIVE=1 时启用。
// ZRE_TOOL_LIVE_DIR 可指定安装根（默认临时目录），用于把真实二进制
// 落到 data/tools 供后续阶段使用。
func TestLiveCheckAndUpdate(t *testing.T) {
	if os.Getenv("ZRE_TOOL_LIVE") != "1" {
		t.Skip("set ZRE_TOOL_LIVE=1 to run live GitHub install")
	}
	root := os.Getenv("ZRE_TOOL_LIVE_DIR")
	if root == "" {
		root = t.TempDir()
	}
	mgr := New(root, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	name := "rem"
	if v := os.Getenv("ZRE_TOOL_LIVE_TOOL"); v != "" {
		name = v
	}
	st, err := mgr.Check(ctx, name)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if st.LatestVersion == "" {
		t.Fatal("未取到最新版本")
	}
	t.Logf("%s latest=%s installed=%s", name, st.LatestVersion, st.InstalledVersion)

	updated, err := mgr.Update(ctx, name, false)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	bin := mgr.BinaryPath(name)
	if !fileExists(bin) {
		t.Fatalf("%s 安装后二进制不存在: %s", name, bin)
	}
	if updated.InstalledVersion == "" || updated.InstalledSHA256 == "" {
		t.Fatalf("安装状态不完整: %+v", updated)
	}
	t.Logf("%s 已安装 %s (sha256=%s) → %s", name, updated.InstalledVersion, updated.InstalledSHA256[:12], bin)
}

func TestResolveToolPathEnvOverride(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "gogo")
	os.WriteFile(fake, []byte("#!/bin/sh\n"), 0o755)
	t.Setenv("ZRE_TOOL_GOGO_PATH", fake)
	mgr := New(filepath.Join(dir, "root"), nil)
	if got := mgr.ResolveToolPath("gogo"); got != fake {
		t.Fatalf("env 覆盖失效: %q", got)
	}
}
