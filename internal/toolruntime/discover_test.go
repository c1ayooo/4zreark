package toolruntime

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func writeDiscoverToolFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

// 只检索项目内部目录：隐藏文件、备份、文本、空文件、子目录都不算工具，
// 同名工具按 managed > vendored 去重，系统 PATH 不参与发现。
func TestDiscoverInstalledOnlyProjectDirs(t *testing.T) {
	root := t.TempDir()
	managed := filepath.Join(root, "data", "bin", "tools", OSDir(runtime.GOOS))
	vendored := filepath.Join(root, "tools", OSDir(runtime.GOOS))
	nucleiBin := filepath.Join(root, "data", "bin", "nuclei", "bin", "nuclei")
	for _, p := range []string{
		filepath.Join(managed, "gogo"),
		filepath.Join(managed, "katana"),
		filepath.Join(vendored, "rem"),
		filepath.Join(vendored, "gogo"), // 与托管同名，应被托管版本压过
		nucleiBin,
	} {
		writeDiscoverToolFile(t, p, "binary", 0o755)
	}
	writeDiscoverToolFile(t, filepath.Join(managed, "gogo.prev"), "old", 0o644)
	writeDiscoverToolFile(t, filepath.Join(managed, "notes.txt"), "note", 0o644)
	writeDiscoverToolFile(t, filepath.Join(managed, ".hidden"), "x", 0o755)
	writeDiscoverToolFile(t, filepath.Join(managed, "empty"), "", 0o755)
	if err := os.MkdirAll(filepath.Join(managed, "subdir"), 0o755); err != nil {
		t.Fatal(err)
	}

	res := DiscoverInstalled(DiscoverOptions{
		ManagedDir: managed, VendoredDirs: []string{vendored}, NucleiBin: nucleiBin,
	})
	if len(res.Items) != 4 {
		t.Fatalf("应发现 4 个项目内工具，实际 %d: %+v", len(res.Items), res.Items)
	}
	byName := map[string]InstalledTool{}
	for _, it := range res.Items {
		byName[it.Name] = it
		if !it.InProject || !it.Executable || it.SizeBytes == 0 {
			t.Errorf("%s 应为项目内可执行文件: %+v", it.Name, it)
		}
	}
	if byName["gogo"].Source != SourceManaged {
		t.Errorf("gogo 应来自托管目录: %s", byName["gogo"].Source)
	}
	if byName["rem"].Source != SourceVendored {
		t.Errorf("rem 应来自 vendored 目录: %s", byName["rem"].Source)
	}
	if byName["nuclei"].Source != SourceNuclei {
		t.Errorf("nuclei 应来自独立运行时: %s", byName["nuclei"].Source)
	}
	if len(res.Roots) != 3 {
		t.Errorf("应报告 3 个检索目录: %v", res.Roots)
	}

	if got := FilterInstalled(res.Items, InstalledFilter{Query: "kata"}); len(got) != 1 || got[0].Name != "katana" {
		t.Fatalf("关键字检索失败: %+v", got)
	}
	if got := FilterInstalled(res.Items, InstalledFilter{Source: SourceManaged}); len(got) != 2 {
		t.Fatalf("来源过滤失败: %+v", got)
	}
	managedOnly := true
	if got := FilterInstalled(res.Items, InstalledFilter{Managed: &managedOnly}); len(got) != 3 {
		t.Fatalf("受管过滤失败（nuclei 非受管）: %+v", got)
	}
	externalOnly := false
	if got := FilterInstalled(res.Items, InstalledFilter{InProject: &externalOnly}); len(got) != 0 {
		t.Fatalf("项目内条目不应命中外部过滤: %+v", got)
	}
}

// 平台安装检测不看系统 PATH：PATH 上能解析到工具时 ProjectToolPath 仍为空，
// 因此 EnsureInstalled 不会跳过项目内自动安装；运行时 PATH 兜底保持不变。
func TestProjectToolPathIgnoresSystemPATH(t *testing.T) {
	root := t.TempDir()
	sysDir := filepath.Join(root, "sys")
	writeDiscoverToolFile(t, filepath.Join(sysDir, "katana"), "system", 0o755)
	t.Setenv("PATH", sysDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("ZRE_TOOL_KATANA_PATH", "")

	m := New(root, nil)
	if got := m.ProjectToolPath("katana"); got != "" {
		t.Fatalf("系统 PATH 不应算平台项目内安装: %s", got)
	}
	resolved := m.ResolveToolPath("katana")
	if resolved == "" {
		t.Fatal("运行时 PATH 兜底应仍可用")
	}
	if got := m.ToolSource("katana", resolved); got != SourceSystem {
		t.Fatalf("PATH 解析来源应为 system: %s", got)
	}

	projectBin := m.BinaryPath("katana")
	writeDiscoverToolFile(t, projectBin, "project", 0o755)
	if got := m.ProjectToolPath("katana"); got == "" {
		t.Fatal("装进托管目录后应被检测为项目内安装")
	}
	if got := m.ToolSource("katana", projectBin); got != SourceManaged {
		t.Fatalf("托管目录来源应为 managed: %s", got)
	}
}
