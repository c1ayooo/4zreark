package toolruntime

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// 平台已安装工具的来源。只有 managed / vendored / nuclei / browser 属于
// 「项目内部」；override / system 是环境里发现的外部候选，不算平台自身工具。
const (
	SourceManaged  = "managed"
	SourceVendored = "vendored"
	SourceNuclei   = "nuclei"
	SourceBrowser  = "browser"
	SourceOverride = "override"
	SourceSystem   = "system"
)

// InstalledTool 是平台已安装工具的统一检索视图（不执行二进制，只看磁盘事实）。
type InstalledTool struct {
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Path        string    `json:"path"`
	Source      string    `json:"source"`
	InProject   bool      `json:"in_project"`
	Managed     bool      `json:"managed"`
	Version     string    `json:"version,omitempty"`
	SizeBytes   int64     `json:"size_bytes"`
	Executable  bool      `json:"executable"`
	ModTime     time.Time `json:"mod_time,omitempty"`
	Note        string    `json:"note,omitempty"`
}

// DiscoverOptions 显式指定要检索的项目内目录/文件；零值不做任何扫描。
// 调用方通过 DefaultDiscoverOptions 取平台默认目录，测试可注入临时目录。
type DiscoverOptions struct {
	ManagedDir   string   // 托管目录 <root>/<os>
	VendoredDirs []string // vendored tools/<os> 候选
	NucleiBin    string   // 项目内 nuclei 二进制的完整路径
	BrowserBin   string   // 项目内自带浏览器的完整路径
}

// DiscoverResult 是检索结果；Roots 是实际扫描过的项目内目录，供面板展示。
type DiscoverResult struct {
	Items []InstalledTool `json:"items"`
	Roots []string        `json:"roots"`
}

// DefaultDiscoverOptions 返回平台默认的项目内工具目录。
func DefaultDiscoverOptions() DiscoverOptions {
	opts := DiscoverOptions{ManagedDir: absClean(Default().InstallDir())}
	seen := map[string]bool{}
	for _, d := range legacyToolDirs() {
		p := absClean(filepath.Join(d, OSDir(runtime.GOOS)))
		if !seen[p] {
			seen[p] = true
			opts.VendoredDirs = append(opts.VendoredDirs, p)
		}
	}
	return opts
}

// DiscoverInstalled 只检索项目内部的工具安装，不查 PATH。
// 同名工具按 managed > vendored > nuclei > browser 的优先级去重。
func DiscoverInstalled(opts DiscoverOptions) DiscoverResult {
	res := DiscoverResult{Items: []InstalledTool{}, Roots: []string{}}
	seenName := map[string]bool{}
	seenRoot := map[string]bool{}
	add := func(it InstalledTool) {
		if it.Name == "" || seenName[it.Name] {
			return
		}
		seenName[it.Name] = true
		res.Items = append(res.Items, it)
	}
	addRoot := func(dir string) {
		if dir == "" || seenRoot[dir] {
			return
		}
		seenRoot[dir] = true
		res.Roots = append(res.Roots, dir)
	}

	scanDir := func(dir, source string) {
		if dir == "" {
			return
		}
		dir = absClean(dir)
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		addRoot(dir)
		for _, e := range entries {
			name := e.Name()
			if strings.HasPrefix(name, ".") || isNonBinary(name) {
				continue
			}
			p := filepath.Join(dir, name)
			// os.Stat 跟随符号链接：软链到项目内真实二进制也算平台内安装。
			fi, err := os.Stat(p)
			if err != nil || !fi.Mode().IsRegular() || fi.Size() == 0 {
				continue
			}
			add(newInstalledTool(binaryName(name), p, source, fi))
		}
	}

	scanDir(opts.ManagedDir, SourceManaged)
	for _, d := range opts.VendoredDirs {
		scanDir(d, SourceVendored)
	}
	for _, b := range []struct {
		path   string
		name   string
		source string
	}{
		{opts.NucleiBin, "nuclei", SourceNuclei},
		{opts.BrowserBin, "browser", SourceBrowser},
	} {
		if b.path == "" {
			continue
		}
		p := absClean(b.path)
		fi, err := os.Stat(p)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		add(newInstalledTool(b.name, p, b.source, fi))
		addRoot(filepath.Dir(p))
	}

	sort.Slice(res.Items, func(i, j int) bool { return res.Items[i].Name < res.Items[j].Name })
	return res
}

// InstalledFilter 是平台工具检索条件；指针字段为 nil 时不过滤。
type InstalledFilter struct {
	Query       string
	Source      string
	InProject   *bool
	Managed     *bool
	Executable  *bool
}

// FilterInstalled 按关键字/来源/位置过滤并稳定排序。
func FilterInstalled(items []InstalledTool, f InstalledFilter) []InstalledTool {
	q := strings.ToLower(strings.TrimSpace(f.Query))
	out := make([]InstalledTool, 0, len(items))
	for _, it := range items {
		if q != "" && !strings.Contains(strings.ToLower(it.Name+" "+it.Path+" "+it.Description+" "+it.Source), q) {
			continue
		}
		if f.Source != "" && it.Source != f.Source {
			continue
		}
		if f.InProject != nil && it.InProject != *f.InProject {
			continue
		}
		if f.Managed != nil && it.Managed != *f.Managed {
			continue
		}
		if f.Executable != nil && it.Executable != *f.Executable {
			continue
		}
		out = append(out, it)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func newInstalledTool(name, path, source string, fi os.FileInfo) InstalledTool {
	it := InstalledTool{
		Name:       name,
		Path:       path,
		Source:     source,
		InProject:  true,
		SizeBytes:  fi.Size(),
		ModTime:    fi.ModTime(),
		Executable: runtime.GOOS == "windows" || fi.Mode().Perm()&0o111 != 0,
	}
	if spec, ok := Spec(name); ok {
		it.Managed = true
		it.Description = spec.Description
	}
	switch name {
	case "nuclei":
		it.Description = "漏洞模板执行 / 自动验证（独立运行时）"
	case "browser":
		it.Description = "Chromium（报告渲染 / SPA 爬虫）"
	}
	if source == SourceVendored {
		it.Note = "项目内 vendored 目录，非托管安装"
	}
	if !it.Executable {
		it.Note = strings.TrimSpace(it.Note + " 文件没有执行权限")
	}
	return it
}

func binaryName(file string) string {
	return strings.TrimSuffix(file, ".exe")
}

func isNonBinary(name string) bool {
	l := strings.ToLower(name)
	for _, ext := range []string{
		".prev", ".tmp", ".bak", ".old", ".zip", ".gz", ".tgz", ".txt",
		".json", ".yaml", ".yml", ".md", ".sha256", ".log",
	} {
		if strings.HasSuffix(l, ext) {
			return true
		}
	}
	return false
}

func absClean(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		return filepath.Clean(abs)
	}
	return filepath.Clean(p)
}
