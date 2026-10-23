// Package toolruntime 统一管理外部扫描工具二进制（gogo / spray / katana / rem）：
// 版本发现、下载校验、staged 安装、回滚与路径解析。
//
// 设计约束：
//   - 更新永不阻断扫描：解析不到托管二进制时回退 vendored tools/<os>/ 与 PATH；
//   - 换版前先过探针（版本可执行 + 我们使用的 flag 仍存在），失败保持旧版；
//   - nuclei 有独立的 nucleiruntime（模板/沙箱体系），本包不接管，仅在 API 聚合展示。
package toolruntime

import (
	"fmt"
	"runtime"
	"strings"
)

// ArchiveKind release 资产的形态。chainreactors 系按平台出裸二进制，
// projectdiscovery 系出 zip；下载后按魔数嗅探，这里只是缺省值。
type ArchiveKind string

const (
	ArchiveRaw   ArchiveKind = "raw"
	ArchiveZip   ArchiveKind = "zip"
	ArchiveTarGz ArchiveKind = "tar.gz"
)

// ToolSpec 描述一个受管工具。AssetName/ChecksumAsset 必须覆盖
// windows（带 .exe 后缀）与 darwin/arm64 等平台差异，不支持时返回错误。
type ToolSpec struct {
	Name        string
	Repo        string // "chainreactors/gogo"
	Description string

	DefaultVersion string // 首次安装的 pin 版本
	MinVersion     string // 低于该版本的 release 一律忽略（semver）

	// AssetName 返回 release 里对应平台的资产文件名。
	AssetName func(version, goos, goarch string) (string, error)
	// ChecksumAsset 返回 sha256 清单资产名（与平台无关）。
	ChecksumAsset string
	Archive       ArchiveKind

	// VersionProbeArgs 运行后能打印版本号的参数（尽力而为，不作为门）。
	VersionProbeArgs []string
	// HelpArgs 运行后打印用法/flag 列表的参数，flag 探针的门。
	HelpArgs []string

	// RequiredFlags 是各 runner buildArgs 实际使用的 flag 全集。
	// 换版前跑 HelpArgs 断言全部仍在；上游改名会在更新门被拦下。
	// 新增 flag 用法时同步维护这里（与 runner 代码同仓同评审）。
	RequiredFlags []string
}

// Specs 是受管工具注册表；顺序即 /api/tools 列表顺序。
var Specs = []ToolSpec{
	{
		Name:        "gogo",
		Repo:        "chainreactors/gogo",
		Description: "端口扫描与服务/协议识别",
		// 与 tools/linux 下 vendored 版本一致（2026-10 校验）
		DefaultVersion: "2.15.0",

		AssetName: func(version, goos, goarch string) (string, error) {
			name := fmt.Sprintf("gogo_%s_%s", goos, goarch)
			if goos == "windows" {
				name += ".exe"
			}
			return name, nil
		},
		ChecksumAsset:    "gogo_checksums.txt",
		Archive:          ArchiveRaw,
		VersionProbeArgs: []string{"-v"},
		HelpArgs:         []string{"-h"},

		// scanner/portscan/gogo_runner.go ScanPorts
		RequiredFlags: []string{"-i", "-p", "-o", "-t", "-d"},
	},
	{
		Name:        "spray",
		Repo:        "chainreactors/spray",
		Description: "目录爆破（JSON 输出）",
		// 注意：spray 的 release 按 created_at 排序 latest 是 v0.3.2，
		// semver 最大是 v1.3.2；更新检查按 semver 取最大且默认只升不降。
		DefaultVersion: "1.3.2",

		AssetName: func(version, goos, goarch string) (string, error) {
			name := fmt.Sprintf("spray_%s_%s", goos, goarch)
			if goos == "windows" {
				name += ".exe"
			}
			return name, nil
		},
		ChecksumAsset:    "spray_checksums.txt",
		Archive:          ArchiveRaw,
		VersionProbeArgs: nil, // spray v1.3.2 无版本打印参数，版本以 release tag 为准
		HelpArgs:         []string{"-h"},

		// scanner/webscan/spray.go buildArgs（单目标/批量两条路径）
		RequiredFlags: []string{"-u", "-l", "-t", "-j", "-f", "--no-color", "--no-bar",
			"-d", "-D", "--rate-limit", "--depth", "--finger", "--crawl", "--bak",
			"--common"},
	},
	{
		Name:           "katana",
		Repo:           "projectdiscovery/katana",
		Description:    "Web 爬虫（JSONL 输出）",
		DefaultVersion: "1.8.0",

		AssetName: func(version, goos, goarch string) (string, error) {
			if goos == "darwin" && (goarch == "386" || goarch == "arm") {
				return "", fmt.Errorf("katana 没有 darwin/%s 官方构建", goarch)
			}
			return fmt.Sprintf("katana_%s_%s_%s.zip", trimV(version), goos, goarch), nil
		},
		ChecksumAsset:    "", // 清单名带版本号（katana-<ver>-checksums.txt），在 github.go 动态拼
		Archive:          ArchiveZip,
		VersionProbeArgs: []string{"-version"},
		HelpArgs:         []string{"-h"},

		// scanner/webscan/katana.go commonArgs + 单目标/列表参数
		RequiredFlags: []string{"-d", "-c", "-timeout", "-rl", "-fs", "-H", "-silent",
			"-jsonl", "-ob", "-or", "-ef", "-jc", "-jsl", "-kf", "-o", "-u", "-list"},
	},
	{
		Name:           "rem",
		Repo:           "chainreactors/rem",
		Description:    "节点部署反向隧道（gost 替代）",
		DefaultVersion: "0.3.0",

		AssetName: func(version, goos, goarch string) (string, error) {
			name := fmt.Sprintf("rem_%s_%s", goos, goarch)
			if goos == "windows" {
				name += ".exe"
			}
			return name, nil
		},
		ChecksumAsset:    "rem_checksums.txt",
		Archive:          ArchiveRaw,
		VersionProbeArgs: []string{"--version"},
		HelpArgs:         []string{"-h"},

		// api/node_tunnel.go：目标侧 -s -k，master 侧 -c -r port://监听/目标。
		// 重要：反向转发依赖 fork 补丁（~/rem 仓 4f21541，官方 v0.3.0 数据面不通）；
		// 官方发布修复后可直接换回官方 release。
		RequiredFlags: []string{"-s", "-c", "-r", "-k"},
	},
}

var specByName = func() map[string]ToolSpec {
	m := make(map[string]ToolSpec, len(Specs))
	for _, s := range Specs {
		m[s.Name] = s
	}
	return m
}()

// Spec 返回工具规格；不存在时第二返回值为 false。
func Spec(name string) (ToolSpec, bool) {
	s, ok := specByName[name]
	return s, ok
}

// SpecNames 受管工具名列表。
func SpecNames() []string {
	names := make([]string, 0, len(Specs))
	for _, s := range Specs {
		names = append(names, s.Name)
	}
	return names
}

// checksumAssetName 解析某版本对应的 sha256 清单资产名。
func (t ToolSpec) checksumAssetName(version string) string {
	if t.Name == "katana" {
		return fmt.Sprintf("katana-%s-checksums.txt", trimV(version))
	}
	return t.ChecksumAsset
}

func trimV(v string) string {
	return strings.TrimPrefix(strings.TrimSpace(v), "v")
}

// OSDir 平台到目录名的映射，与 tools/<os>/ 约定一致。
func OSDir(goos string) string {
	switch goos {
	case "darwin", "linux":
		return goos
	case "windows":
		return "win"
	default:
		return "linux"
	}
}

func exeName(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}
