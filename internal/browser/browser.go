// Package browser 浏览器探测与无头操作（报告渲染/截图、SPA 爬虫、数据源
// 扫码登录、小蓝本签名通道共用的唯一检测入口）。
//
// 检测顺序：环境变量（ZRE_CHROME > ZRE_XLB_CHROME）> 标准安装位 > PATH
// 常见命令名 > 项目统一 bin 根（data/bin/browser，ZRE_BIN_DIR 可覆盖）
// > rod 历史 HOME 缓存 > playwright 缓存。每个候选逐一 --version
// 实跑探活——文件存在不代表能用（Ubuntu 的 chromium-browser 可能是指向
// snap 的坏 stub，启动时才报错），探活阶段直接淘汰。
//
// 结果进程级缓存：探测要 spawn 进程，且浏览器安装状态在进程生命周期内
// 不会变化；安装浏览器后需重启进程生效。
//
// 目录管理：自带浏览器落在项目统一可执行资产根 data/bin/browser/
//（ZRE_BIN_DIR 覆盖根）；扫描工具 data/tools/（ZRE_TOOLS_DIR）与 nuclei
// data/nuclei/（ZRE_NUCLEI_DIR）沿用既有根，需要归拢时设对应环境变量。
// 部署建议：Dockerfile/安装脚本执行 `apt-get install -y chromium` 即可被
// 探测到；路径特殊的环境用 ZRE_CHROME 指定可执行文件。
package browser

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/internal/datadir"
	"github.com/go-rod/rod/lib/launcher"
)

// ProbeTimeout 单个候选 --version 探活的超时。
const ProbeTimeout = 5 * time.Second

var (
	once      sync.Once
	foundPath string
	misses    []string // 探测失败原因清单（诊断用）
)

// envOverrides 环境变量覆盖，按优先级排列。ZRE_CHROME 是全平台通用名，
// ZRE_XLB_CHROME 是小蓝本文档历史用名，保留兼容。
var envOverrides = []string{"ZRE_CHROME", "ZRE_XLB_CHROME"}

// Candidates 按优先级枚举候选浏览器路径。
func Candidates() []string {
	var out []string
	for _, env := range envOverrides {
		if p := strings.TrimSpace(os.Getenv(env)); p != "" {
			out = append(out, p)
		}
	}
	out = append(out,
		"/usr/bin/google-chrome", "/usr/bin/google-chrome-stable",
		"/usr/bin/chromium", "/usr/bin/chromium-browser",
		"/snap/bin/chromium",
		"/opt/google/chrome/chrome",
	)
	// PATH 上的常见命令名（自定义安装与桌面环境）
	for _, name := range []string{
		"google-chrome", "google-chrome-stable",
		"chromium", "chromium-browser", "microsoft-edge",
	} {
		if p, err := exec.LookPath(name); err == nil {
			out = append(out, p)
		}
	}
	home, err := os.UserHomeDir()
	if err == nil {
		// 项目统一 bin 根的自带浏览器（优先于 HOME 各缓存）
		if m, _ := filepath.Glob(filepath.Join(BinRoot(), "browser", "chromium-*", "chrome")); len(m) > 0 {
			sort.Sort(sort.Reverse(sort.StringSlice(m)))
			out = append(out, m...)
		}
		// rod 按需下载的浏览器（历史落点：HOME 缓存，兼容未迁移的部署），
		// 新版本目录在前
		if m, _ := filepath.Glob(filepath.Join(home, ".cache", "rod", "browser", "*", "chrome")); len(m) > 0 {
			sort.Sort(sort.Reverse(sort.StringSlice(m)))
			out = append(out, m...)
		}
		// playwright 缓存（目录形态随版本变化，用通配）
		if m, _ := filepath.Glob(filepath.Join(home, ".cache", "ms-playwright", "*", "chrome-linux*", "chrome")); len(m) > 0 {
			out = append(out, m...)
		}
	}
	return out
}

// ProbeChrome 试跑 --version 验证浏览器二进制可用
func ProbeChrome(bin string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), ProbeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "--version")
	return cmd.Run() == nil
}

// FindChrome 返回本机可用的浏览器二进制；找不到时自动下载 rod 托管的
// Chromium（项目自带浏览器，不要求宿主机预装），下载产物与系统安装同等
// 参与 --version 探活。全失败返回 ""（原因留档日志）。结果进程级缓存。
func FindChrome() string {
	once.Do(func() {
		foundPath = detect()
		if foundPath == "" {
			// 自带浏览器兜底：项目不依赖宿主机预装。下载 ~150MB，
			// 三源竞速（Google/NPM/Playwright），尊重 HTTPS_PROXY。
			if bin, ok := ensureDownloaded(""); ok {
				if ProbeChrome(bin) {
					foundPath = bin
					log.Printf("[browser] 已自动下载项目自带浏览器: %s", bin)
					return
				}
				log.Printf("[browser] 自带浏览器下载完成但探活失败: %s", bin)
			}
			log.Printf("[browser] 未检测到可用浏览器（含自动下载），候选探测记录: %s", strings.Join(misses, "; "))
		}
	})
	return foundPath
}

// detect 按候选枚举 + --version 探活寻找系统已有浏览器。
func detect() string {
	for _, p := range Candidates() {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err != nil {
			misses = append(misses, p+": 不存在")
			continue
		}
		if !ProbeChrome(p) {
			misses = append(misses, p+": 无法执行（snap stub 或依赖缺失）")
			continue
		}
		return p
	}
	return ""
}

// DownloadTimeout 自动下载浏览器整体超时（~150MB，弱网容忍）。
const DownloadTimeout = 10 * time.Minute

// BinRoot 返回统一可执行资产根（data/bin，ZRE_BIN_DIR 覆盖）。
// 目录约定与历史目录收编统一在 internal/datadir，此处委托。
func BinRoot() string { return datadir.BinRoot() }

// DownloadDir 自带浏览器的下载根（<bin>/browser/chromium-<rev>/chrome）。
func DownloadDir() string {
	return filepath.Join(BinRoot(), "browser")
}

// ensureDownloaded 下载 rod 托管的 Chromium 到项目统一 bin 根
//（data/bin/browser/chromium-<rev>/chrome），成功返回可执行路径。
// rootDir 非空时覆盖下载目录（测试隔离用）。
// 下载源三选一竞速（Google/NPM/Playwright），尊重 HTTPS_PROXY 环境变量。
func ensureDownloaded(rootDir string) (string, bool) {
	b := launcher.NewBrowser()
	b.RootDir = DownloadDir()
	if rootDir != "" {
		b.RootDir = rootDir
	}
	if err := os.MkdirAll(b.RootDir, 0o750); err != nil {
		log.Printf("[browser] 创建下载目录失败: %v", err)
		return "", false
	}
	ctx, cancel := context.WithTimeout(context.Background(), DownloadTimeout)
	defer cancel()
	b.Context = ctx
	// 下载进度走标准日志（rod 默认打到 stdout，会混进业务输出）
	b.Logger = log.New(os.Stderr, "[browser-download] ", log.LstdFlags)
	if err := b.Download(); err != nil {
		log.Printf("[browser] 自动下载失败（网络需可达 playwright.azureedge.net/npm/Google 源，或配置 HTTPS_PROXY）: %v", err)
		return "", false
	}
	bin := b.BinPath()
	if _, err := os.Stat(bin); err != nil {
		log.Printf("[browser] 下载完成但可执行文件缺失: %s", bin)
		return "", false
	}
	return bin, true
}

// MissingError 找不到浏览器时的用户提示（自动下载也失败后的兜底）：
// 给出可操作的安装/指定途径。purpose 描述调用方业务（如「报告 PDF 渲染」
// 「扫码登录」）。
func MissingError(purpose string) error {
	return fmt.Errorf("%s需要本机 Chrome/Chromium：自动检测未找到，且自带浏览器自动下载失败（需可达 playwright.azureedge.net 等下载源，代理环境请配置 HTTPS_PROXY）。"+
		"处理方式任选其一：① 修复网络/代理后重试（平台会自动下载自带浏览器）；"+
		"② 安装 Chrome/Chromium（apt install chromium-browser 或官网安装包）；"+
		"③ 已装有但路径特殊时设置环境变量 ZRE_CHROME 指向可执行文件后重启", purpose)
}

// ---------- 工具运行时面板集成：状态视图与更新 ----------

// launcher 包的 RevisionDefault 在编译期固定（随 rod 依赖升级而变），
// 这里取不到常量就动态构造一个 NewBrowser 读它。
func currentRevision() int {
	return launcher.NewBrowser().Revision
}

// Status 返回浏览器运行时状态（工具运行时面板的 browser 条目）。
// installed/path 取自统一检测；revision 仅对 rod 托管下载的产物有意义
//（系统安装的浏览器版本随系统，无 rod revision 口径）。
// update_available：rod 托管产物 revision 落后于当前平台期望（rod 依赖
// 升级会带新 revision），提示面板触发更新。
func Status() map[string]any {
	path := FindChrome()
	out := map[string]any{
		"name":             "browser",
		"description":      "Chromium（报告渲染/SPA 爬虫/扫码登录/小蓝本签名通道共用）",
		"installed":        path != "",
		"path":             path,
		"update_available": false,
	}
	if path == "" {
		out["revision"] = currentRevision()
		out["note"] = "未安装：首次使用时将自动下载自带浏览器"
		return out
	}

	// --version 输出作展示版本（系统安装与 rod 产物都适用）
	if v, err := exec.Command(path, "--version").Output(); err == nil {
		out["version"] = strings.TrimSpace(string(v))
	}
	if st, err := os.Stat(path); err == nil {
		out["size_bytes"] = st.Size()
	}

	// 来源与 revision：rod 托管目录下的产物解析目录名 chromium-<rev>
	want := currentRevision()
	out["expected_revision"] = want
	if dir := filepath.Base(filepath.Dir(path)); strings.HasPrefix(dir, "chromium-") {
		out["source"] = "bundled"
		if rev, perr := strconv.Atoi(strings.TrimPrefix(dir, "chromium-")); perr == nil {
			out["revision"] = rev
			if rev < want {
				out["update_available"] = true
				out["note"] = "自带浏览器 revision 落后于当前平台期望，可在面板触发更新"
			}
		}
	} else {
		out["source"] = "system"
		out["note"] = "系统安装的浏览器，随系统更新；ZRE_CHROME 可固定指定"
	}
	return out
}

// Update 重新自举自带浏览器：下载当前平台期望的 revision（已存在时
// 快速返回），探活通过后返回新状态。系统安装的浏览器不走此通道。
func Update(ctx context.Context) (map[string]any, error) {
	if path := FindChrome(); path != "" {
		if dir := filepath.Base(filepath.Dir(path)); !strings.HasPrefix(dir, "chromium-") {
			return Status(), nil // 系统安装：无更新通道
		}
	}
	done := make(chan struct{})
	go func() {
		<-done
	}()
	bin, ok := ensureDownloaded("")
	if !ok {
		return nil, fmt.Errorf("自带浏览器下载失败（需可达下载源或配置 HTTPS_PROXY）")
	}
	if !ProbeChrome(bin) {
		return nil, fmt.Errorf("下载产物探活失败: %s", bin)
	}
	// 进程缓存已在首次 FindChrome 时填充；下载出更新 revision 后覆盖，
	// 后续调用方拿到新产物。
	foundPath = bin
	return Status(), nil
}
