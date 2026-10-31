// Package browser 浏览器探测与无头操作（报告渲染/截图、SPA 爬虫、数据源
// 扫码登录、小蓝本签名通道共用的唯一检测入口）。
//
// 检测顺序：环境变量（ZRE_CHROME > ZRE_XLB_CHROME）> 标准安装位 > PATH
// 常见命令名 > rod 自带下载缓存 > playwright 缓存。每个候选逐一 --version
// 实跑探活——文件存在不代表能用（Ubuntu 的 chromium-browser 可能是指向
// snap 的坏 stub，启动时才报错），探活阶段直接淘汰。
//
// 结果进程级缓存：探测要 spawn 进程，且浏览器安装状态在进程生命周期内
// 不会变化；安装浏览器后需重启进程生效。
//
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
	"strings"
	"sync"
	"time"
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
		// rod 按需下载的浏览器（首次启动/工具运行时自动落在这里），
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

// FindChrome 返回本机可用的浏览器二进制；找不到返回 ""（探测失败原因
// 留档日志）。结果进程级缓存。
func FindChrome() string {
	once.Do(func() {
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
			foundPath = p
			return
		}
		log.Printf("[browser] 未检测到可用浏览器，候选探测记录: %s", strings.Join(misses, "; "))
	})
	return foundPath
}

// MissingError 找不到浏览器时的用户提示：给出可操作的安装/指定途径。
// purpose 描述调用方业务（如「报告 PDF 渲染」「扫码登录」）。
func MissingError(purpose string) error {
	return fmt.Errorf("%s需要本机 Chrome/Chromium，但自动检测未找到可用浏览器。"+
		"处理方式任选其一：① 安装 Chrome/Chromium（apt install chromium-browser 或官网安装包）；"+
		"② 已装有但路径特殊时设置环境变量 ZRE_CHROME 指向可执行文件后重启；"+
		"③ 不依赖浏览器的替代路径（视功能而定：报告回退 HTML、扫码登录改粘贴 Cookie、企业穿透改用 HTTP 直连数据源）", purpose)
}
