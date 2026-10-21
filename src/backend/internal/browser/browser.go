// Package browser 浏览器探测与无头操作（截图/PDF 共用的底层能力）。
// 浏览器来源三重兜底：系统安装（apt/包管理）、Playwright 缓存目录、
// 均不可用时调用方降级（报告回退 HTML-only、截图跳过并提示）。
// 部署时建议：Dockerfile/安装脚本执行 `apt-get install -y chromium` 即可被探测到。
package browser

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// FindChrome 按候选顺序寻找可用浏览器二进制；逐一 --version 试跑，
// 跳过存在但损坏的安装（如未真正安装的 chromium snap 包装器）。
func FindChrome() string {
	candidates := []string{
		"/usr/bin/google-chrome", "/usr/bin/google-chrome-stable",
		"/usr/bin/chromium", "/usr/bin/chromium-browser",
		"/snap/bin/chromium",
		filepath.Join(os.Getenv("HOME"), ".local/bin/google-chrome"),
		filepath.Join(os.Getenv("HOME"), ".cache/ms-playwright/chromium-1223/chrome-linux64/chrome"),
	}
	for _, p := range candidates {
		if p == "" {
			continue
		}
		if _, err := exec.LookPath(p); err != nil {
			if _, serr := os.Stat(p); serr != nil {
				continue
			}
		}
		// 存在不等于可用：损坏的包装器在此被淘汰
		if ProbeChrome(p) {
			return p
		}
	}
	return ""
}

// ProbeChrome 试跑 --version 验证浏览器二进制可用
func ProbeChrome(bin string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "--version")
	return cmd.Run() == nil
}
