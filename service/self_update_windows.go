//go:build windows

package service

import (
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"os/exec"
)

// installAndRestart Windows 不允许覆盖正在运行的 exe，换一条路：
// 新二进制先落成 worker.exe.new，启动它，然后当前进程退出；
// 新进程在启动阶段会把正式文件名让给自己（见 main.go 的 .new 接力）。
func installAndRestart(exe, tmpBin, wantVersion string) error {
	newExe := exe + ".new"
	_ = os.Remove(newExe)
	if err := os.Rename(tmpBin, newExe); err != nil {
		return fmt.Errorf("准备新二进制失败: %w", err)
	}

	log.Printf("[SelfUpdate] %s -> %s，启动新进程", SelfVersion(), wantVersion)

	// Windows 没有 /dev/stdin，配置走环境变量接力
	if raw := configSourceBytes(); len(raw) > 0 {
		if err := os.Setenv("ZRE_CONFIG_BASE64", base64.StdEncoding.EncodeToString(raw)); err != nil {
			return err
		}
	}

	cmd := exec.Command(newExe)
	cmd.Env = os.Environ()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动新进程失败: %w", err)
	}
	log.Printf("[SelfUpdate] 新进程已启动 pid=%d，当前进程退出", cmd.Process.Pid)
	os.Exit(0)
	return nil
}

// configUsesStdin Windows 没有 /dev/stdin，恒为 false，配置靠环境变量。
func configUsesStdin() bool { return false }
