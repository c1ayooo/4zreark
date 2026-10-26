//go:build !windows

package service

import (
	"fmt"
	"log"
	"os"
	"syscall"
)

// configUsesStdin 判断当前配置是不是从标准输入读的（节点零配置启动的情形）。
func configUsesStdin() bool {
	p := os.Getenv("CONFIG_PATH")
	return p == "/dev/stdin" || p == "-"
}

// installAndRestart 原子替换二进制后 exec 重启；任何一步失败都回滚到旧镜像。
func installAndRestart(exe, tmpBin, wantVersion string) error {
	backup := exe + ".old"
	_ = os.Remove(backup)
	if err := os.Rename(exe, backup); err != nil {
		return fmt.Errorf("备份旧二进制失败: %w", err)
	}
	if err := os.Rename(tmpBin, exe); err != nil {
		_ = os.Rename(backup, exe)
		return fmt.Errorf("替换二进制失败: %w", err)
	}

	log.Printf("[SelfUpdate] %s -> %s，准备 exec 重启", SelfVersion(), wantVersion)

	// 配置来自 stdin 时先把原文重新灌满 fd 0，新进程依然零配置启动
	if configUsesStdin() {
		raw := configSourceBytes()
		if len(raw) == 0 {
			return fmt.Errorf("配置原文缺失，拒绝重启")
		}
		pr, pw, err := os.Pipe()
		if err != nil {
			return err
		}
		if _, werr := pw.Write(raw); werr != nil {
			pr.Close()
			pw.Close()
			return werr
		}
		pw.Close()
		if derr := syscall.Dup3(int(pr.Fd()), 0, 0); derr != nil {
			pr.Close()
			return derr
		}
		pr.Close()
	}

	// pid / 会话 / 监听端口全部保留，旧镜像直接被替换
	return syscall.Exec(exe, os.Args, os.Environ())
}
