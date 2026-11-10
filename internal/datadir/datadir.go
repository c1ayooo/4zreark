// Package datadir 平台运行时可执行资产（bin）的统一目录约定：
// 扫描工具、nuclei 运行时、自带浏览器等全部收敛到 <工作目录>/data/bin/
// 之下（ZRE_BIN_DIR 覆盖根），并负责把历史散落的旧目录一次性迁移进来。
//
// 布局（详见 docs/目录管理-运行时资产-bin布局-*.md）：
//
//	data/bin/
//	├── tools/<os>/…        扫描工具（gogo/katana/spray/rem）
//	├── nuclei/…            nuclei 运行时（bin/templates/custom-templates/home）
//	└── browser/chromium-<rev>/chrome  自带浏览器
package datadir

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const binRootEnv = "ZRE_BIN_DIR"

var (
	once   sync.Once
	binDir string
)

// BinRoot 返回统一 bin 根目录（不保证已创建）。
func BinRoot() string {
	once.Do(func() {
		if p := trim(os.Getenv(binRootEnv)); p != "" {
			binDir = p
			return
		}
		binDir = filepath.Join("data", "bin")
	})
	return binDir
}

// Sub 返回 bin 根下的子目录路径。
func Sub(name string) string { return filepath.Join(BinRoot(), name) }

// Adopt 把历史散落的旧目录收编进 bin 根：旧目录存在且目标不存在时整体
// rename（同文件系统原子操作，数据无拷贝）；目标已存在（重复启动/手动
// 预置）时以目标为准并移除旧目录空壳；rename 失败（跨设备、旧目录是
// 挂载点等）时保留旧路径继续使用并留日志——调用方拿到的一定是可用目录。
// 返回收编后的实际路径。
func Adopt(legacy, name string) string {
	return adopt(legacy, filepath.Join(BinRoot(), name))
}

// adoptForTest 供测试注入独立目标目录（绕过 BinRoot 进程缓存）。
var adoptForTest = adopt

func adopt(legacy, dst string) string {
	if trim(legacy) == "" {
		return dst
	}

	_, dstStatErr := os.Stat(dst)
	legacyEntries, legacyReadErr := os.ReadDir(legacy)
	switch {
	case legacyReadErr != nil:
		// 旧目录不存在：新部署，直接用 bin 位置
	case dstStatErr == nil && len(legacyEntries) == 0:
		// 旧目录已是空壳（此前迁移过）：清掉壳，用 bin 位置
		_ = os.Remove(legacy)
	case dstStatErr != nil:
		// 正常迁移路径：旧有内容 + 目标不存在
		if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
			log.Printf("[datadir] 创建 %s 失败（%v），沿用旧目录 %s", filepath.Dir(dst), err, legacy)
			return legacy
		}
		if err := os.Rename(legacy, dst); err != nil {
			// 挂载点/跨设备等不可迁移场景：沿用旧路径，不丢数据
			log.Printf("[datadir] %s 迁移到 %s 失败（%v），沿用旧目录", legacy, dst, err)
			return legacy
		}
		log.Printf("[datadir] 已将 %s 收编到 %s", legacy, dst)
	default:
		// 两边都有内容（异常态，如旧版本进程把工具重装回旧路径）：以 bin 为准
		// 收敛——旧目录中 bin 缺失的条目搬过去，同名条目保留 bin 版本（bin 是
		// 统一后的权威位置），搬完移除旧目录。此前这里「保守沿用旧目录」，结果
		// 一旦旧目录被重建，平台就永远困在旧路径：bin 里的新装工具（如 rem）
		// 检测不到，还在持续使用旧目录里的旧版本二进制。
		if err := mergeInto(legacy, dst); err != nil {
			log.Printf("[datadir] %s 并入 %s 失败（%v），沿用旧目录", legacy, dst, err)
			return legacy
		}
		if err := os.RemoveAll(legacy); err != nil {
			log.Printf("[datadir] 移除旧目录 %s 失败（%v），沿用旧目录", legacy, err)
			return legacy
		}
		log.Printf("[datadir] %s 已并入 %s（同名条目以 %s 为准）", legacy, dst, dst)
	}
	return dst
}

// mergeInto 把 src 目录树并入 dst：同名条目保留 dst 现状，src 独有的搬过去。
// bin 内已存在的任何文件都不会被覆盖。
func mergeInto(src, dst string) error {
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dst, 0o750); err != nil {
		return err
	}
	for _, e := range entries {
		s := filepath.Join(src, e.Name())
		d := filepath.Join(dst, e.Name())
		if e.IsDir() {
			if err := mergeInto(s, d); err != nil {
				return err
			}
			continue
		}
		if _, err := os.Lstat(d); err == nil {
			continue // dst 已有同名条目，保留 bin 版本
		}
		if err := os.Rename(s, d); err == nil {
			continue
		}
		// rename 失败（跨设备等）退化为拷贝
		if err := copyFile(s, d, e); err != nil {
			return fmt.Errorf("搬移 %s: %w", s, err)
		}
	}
	return nil
}

func copyFile(src, dst string, e os.DirEntry) error {
	info, err := e.Info()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("跳过非普通文件 %s", src)
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, info.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(dst)
		return err
	}
	return out.Close()
}

// tmpOnce / tmpDirVal 缓存临时目录（含一次性残留清理）。
var (
	tmpOnce   sync.Once
	tmpDirVal string
	tmpMaxAge = 48 * time.Hour
)

// TmpDir 返回平台统一临时目录（data/tmp，ZRE_TMPDIR 覆盖）：所有
// MkdirTemp/临时文件（nuclei 物化、JS 审计、备份、katana/spray 输出、
// tunnel 记录、OOB cookie）都约束在这里，不再散落系统 /tmp 或工作目录根。
// 首次调用时清理 48 小时前的残留。
func TmpDir() string {
	tmpOnce.Do(func() {
		tmpDirVal = filepath.Join(BinRoot(), "..", "tmp")
		if p := trim(os.Getenv("ZRE_TMPDIR")); p != "" {
			tmpDirVal = p
		}
		if err := os.MkdirAll(tmpDirVal, 0o750); err != nil {
			log.Printf("[datadir] 创建临时目录失败（%v），回退系统 /tmp", err)
			tmpDirVal = os.TempDir()
			return
		}
		cutoff := time.Now().Add(-tmpMaxAge)
		entries, err := os.ReadDir(tmpDirVal)
		if err != nil {
			return
		}
		for _, e := range entries {
			fi, err := e.Info()
			if err != nil || fi.ModTime().After(cutoff) {
				continue
			}
			_ = os.RemoveAll(filepath.Join(tmpDirVal, e.Name()))
		}
	})
	return tmpDirVal
}

func trim(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[len(s)-1] == ' ') {
		s = s[1 : len(s)-1]
	}
	return s
}
