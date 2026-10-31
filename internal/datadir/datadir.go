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
	"log"
	"os"
	"path/filepath"
	"sync"
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
		// 两边都有内容（异常态）：保守起见沿用旧目录，避免覆盖 bin 内数据
		log.Printf("[datadir] %s 与 %s 同时存在且均有内容，沿用旧目录 %s", legacy, dst, legacy)
		return legacy
	}
	return dst
}

func trim(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[len(s)-1] == ' ') {
		s = s[1 : len(s)-1]
	}
	return s
}
