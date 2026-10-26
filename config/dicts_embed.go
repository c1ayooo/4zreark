package config

import (
	"embed"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// 字典随二进制分发：worker 只需要一个可执行文件，不再依赖 config/dicts 目录。
// 磁盘上的 config/dicts 仍然优先，便于现场覆盖词表。
//
//go:embed all:dicts
var embeddedDictFS embed.FS

// ReadDictFile 先读磁盘，再回落到内置字典。
func ReadDictFile(filePath string) ([]byte, error) {
	if data, err := os.ReadFile(filePath); err == nil {
		return data, nil
	}
	slash := filepath.ToSlash(filePath)
	if i := strings.Index(slash, "dicts/"); i >= 0 {
		if data, err := embeddedDictFS.ReadFile(slash[i:]); err == nil {
			return data, nil
		}
	}
	return nil, os.ErrNotExist
}

// EmbeddedDicts 返回内置字典文件系统（根为 dicts/）。
func EmbeddedDicts() fs.FS { return embeddedDictFS }

// WriteEmbeddedDicts 把内置字典展开到 dest（dest 是 dicts 目录本身）。
func WriteEmbeddedDicts(dest string) error {
	return fs.WalkDir(embeddedDictFS, "dicts", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel := strings.TrimPrefix(p, "dicts")
		rel = strings.TrimPrefix(rel, "/")
		target := filepath.Join(dest, filepath.FromSlash(rel))
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := embeddedDictFS.ReadFile(p)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
}

// HasLocalDicts 判断磁盘上是否存在可用的 config/dicts。
func HasLocalDicts() bool {
	_, err := os.Stat(GetDictBasePath())
	return err == nil
}
