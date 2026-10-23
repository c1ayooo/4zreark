// Package backup 实现 4zreark 平台的全量备份与恢复（ARL-Next 一键迁移理念的 PG 版）。
//
// 备份产物是单个 <名>.zrebackup 文件（本质是 tar.gz），内含三个成员：
//   - manifest.json  备份元信息（格式版本、pg_dump 版本、源库信息、文件清单+sha256）
//   - db.dump        pg_dump --format=custom 的业务库转储（只针对配置的 schema）
//   - files.tar.gz   文件卷（config/dicts、pocs、configs 等目录，保留相对路径）
//
// 与 PostgreSQL 的交互全部 shell out 到 pg_dump/pg_restore/psql（CommandContext 带超时，
// 密码走 PGPASSWORD 环境变量），不直连数据库，因此本包不依赖任何驱动。
package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
)

// 备份格式版本与产物扩展名。manifest.version 与 FormatVersion 不一致时拒绝恢复。
const (
	FormatVersion = 1
	Ext           = ".zrebackup"
	toolName      = "4zreark-backup"

	entryManifest = "manifest.json"
	entryDB       = "db.dump"
	entryFiles    = "files.tar.gz"

	// DefaultTimeout 是 create/restore 子进程级的默认超时。
	DefaultTimeout = 30 * time.Minute

	// BusyConnThreshold 是恢复前的活跃连接安全阈值：
	// pg_stat_activity 里目标库的其他客户端连接数超过该值时默认拒绝恢复。
	BusyConnThreshold = 2
)

// DefaultFileDirs 是默认随库一起备份的文件卷目录（相对平台工作目录）。
var DefaultFileDirs = []string{"config/dicts", "pocs", "configs"}

// ErrBusy 表示恢复因目标库存在活跃连接被安全拒绝（CLI 据此以退出码 2 退出）。
var ErrBusy = errors.New("目标库存在活跃连接，拒绝恢复")

// Target 是备份/恢复的目标 PostgreSQL 连接信息，由 cmd/backup 从 config.PostgresConfig 映射而来。
type Target struct {
	Host     string
	Port     int
	User     string
	Password string // 只用于 PGPASSWORD 环境变量，绝不写入 manifest
	DBName   string
	Schema   string
	SSLMode  string
}

// SourceInfo 写入 manifest 的源库信息，刻意不含密码。
type SourceInfo struct {
	Host   string `json:"host"`
	Port   int    `json:"port"`
	User   string `json:"user"`
	DBName string `json:"dbname"`
	Schema string `json:"schema"`
}

// GitInfo 记录构建侧信息（go build 的 VCS stamp），go run 或无 VCS 时为空。
type GitInfo struct {
	Revision string `json:"revision,omitempty"`
	Modified bool   `json:"modified,omitempty"`
}

// EntryInfo 是归档内单个成员的校验信息。
type EntryInfo struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// ExtensionInfo 是装在业务 schema 里的 PostgreSQL 扩展（如 pg_trgm）。
// pg_dump --schema 不会导出 CREATE EXTENSION 语句，恢复到全新库前必须按这份清单预创建，
// 否则依赖扩展运算符类的索引（gin_trgm_ops 等）会建不出来。
type ExtensionInfo struct {
	Name   string `json:"name"`
	Schema string `json:"schema"`
}

// Manifest 是 .zrebackup 的元信息清单。
type Manifest struct {
	Version       int             `json:"version"`
	CreatedAt     time.Time       `json:"created_at"`
	Tool          string          `json:"tool"`
	PgDumpVersion string          `json:"pg_dump_version"`
	Source        SourceInfo      `json:"source"`
	Git           GitInfo         `json:"git"`
	Entries       []EntryInfo     `json:"entries"`              // db.dump / files.tar.gz 的 sha256
	Files         []string        `json:"files"`                // files.tar.gz 内的相对路径清单
	Extensions    []ExtensionInfo `json:"extensions,omitempty"` // 业务 schema 内的扩展，恢复前预创建
}

// CreateOptions 控制 Create 的行为。
type CreateOptions struct {
	Target   Target        // 数据库连接信息（来自 config）
	OutDir   string        // 输出目录，默认 ./backups
	Name     string        // 备份名，默认 zre-<yyyymmdd>-<hhmmss>
	FileDirs []string      // 文件卷目录，默认 DefaultFileDirs；缺失的目录跳过并告警
	PGBinDir string        // 额外的 pg_dump 查找目录（CLI 的 --pg-bin，优先于 PATH）
	Timeout  time.Duration // 单命令超时，默认 DefaultTimeout
	Stderr   io.Writer     // 子进程 stderr 透传目标（nil = 丢弃）
	Warn     io.Writer     // 告警输出（nil = 丢弃）
	Now      func() time.Time
}

// CreateResult 是 Create 的产物描述。
type CreateResult struct {
	Path     string // .zrebackup 完整路径
	Name     string // 备份名（不含扩展名）
	Size     int64  // 文件字节数
	Manifest Manifest
}

// RestoreOptions 控制 Restore 的行为。
type RestoreOptions struct {
	File     string        // .zrebackup 路径
	Target   Target        // 恢复目标数据库
	Drop     bool          // 先 DROP SCHEMA ... CASCADE 再整库恢复
	Force    bool          // 跳过活跃连接安全检查
	FileDirs []string      // 文件卷要落地的目录集合（用于识别需要先备份的旧目录），默认 DefaultFileDirs
	Root     string        // 文件卷解包根目录，默认 "."（平台工作目录）
	PGBinDir string        // 额外的 pg_restore/psql 查找目录
	Timeout  time.Duration // 单命令超时，默认 DefaultTimeout
	Stderr   io.Writer     // 子进程 stderr 透传目标
	Warn     io.Writer     // 告警输出
	Now      func() time.Time
}

// RestoreResult 是 Restore 的结果描述。
type RestoreResult struct {
	Manifest      Manifest
	FilesRestored []string // files.tar.gz 解出的相对路径
	DirsBackedUp  []string // 恢复前被改名为 .bak-<ts> 的旧目录
	BusyConns     int      // 恢复前观测到的活跃连接数（-1 表示未检查）
}

// BackupSummary 是 List 对单个备份文件的摘要；解析失败时 Err 非空。
type BackupSummary struct {
	Path     string
	Name     string
	Size     int64
	Manifest *Manifest
	Err      error
}

// DefaultBackupName 生成 zre-20261023-153000 形式的默认备份名。
func DefaultBackupName(t time.Time) string {
	return "zre-" + t.Format("20060102-150405")
}

// ---------------------------------------------------------------------------
// manifest 读写
// ---------------------------------------------------------------------------

// WriteManifest 以缩进 JSON 写出 manifest（末尾带换行，便于人工检视）。
func WriteManifest(w io.Writer, m *Manifest) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化 manifest 失败: %w", err)
	}
	if _, err := w.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("写入 manifest 失败: %w", err)
	}
	return nil
}

// ReadManifest 解析 manifest 并校验格式版本。
func ReadManifest(r io.Reader) (*Manifest, error) {
	m := &Manifest{}
	if err := json.NewDecoder(r).Decode(m); err != nil {
		return nil, fmt.Errorf("解析 manifest 失败: %w", err)
	}
	if m.Version != FormatVersion {
		return nil, fmt.Errorf("不支持的备份格式版本 %d（当前支持 %d）", m.Version, FormatVersion)
	}
	return m, nil
}

// ---------------------------------------------------------------------------
// 工具查找
// ---------------------------------------------------------------------------

// FindTool 查找外部工具：先查 extraDir（--pg-bin 覆盖），再退回 PATH。
func FindTool(name, extraDir string) (string, error) {
	if extraDir != "" {
		p := filepath.Join(extraDir, name)
		if info, err := os.Stat(p); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}
	return "", fmt.Errorf("未找到 %s", name)
}

// toolMissingError 生成中文可操作错误：装 libpq / -pg-bin / 容器内执行的替代命令。
func toolMissingError(tool, extraDir string, t *Target) error {
	var b strings.Builder
	b.WriteString("未找到 " + tool)
	if extraDir != "" {
		b.WriteString("（-pg-bin 目录 " + extraDir + " 与 PATH 均未命中）")
	} else {
		b.WriteString("（PATH 中不存在）")
	}
	b.WriteString("。任选一种解决方式：\n")
	b.WriteString("  1. 安装 PostgreSQL 客户端工具（libpq）：\n")
	b.WriteString("       Debian/Ubuntu: sudo apt install postgresql-client\n")
	b.WriteString("       RHEL/CentOS:   sudo dnf install postgresql\n")
	b.WriteString("       macOS:         brew install libpq && brew link --force libpq\n")
	b.WriteString("  2. 用 -pg-bin 指定包含 " + tool + " 的目录\n")
	if t != nil {
		schema, user, db := schemaOf(t), orDash(t.User), orDash(t.DBName)
		switch tool {
		case "pg_dump":
			fmt.Fprintf(&b, "  3. 容器部署时改在数据库容器内执行（宿主机无需 pg_dump）：\n")
			fmt.Fprintf(&b, "       docker exec <容器名> pg_dump --format=custom --no-owner --no-privileges --schema=%s --username=%s --dbname=%s -f /tmp/db.dump\n", schema, user, db)
			b.WriteString("       docker cp <容器名>:/tmp/db.dump ./db.dump\n")
		case "pg_restore":
			b.WriteString("  3. 容器部署时改在数据库容器内执行（宿主机无需 pg_restore）：\n")
			b.WriteString("       docker cp ./db.dump <容器名>:/tmp/db.dump\n")
			fmt.Fprintf(&b, "       docker exec <容器名> pg_restore --no-owner --no-privileges --clean --if-exists --username=%s --dbname=%s /tmp/db.dump\n", user, db)
		case "psql":
			fmt.Fprintf(&b, "  3. 容器部署时改在数据库容器内执行：\n")
			fmt.Fprintf(&b, "       docker exec <容器名> psql --username=%s --dbname=%s -c 'select 1'\n", user, db)
		}
	}
	return errors.New(b.String())
}

// ---------------------------------------------------------------------------
// 归档：tar.gz 打包 / 解包
// ---------------------------------------------------------------------------

// ArchiveDirs 把若干目录（相对当前工作目录）打包为 tar.gz，保留相对路径。
// 返回收集到的相对路径清单；不存在的目录跳过并写一条告警。
func ArchiveDirs(dirs []string, w io.Writer, warn io.Writer) ([]string, error) {
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	collected := make([]string, 0, 256)

	for _, dir := range dirs {
		dir = filepath.Clean(dir)
		info, err := os.Stat(dir)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Fprintf(warn, "[warn] 文件卷目录不存在，跳过: %s\n", dir)
				continue
			}
			return nil, fmt.Errorf("读取 %s 失败: %w", dir, err)
		}
		if err := addTarEntry(tw, filepath.ToSlash(dir), dir, info, &collected); err != nil {
			return nil, err
		}
		if err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if path == dir {
				return nil
			}
			info, ierr := d.Info()
			if ierr != nil {
				return ierr
			}
			return addTarEntry(tw, filepath.ToSlash(path), path, info, &collected)
		}); err != nil {
			return nil, fmt.Errorf("遍历 %s 失败: %w", dir, err)
		}
	}

	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("关闭 tar 写入器失败: %w", err)
	}
	if err := gz.Close(); err != nil {
		return nil, fmt.Errorf("关闭 gzip 写入器失败: %w", err)
	}
	return collected, nil
}

// addTarEntry 写入单个 tar 头（目录或普通文件；符号链接等特殊文件跳过并告警）。
// name 是归档内的相对路径，path 是磁盘上的实际路径。
func addTarEntry(tw *tar.Writer, name, path string, info os.FileInfo, collected *[]string) error {
	if !info.Mode().IsRegular() && !info.Mode().IsDir() {
		fmt.Fprintf(os.Stderr, "[warn] 跳过非常规文件: %s\n", name)
		return nil
	}
	hdr := &tar.Header{
		Name:    name,
		ModTime: info.ModTime(),
	}
	if info.Mode().IsDir() {
		hdr.Typeflag = tar.TypeDir
		hdr.Mode = int64(info.Mode().Perm())
	} else {
		hdr.Typeflag = tar.TypeReg
		hdr.Mode = int64(info.Mode().Perm())
		hdr.Size = info.Size()
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("写入 tar 头 %s 失败: %w", name, err)
	}
	if info.Mode().IsRegular() {
		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("打开 %s 失败: %w", name, err)
		}
		_, err = io.Copy(tw, f)
		f.Close()
		if err != nil {
			return fmt.Errorf("写入 %s 内容失败: %w", name, err)
		}
		*collected = append(*collected, name)
	}
	return nil
}

// ExtractTarGz 把 tar.gz 解包到 dest，保留相对路径；返回解出的文件相对路径。
// 拒绝绝对路径与 .. 穿越（zip-slip 防护）。
func ExtractTarGz(r io.Reader, dest string) ([]string, error) {
	dest = filepath.Clean(dest)
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("打开 gzip 流失败: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	extracted := make([]string, 0, 256)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("读取 tar 流失败: %w", err)
		}
		name := hdr.Name
		if name == "" || filepath.IsAbs(name) || strings.HasPrefix(filepath.ToSlash(filepath.Clean(name)), "../") {
			return nil, fmt.Errorf("归档条目路径非法，已拒绝: %q", name)
		}
		target := filepath.Join(dest, filepath.FromSlash(name))
		// 用 Rel 做越界判定：dest="." 等相对根也能正确放行普通相对路径
		if rel, rerr := filepath.Rel(dest, target); rerr != nil || rel == ".." ||
			strings.HasPrefix(filepath.ToSlash(rel), "../") {
			return nil, fmt.Errorf("归档条目越界，已拒绝: %q", name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(hdr.Mode).Perm()); err != nil {
				return nil, fmt.Errorf("创建目录 %s 失败: %w", target, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return nil, fmt.Errorf("创建父目录失败: %w", err)
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(hdr.Mode).Perm())
			if err != nil {
				return nil, fmt.Errorf("创建文件 %s 失败: %w", target, err)
			}
			_, err = io.Copy(f, tr)
			f.Close()
			if err != nil {
				return nil, fmt.Errorf("写入 %s 失败: %w", target, err)
			}
			extracted = append(extracted, filepath.ToSlash(name))
		default:
			fmt.Fprintf(os.Stderr, "[warn] 跳过非常规归档条目: %s\n", name)
		}
	}
	return extracted, nil
}

// writeArchiveFile 把临时目录里的 manifest.json、db.dump、files.tar.gz 按固定顺序
// （manifest 最先，便于 list 只读头部）打包为最终的 .zrebackup。
func writeArchiveFile(outPath, tmpDir string) error {
	for _, name := range []string{entryManifest, entryDB, entryFiles} {
		if _, err := os.Stat(filepath.Join(tmpDir, name)); err != nil {
			return fmt.Errorf("打包缺少 %s: %w", name, err)
		}
	}
	f, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("创建 %s 失败: %w", outPath, err)
	}
	defer f.Close()

	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for _, name := range []string{entryManifest, entryDB, entryFiles} {
		diskPath := filepath.Join(tmpDir, name)
		if err := addTarEntry(tw, name, diskPath, mustStat(diskPath), &[]string{}); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return fmt.Errorf("收尾 tar 失败: %w", err)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("收尾 gzip 失败: %w", err)
	}
	return f.Close()
}

// mustStat 是 writeArchiveFile 内部的辅助：调用前已确认文件存在。
func mustStat(path string) os.FileInfo {
	info, err := os.Stat(path)
	if err != nil {
		panic(err)
	}
	return info
}

// ---------------------------------------------------------------------------
// 归档校验
// ---------------------------------------------------------------------------

// ReadArchiveManifest 只读 .zrebackup 头部的 manifest.json（成员按 manifest 优先写入，可提前收工）。
func ReadArchiveManifest(path string) (*Manifest, error) {
	m, _, err := scanArchive(path, true)
	return m, err
}

// ValidateArchive 完整校验 .zrebackup：manifest 存在、版本受支持、
// db.dump 与 files.tar.gz 的 size/sha256 与 manifest.entries 一致。
func ValidateArchive(path string) (*Manifest, error) {
	m, stats, err := scanArchive(path, false)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(m.Entries))
	for _, e := range m.Entries {
		got, ok := stats[e.Name]
		if !ok {
			return nil, fmt.Errorf("manifest 声明了 %s，但归档里没有该成员", e.Name)
		}
		if got.sha256 != e.SHA256 || got.size != e.Size {
			return nil, fmt.Errorf("成员 %s 校验失败（sha256/大小与 manifest 不一致，文件可能已损坏或被篡改）", e.Name)
		}
		seen[e.Name] = true
	}
	for name := range stats {
		if !seen[name] {
			return nil, fmt.Errorf("归档成员 %s 不在 manifest 清单中", name)
		}
	}
	return m, nil
}

type entryStat struct {
	size   int64
	sha256 string
}

// scanArchive 流式扫描 .zrebackup；stopAfterManifest 为 true 时读到 manifest 即返回。
func scanArchive(path string, stopAfterManifest bool) (*Manifest, map[string]entryStat, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, nil, fmt.Errorf("%s 不是有效的 gzip 归档: %w", filepath.Base(path), err)
	}
	defer gz.Close()

	var m *Manifest
	stats := map[string]entryStat{}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("读取归档失败: %w", err)
		}
		switch filepath.Clean(hdr.Name) {
		case entryManifest:
			m, err = ReadManifest(tr)
			if err != nil {
				return nil, nil, fmt.Errorf("读取 %s: %w", entryManifest, err)
			}
			if stopAfterManifest {
				return m, stats, nil
			}
		case entryDB, entryFiles:
			h := sha256.New()
			n, err := io.Copy(h, tr)
			if err != nil {
				return nil, nil, fmt.Errorf("读取成员 %s 失败: %w", hdr.Name, err)
			}
			stats[filepath.Clean(hdr.Name)] = entryStat{size: n, sha256: hex.EncodeToString(h.Sum(nil))}
		default:
			// 未知成员：为前向兼容忽略
		}
	}
	if m == nil {
		return nil, nil, fmt.Errorf("归档里缺少 %s，不是有效的 %s 备份", entryManifest, Ext)
	}
	return m, stats, nil
}

// ---------------------------------------------------------------------------
// 备份
// ---------------------------------------------------------------------------

// Create 执行一次全量备份：pg_dump + 文件卷打包 + manifest + 单文件归档。
func Create(ctx context.Context, opts CreateOptions) (*CreateResult, error) {
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}
	target := opts.Target
	if target.DBName == "" {
		return nil, errors.New("目标数据库未配置（postgres.dbname 为空）")
	}
	warn := nullWriter(opts.Warn)

	dumpBin, err := FindTool("pg_dump", opts.PGBinDir)
	if err != nil {
		return nil, toolMissingError("pg_dump", opts.PGBinDir, &target)
	}

	now := time.Now()
	if opts.Now != nil {
		now = opts.Now()
	}

	tmpDir, err := os.MkdirTemp("", "zre-backup-")
	if err != nil {
		return nil, fmt.Errorf("创建临时目录失败: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// 1. 数据库转储（custom 格式，只针对业务 schema）
	dumpPath := filepath.Join(tmpDir, entryDB)
	args := []string{
		"--format=custom",
		"--no-owner",
		"--no-privileges",
		"--schema=" + schemaOf(&target),
		"--file=" + dumpPath,
	}
	args = append(args, connArgs(&target)...)
	fmt.Fprintf(warn, "[1/4] pg_dump 导出 %s@%s:%d/%s (schema=%s) ...\n",
		orDash(target.User), target.Host, target.Port, target.DBName, schemaOf(&target))
	if err := runPGTool(ctx, dumpBin, args, &target, opts.Stderr); err != nil {
		return nil, fmt.Errorf("pg_dump 失败: %w", err)
	}

	// 2. 文件卷 tar.gz
	filesPath := filepath.Join(tmpDir, entryFiles)
	fmt.Fprintln(warn, "[2/4] 打包文件卷:", strings.Join(fileDirsOf(opts.FileDirs), ", "))
	filesTar, ferr := os.Create(filesPath)
	if ferr != nil {
		return nil, fmt.Errorf("创建 %s 失败: %w", filesPath, ferr)
	}
	fileList, aerr := ArchiveDirs(fileDirsOf(opts.FileDirs), filesTar, warn)
	if cerr := filesTar.Close(); cerr != nil && aerr == nil {
		aerr = cerr
	}
	if aerr != nil {
		return nil, fmt.Errorf("打包文件卷失败: %w", aerr)
	}

	// 3. manifest（含成员 sha256；源信息不含密码）
	fmt.Fprintln(warn, "[3/4] 生成 manifest.json ...")
	entries := make([]EntryInfo, 0, 2)
	for _, name := range []string{entryDB, entryFiles} {
		p := filepath.Join(tmpDir, name)
		sum, size, ierr := hashFile(p)
		if ierr != nil {
			return nil, ierr
		}
		entries = append(entries, EntryInfo{Name: name, Size: size, SHA256: sum})
	}
	// 记录装在业务 schema 里的扩展：pg_dump --schema 不导出它们，恢复端要预创建。
	// psql 不可用时降级为告警（备份仍有效，只是恢复全新库时可能要手动 CREATE EXTENSION）。
	var extensions []ExtensionInfo
	if psqlBin, perr := FindTool("psql", opts.PGBinDir); perr == nil {
		exts, qerr := ListSchemaExtensions(ctx, psqlBin, &target)
		if qerr != nil {
			fmt.Fprintf(warn, "[warn] 读取 schema 内扩展清单失败（继续备份）: %v\n", qerr)
		} else {
			extensions = exts
			if len(extensions) > 0 {
				names := make([]string, 0, len(extensions))
				for _, e := range extensions {
					names = append(names, e.Name+"@"+e.Schema)
				}
				fmt.Fprintf(warn, "schema 内扩展: %s\n", strings.Join(names, ", "))
			}
		}
	} else {
		fmt.Fprintln(warn, "[warn] 未找到 psql，无法记录 schema 内扩展清单（建议安装 postgresql-client）")
	}
	manifest := Manifest{
		Version:       FormatVersion,
		CreatedAt:     now,
		Tool:          toolName,
		PgDumpVersion: probeVersion(ctx, dumpBin),
		Source:        sourceOf(&target),
		Git:           gitInfo(),
		Entries:       entries,
		Files:         fileList,
		Extensions:    extensions,
	}
	mf, err := os.Create(filepath.Join(tmpDir, entryManifest))
	if err != nil {
		return nil, fmt.Errorf("创建 manifest 失败: %w", err)
	}
	err = WriteManifest(mf, &manifest)
	mf.Close()
	if err != nil {
		return nil, err
	}

	// 4. 单文件归档
	if opts.OutDir == "" {
		opts.OutDir = "backups"
	}
	if err := os.MkdirAll(opts.OutDir, 0o755); err != nil {
		return nil, fmt.Errorf("创建输出目录 %s 失败: %w", opts.OutDir, err)
	}
	name := opts.Name
	if name == "" {
		name = DefaultBackupName(now)
	}
	name = strings.TrimSuffix(name, Ext)
	outPath := filepath.Join(opts.OutDir, name+Ext)
	fmt.Fprintln(warn, "[4/4] 打包", outPath)
	if err := writeArchiveFile(outPath, tmpDir); err != nil {
		return nil, err
	}
	info, err := os.Stat(outPath)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(warn, "备份完成: %s (%s)\n", outPath, humanBytes(info.Size()))

	return &CreateResult{Path: outPath, Name: name, Size: info.Size(), Manifest: manifest}, nil
}

// ---------------------------------------------------------------------------
// 恢复
// ---------------------------------------------------------------------------

// Restore 执行恢复：校验归档 → 活跃连接安全检查 →（可选 drop schema）→ pg_restore → 文件卷落地。
func Restore(ctx context.Context, opts RestoreOptions) (*RestoreResult, error) {
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}
	if opts.File == "" {
		return nil, errors.New("缺少备份文件路径")
	}
	target := opts.Target
	if target.DBName == "" {
		return nil, errors.New("目标数据库未配置（postgres.dbname 为空）")
	}
	warn := nullWriter(opts.Warn)

	// 1. 校验 manifest 与 sha256
	fmt.Fprintln(warn, "[1/5] 校验备份与 sha256 ...")
	m, err := ValidateArchive(opts.File)
	if err != nil {
		return nil, fmt.Errorf("备份校验失败: %w", err)
	}
	if m.Source.Schema != "" && m.Source.Schema != schemaOf(&target) {
		fmt.Fprintf(warn, "[warn] 备份源 schema=%s 与目标 schema=%s 不一致\n", m.Source.Schema, schemaOf(&target))
	}

	// 2. 工具
	restoreBin, err := FindTool("pg_restore", opts.PGBinDir)
	if err != nil {
		return nil, toolMissingError("pg_restore", opts.PGBinDir, &target)
	}
	psqlBin, psqlErr := FindTool("psql", opts.PGBinDir)

	// 3. 安全边界：目标库有活跃应用连接时默认拒绝
	busy := -1
	if psqlErr == nil {
		if n, cerr := CountActiveConns(ctx, psqlBin, &target, warn); cerr == nil {
			busy = n
			if n > BusyConnThreshold && !opts.Force {
				return nil, fmt.Errorf("%w：检测到 %d 个活跃连接（阈值 %d）。请先停掉平台与扫描节点，确认无误后加 --force 重试",
					ErrBusy, n, BusyConnThreshold)
			}
			if n > BusyConnThreshold && opts.Force {
				fmt.Fprintf(warn, "[warn] 目标库仍有 %d 个活跃连接，--force 已跳过安全检查\n", n)
			}
		} else {
			fmt.Fprintf(warn, "[warn] 活跃连接检查失败（继续执行）: %v\n", cerr)
		}
	} else {
		fmt.Fprintln(warn, "[warn] 未找到 psql，跳过活跃连接安全检查（建议安装 postgresql-client）")
	}

	// 4. 解包 .zrebackup 到临时目录
	fmt.Fprintln(warn, "[2/5] 解包备份 ...")
	tmpDir, err := os.MkdirTemp("", "zre-restore-")
	if err != nil {
		return nil, fmt.Errorf("创建临时目录失败: %w", err)
	}
	defer os.RemoveAll(tmpDir)
	if f, ferr := os.Open(opts.File); ferr != nil {
		return nil, ferr
	} else {
		_, ferr = ExtractTarGz(f, tmpDir)
		f.Close()
		if ferr != nil {
			return nil, fmt.Errorf("解包备份失败: %w", ferr)
		}
	}
	dumpPath := filepath.Join(tmpDir, entryDB)
	filesPath := filepath.Join(tmpDir, entryFiles)
	if _, err := os.Stat(dumpPath); err != nil {
		return nil, fmt.Errorf("备份里缺少 %s", entryDB)
	}

	// 5. 数据库恢复
	schema := schemaOf(&target)
	if opts.Drop {
		fmt.Fprintf(warn, "[3/5] 删除并重建 schema %s ...\n", schema)
		if psqlErr != nil {
			return nil, toolMissingError("psql", opts.PGBinDir, &target)
		}
		dropSQL := fmt.Sprintf(`DROP SCHEMA IF EXISTS %s CASCADE`, quoteIdent(schema))
		dropArgs := append(connArgs(&target), "--command="+dropSQL)
		if err := runPGTool(ctx, psqlBin, dropArgs, &target, warn); err != nil {
			return nil, fmt.Errorf("DROP SCHEMA 失败: %w", err)
		}
	} else {
		fmt.Fprintf(warn, "[3/5] pg_restore --clean 逐对象替换 ...\n")
	}

	// 5a. 扩展预创建前置：确保业务 schema 存在（--drop 刚删掉；全新库里也没有）。
	// dump 里自带的 CREATE SCHEMA 随后报 "already exists"，属可忽略错误（见下方分类）。
	if psqlErr != nil {
		if len(m.Extensions) > 0 {
			return nil, fmt.Errorf("备份需要预创建扩展 %s，但未找到 psql。\n%v",
				extensionNames(m.Extensions), toolMissingError("psql", opts.PGBinDir, &target))
		}
		fmt.Fprintln(warn, "[warn] 未找到 psql，跳过 schema/扩展预创建（建议安装 postgresql-client）")
	}
	if psqlErr == nil {
		ensureSQL := fmt.Sprintf(`CREATE SCHEMA IF NOT EXISTS %s`, quoteIdent(schema))
		ensureArgs := append(connArgs(&target), "--command="+ensureSQL)
		if err := runPGTool(ctx, psqlBin, ensureArgs, &target, warn); err != nil {
			return nil, fmt.Errorf("CREATE SCHEMA %s 失败: %w", schema, err)
		}

		// 5b. 预创建业务 schema 内的扩展（pg_dump --schema 不导出 CREATE EXTENSION）。
		// 旧格式备份没有这份清单时给出手工操作提示。
		if len(m.Extensions) == 0 {
			fmt.Fprintln(warn, "[hint] manifest 未记录 schema 内扩展（旧格式备份）。若恢复后报 "+
				"operator class ... does not exist，请先执行: CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA "+
				schema+";")
		}
		for _, ext := range m.Extensions {
			sql := fmt.Sprintf(`CREATE EXTENSION IF NOT EXISTS %s WITH SCHEMA %s`, quoteIdent(ext.Name), quoteIdent(ext.Schema))
			fmt.Fprintf(warn, "预创建扩展: %s (schema=%s)\n", ext.Name, ext.Schema)
			extArgs := append(connArgs(&target), "--command="+sql)
			if err := runPGTool(ctx, psqlBin, extArgs, &target, warn); err != nil {
				return nil, fmt.Errorf("CREATE EXTENSION %s 失败: %w", ext.Name, err)
			}
		}
	}

	args := append(connArgs(&target), "--no-owner", "--no-privileges")
	if !opts.Drop {
		// --clean 会先 DROP 再 CREATE 每个对象；--if-exists 容忍对象不存在。
		// 不加 --exit-on-error：个别环境噪音错误（如 schema 撞名）由下方分类兜底。
		args = append(args, "--clean", "--if-exists")
	}
	// 过滤 TOC 里的 SCHEMA 条目：schema 的存在性由本工具管理（--clean 会试图
	// DROP SCHEMA，会被 schema 内的扩展依赖挡住；目标库已有该 schema 时又会报
	// already exists）。用 --use-list 只恢复 schema 内的对象。
	if listPath, lerr := writeFilteredTOC(ctx, restoreBin, dumpPath, tmpDir); lerr == nil {
		args = append(args, "--use-list="+listPath)
	} else {
		fmt.Fprintf(warn, "[warn] 读取归档 TOC 失败，按完整归档恢复: %v\n", lerr)
	}
	args = append(args, dumpPath)

	var stderrBuf bytes.Buffer
	var stderrOut io.Writer = nullWriter(opts.Stderr)
	tee := io.MultiWriter(stderrOut, &stderrBuf)
	if err := runPGToolCapture(ctx, restoreBin, args, &target, tee); err != nil {
		stderrText := stderrBuf.String()
		switch {
		case onlyBenignRestoreErrors(stderrText):
			// 两种模式都会遇到：--clean 下目标 schema 已存在；
			// --drop 下是我们为扩展预创建的 schema 与 dump 的 CREATE SCHEMA 撞名。
			fmt.Fprintln(warn, "[warn] pg_restore 报告了已知可忽略的错误（schema 撞名/分区继承约束），恢复已继续")
		case isExtensionMissing(stderrText):
			return nil, fmt.Errorf("pg_restore 失败: %w\n目标库缺少转储依赖的扩展运算符类。请确认扩展已装在业务 schema 内：\n"+
				"  CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA %s;\n"+
				"（或使用新版备份，manifest.extensions 会记录并自动预创建）", err, schema)
		default:
			return nil, fmt.Errorf("pg_restore 失败: %w", err)
		}
	}

	// 6. 文件卷：先把旧目录改名备份，再解包覆盖
	fmt.Fprintln(warn, "[4/5] 恢复文件卷 ...")
	result := &RestoreResult{Manifest: *m, BusyConns: busy}
	if _, err := os.Stat(filesPath); err == nil && len(m.Files) > 0 {
		root := opts.Root
		if root == "" {
			root = "."
		}
		swapDirs := dirsCoveredBy(fileDirsOf(opts.FileDirs), m.Files)
		result.DirsBackedUp = backupExistingDirs(swapDirs, nowOf(opts.Now), warn)
		ff, ferr := os.Open(filesPath)
		if ferr != nil {
			return nil, ferr
		}
		result.FilesRestored, ferr = ExtractTarGz(ff, root)
		ff.Close()
		if ferr != nil {
			return nil, fmt.Errorf("解包文件卷失败: %w", ferr)
		}
	} else {
		fmt.Fprintln(warn, "[warn] 备份内没有文件卷，跳过")
	}

	fmt.Fprintf(warn, "[5/5] 恢复完成：%d 个文件落地，%d 个旧目录已备份\n",
		len(result.FilesRestored), len(result.DirsBackedUp))
	return result, nil
}

// ListSchemaExtensions 查询装在业务 schema（current_schema）里的扩展清单。
// pg_dump --schema 不会导出这些扩展，恢复端要靠这份清单预创建。
func ListSchemaExtensions(ctx context.Context, psqlBin string, t *Target) ([]ExtensionInfo, error) {
	const q = `select e.extname, n.nspname
  from pg_extension e join pg_namespace n on n.oid = e.extnamespace
 where n.nspname = current_schema() order by 1`
	args := append(connArgs(t), "--tuples-only", "--no-align", "--field-separator=|", "--command="+q)
	cmd := exec.CommandContext(ctx, psqlBin, args...)
	cmd.Env = pgEnv(t)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(out.String()))
	}
	var exts []ExtensionInfo
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name, schema, ok := strings.Cut(line, "|")
		if !ok {
			return nil, fmt.Errorf("解析扩展清单失败: %q", line)
		}
		exts = append(exts, ExtensionInfo{Name: strings.TrimSpace(name), Schema: strings.TrimSpace(schema)})
	}
	return exts, nil
}

// extensionNames 拼接扩展名列表（错误信息用）。
func extensionNames(exts []ExtensionInfo) string {
	names := make([]string, 0, len(exts))
	for _, e := range exts {
		names = append(names, e.Name)
	}
	return strings.Join(names, ", ")
}

// isExtensionMissing 判断 pg_restore 的 stderr 是否为缺扩展运算符类类错误。
func isExtensionMissing(stderrText string) bool {
	return strings.Contains(stderrText, "does not exist for access method") ||
		strings.Contains(stderrText, "operator class")
}

// writeFilteredTOC 用 pg_restore --list 读出归档目录，剔除 SCHEMA 条目后写到
// 临时文件，返回供 --use-list 使用。pg_restore --list 只读 TOC，不连数据库。
func writeFilteredTOC(ctx context.Context, restoreBin, dumpPath, tmpDir string) (string, error) {
	out, err := exec.CommandContext(ctx, restoreBin, "--list", dumpPath).Output()
	if err != nil {
		return "", fmt.Errorf("%w: %s", err, tailLines(string(out), 5))
	}
	var kept []string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		// 行格式: `7; 2615 16389 SCHEMA - zre zre`，第 3 个字段是对象类型
		if parts := strings.SplitN(line, ";", 2); len(parts) == 2 {
			if f := strings.Fields(parts[1]); len(f) >= 3 && f[2] == "SCHEMA" {
				continue
			}
		}
		kept = append(kept, line)
	}
	listPath := filepath.Join(tmpDir, "restore-toc.txt")
	if err := os.WriteFile(listPath, []byte(strings.Join(kept, "\n")+"\n"), 0o644); err != nil {
		return "", err
	}
	return listPath, nil
}

// CountActiveConns 通过 psql 查询 pg_stat_activity，返回目标库上其他客户端连接数
// （排除本次检查自身的连接）。
func CountActiveConns(ctx context.Context, psqlBin string, t *Target, stderr io.Writer) (int, error) {
	const q = `select count(*) from pg_stat_activity ` +
		`where datname = current_database() and pid <> pg_backend_pid() and backend_type = 'client backend'`
	args := append(connArgs(t), "--tuples-only", "--no-align", "--command="+q)
	cmd := exec.CommandContext(ctx, psqlBin, args...)
	cmd.Env = pgEnv(t)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = io.MultiWriter(nullWriter(stderr), &out)
	if err := cmd.Run(); err != nil {
		return 0, fmt.Errorf("%w: %s", err, strings.TrimSpace(out.String()))
	}
	n, err := strconv.Atoi(strings.TrimSpace(out.String()))
	if err != nil {
		return 0, fmt.Errorf("解析活跃连接数失败: %q", out.String())
	}
	return n, nil
}

// onlyBenignRestoreErrors 判断 pg_restore 的 stderr 是否只包含已知可忽略的错误：
//   - schema 已存在（--clean 模式撞名 / --drop 模式预创建的 schema 与 dump 撞名）
//   - cannot drop inherited constraint（pg_restore --clean 对分区表主键的已知噪音，
//     分区会从父表继承主键，单独特删本就不该发生）
func onlyBenignRestoreErrors(stderrText string) bool {
	sawError := false
	for _, line := range strings.Split(stderrText, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, "error") {
			continue
		}
		sawError = true
		if strings.Contains(line, "already exists") {
			continue
		}
		if strings.Contains(line, "cannot drop inherited constraint") {
			continue
		}
		if strings.Contains(line, "errors ignored on restore:") {
			continue
		}
		return false
	}
	return sawError
}

// backupExistingDirs 把已存在的旧目录改名为 <dir>.bak-<时间戳>（重名时追加序号），返回改名结果。
func backupExistingDirs(dirs []string, now time.Time, warn io.Writer) []string {
	ts := now.Format("20060102-150405")
	backed := make([]string, 0, len(dirs))
	for _, dir := range dirs {
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		bak := dir + ".bak-" + ts
		for i := 1; ; i++ {
			if _, err := os.Stat(bak); err != nil {
				break
			}
			bak = fmt.Sprintf("%s.bak-%s-%d", dir, ts, i)
		}
		if err := os.Rename(dir, bak); err != nil {
			fmt.Fprintf(warn, "[warn] 旧目录备份失败（继续原目录覆盖）: %s → %s: %v\n", dir, bak, err)
			continue
		}
		fmt.Fprintf(warn, "旧目录已备份: %s → %s\n", dir, bak)
		backed = append(backed, bak)
	}
	return backed
}

// dirsCoveredBy 返回 fileDirs 中至少出现在 files 清单里的目录。
func dirsCoveredBy(fileDirs, files []string) []string {
	out := make([]string, 0, len(fileDirs))
	for _, d := range fileDirs {
		prefix := filepath.ToSlash(filepath.Clean(d)) + "/"
		for _, f := range files {
			norm := filepath.ToSlash(filepath.Clean(f))
			if norm == filepath.ToSlash(filepath.Clean(d)) || strings.HasPrefix(norm, prefix) {
				out = append(out, d)
				break
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// 备份清单
// ---------------------------------------------------------------------------

// List 扫描目录下的 .zrebackup 并读取 manifest 摘要；单个文件损坏不影响其余条目。
func List(dir string) []BackupSummary {
	matches, err := filepath.Glob(filepath.Join(dir, "*"+Ext))
	if err != nil {
		return nil
	}
	out := make([]BackupSummary, 0, len(matches))
	for _, p := range matches {
		s := BackupSummary{Path: p, Name: strings.TrimSuffix(filepath.Base(p), Ext)}
		if info, err := os.Stat(p); err == nil {
			s.Size = info.Size()
		}
		m, err := ReadArchiveManifest(p)
		if err != nil {
			s.Err = err
		} else {
			s.Manifest = m
		}
		out = append(out, s)
	}
	return out
}

// ---------------------------------------------------------------------------
// 内部小工具
// ---------------------------------------------------------------------------

// connArgs 生成 pg 工具的连接参数（不含密码；密码走 PGPASSWORD）。
func connArgs(t *Target) []string {
	args := make([]string, 0, 4)
	if t.Host != "" {
		args = append(args, "--host="+t.Host)
	}
	if t.Port > 0 {
		args = append(args, "--port="+strconv.Itoa(t.Port))
	}
	if t.User != "" {
		args = append(args, "--username="+t.User)
	}
	if t.DBName != "" {
		args = append(args, "--dbname="+t.DBName)
	}
	return args
}

// pgEnv 生成带 PGPASSWORD / PGSSLMODE 的子进程环境。
func pgEnv(t *Target) []string {
	env := os.Environ()
	if t.Password != "" {
		env = append(env, "PGPASSWORD="+t.Password)
	}
	if t.SSLMode != "" {
		env = append(env, "PGSSLMODE="+t.SSLMode)
	}
	return env
}

// runPGTool 执行 pg 工具，stdout/stderr 透传到 passthrough，同时留存摘要；
// 失败时错误信息附最后 10 行输出，便于一眼看到原因。
func runPGTool(ctx context.Context, bin string, args []string, t *Target, passthrough io.Writer) error {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = pgEnv(t)
	var buf bytes.Buffer
	w := io.MultiWriter(nullWriter(passthrough), &buf)
	cmd.Stdout = w
	cmd.Stderr = w
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w\n%s", err, tailLines(buf.String(), 10))
	}
	return nil
}

// runPGToolCapture 执行 pg 工具，stdout/stderr 全部写入给定 writer（不额外摘要）。
func runPGToolCapture(ctx context.Context, bin string, args []string, t *Target, out io.Writer) error {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = pgEnv(t)
	cmd.Stdout = out
	cmd.Stderr = out
	return cmd.Run()
}

// probeVersion 返回工具 --version 的第一行，失败返回空串（非致命）。
func probeVersion(ctx context.Context, bin string) string {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, bin, "--version").Output()
	if err != nil {
		return ""
	}
	line, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	return line
}

// hashFile 返回文件的 sha256 与大小。
func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, fmt.Errorf("打开 %s 失败: %w", path, err)
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, fmt.Errorf("读取 %s 失败: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// hashBytes 返回字节串的 sha256（测试与调用方共用）。
func hashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func schemaOf(t *Target) string {
	if t.Schema == "" {
		return "public"
	}
	return t.Schema
}

func sourceOf(t *Target) SourceInfo {
	return SourceInfo{Host: t.Host, Port: t.Port, User: t.User, DBName: t.DBName, Schema: schemaOf(t)}
}

func fileDirsOf(dirs []string) []string {
	if len(dirs) > 0 {
		return dirs
	}
	return DefaultFileDirs
}

func nowOf(now func() time.Time) time.Time {
	if now != nil {
		return now()
	}
	return time.Now()
}

func nullWriter(w io.Writer) io.Writer {
	if w == nil {
		return io.Discard
	}
	return w
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// quoteIdent 按 PostgreSQL 规则给标识符加引号（防御 schema 名里的特殊字符）。
func quoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// tailLines 取文本最后 n 行（错误信息摘要）。
func tailLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// humanBytes 把字节数格式化为人类可读大小。
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

// gitInfo 读取 go build 的 VCS 信息；go run 或无 VCS 时返回零值（manifest 里省略）。
func gitInfo() GitInfo {
	var out GitInfo
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return out
	}
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			out.Revision = s.Value
		case "vcs.modified":
			out.Modified = s.Value == "true"
		}
	}
	return out
}
