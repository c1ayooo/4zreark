// backup：4zreark 平台全量备份/恢复 CLI。
//
// 产物是单个 <名>.zrebackup（tar.gz：manifest.json + db.dump + files.tar.gz），
// 数据库走 pg_dump/pg_restore，文件卷覆盖 config/dicts、pocs、configs。
//
// 用法：
//
//	go run ./cmd/backup create [-o backups] [-n zre-20261023-153000] [-config config/config.yaml] [-pg-bin 目录]
//	go run ./cmd/backup restore <file.zrebackup> [--drop] [--yes] [--force] [-config ...] [-pg-bin 目录]
//	go run ./cmd/backup list [-o backups]
//
// 退出码：0 成功；1 一般错误；2 恢复被安全检查拒绝（目标库活跃连接超阈值）。
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/internal/backup"
)

const usageText = `4zreark 全量备份/恢复工具

用法：
  backup create [-o 输出目录] [-n 备份名] [-config 配置文件] [-pg-bin 目录]
  backup restore <file.zrebackup> [--drop] [--yes] [--force] [-config 配置文件] [-pg-bin 目录]
  backup list [-o 目录]

子命令：
  create   备份 PostgreSQL 业务库（pg_dump custom 格式）+ 文件卷（config/dicts、pocs、configs）为单个 .zrebackup
  restore  从 .zrebackup 恢复数据库与文件卷（默认 --clean 逐对象替换；--drop 则先删 schema 全量重建）
  list     列出目录下所有备份及 manifest 摘要

通用参数：
  -config   配置文件路径（默认 config/config.yaml）
  -pg-bin   pg_dump/pg_restore/psql 所在目录（优先于 PATH 查找）
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usageText)
		os.Exit(1)
	}
	switch os.Args[1] {
	case "create":
		cmdCreate(os.Args[2:])
	case "restore":
		cmdRestore(os.Args[2:])
	case "list":
		cmdList(os.Args[2:])
	case "-h", "--help", "help":
		fmt.Print(usageText)
	default:
		fmt.Fprintf(os.Stderr, "未知子命令 %q\n\n", os.Args[1])
		fmt.Fprint(os.Stderr, usageText)
		os.Exit(1)
	}
}

// targetFromConfig 把 config.PostgresConfig 映射为 backup.Target。
func targetFromConfig(cfg *config.Config) backup.Target {
	pg := cfg.Postgres
	return backup.Target{
		Host:     pg.Host,
		Port:     pg.Port,
		User:     pg.User,
		Password: pg.Password,
		DBName:   pg.DBName,
		Schema:   pg.Schema,
		SSLMode:  pg.SSLMode,
	}
}

func loadConfigOrDie(path string) *config.Config {
	if path == "" {
		path = "config/config.yaml"
	}
	cfg := config.LoadConfig(path)
	if cfg == nil || cfg.Postgres.DBName == "" {
		fmt.Fprintf(os.Stderr, "读取配置失败或 postgres.dbname 为空: %s\n", path)
		os.Exit(1)
	}
	return cfg
}

func cmdCreate(args []string) {
	fs := flag.NewFlagSet("create", flag.ExitOnError)
	outDir := fs.String("o", "backups", "输出目录")
	name := fs.String("n", "", "备份名（默认 zre-<yyyymmdd>-<hhmmss>）")
	cfgPath := fs.String("config", "config/config.yaml", "配置文件路径")
	pgBin := fs.String("pg-bin", "", "pg_dump 所在目录（优先于 PATH）")
	fs.Parse(args)

	cfg := loadConfigOrDie(*cfgPath)
	opts := backup.CreateOptions{
		Target:   targetFromConfig(cfg),
		OutDir:   *outDir,
		Name:     *name,
		PGBinDir: *pgBin,
		Timeout:  backup.DefaultTimeout,
		Stderr:   os.Stderr,
		Warn:     os.Stderr,
	}

	ctx, cancel := context.WithTimeout(context.Background(), backup.DefaultTimeout)
	defer cancel()

	res, err := backup.Create(ctx, opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "备份失败:", err)
		os.Exit(1)
	}

	fmt.Println("备份完成")
	fmt.Printf("  文件:     %s (%s)\n", res.Path, humanBytes(res.Size))
	fmt.Printf("  源库:     %s@%s:%d/%s schema=%s\n",
		res.Manifest.Source.User, res.Manifest.Source.Host, res.Manifest.Source.Port,
		res.Manifest.Source.DBName, res.Manifest.Source.Schema)
	fmt.Printf("  pg_dump:  %s\n", res.Manifest.PgDumpVersion)
	fmt.Printf("  文件卷:   %d 个文件\n", len(res.Manifest.Files))
	fmt.Printf("  创建时间: %s\n", res.Manifest.CreatedAt.Format("2006-01-02 15:04:05"))
}

func cmdRestore(args []string) {
	fs := flag.NewFlagSet("restore", flag.ExitOnError)
	drop := fs.Bool("drop", false, "先 DROP SCHEMA ... CASCADE 再全量恢复（未加时用 --clean 逐对象替换）")
	yes := fs.Bool("yes", false, "跳过交互确认（非交互环境必须显式传入）")
	force := fs.Bool("force", false, "目标库存在活跃连接时强制恢复")
	cfgPath := fs.String("config", "config/config.yaml", "配置文件路径")
	pgBin := fs.String("pg-bin", "", "pg_restore/psql 所在目录（优先于 PATH）")
	flags, positional := splitArgs(args)
	fs.Parse(flags)

	file := ""
	if len(positional) > 0 {
		file = positional[0]
	}
	if file == "" {
		fmt.Fprintln(os.Stderr, "缺少备份文件参数：backup restore <file.zrebackup>")
		os.Exit(1)
	}

	cfg := loadConfigOrDie(*cfgPath)
	target := targetFromConfig(cfg)

	// 恢复前校验归档并打印醒目警告
	manifest, err := backup.ValidateArchive(file)
	if err != nil {
		fmt.Fprintln(os.Stderr, "备份校验失败:", err)
		os.Exit(1)
	}
	mode := "--clean 逐对象替换"
	if *drop {
		mode = "先 DROP SCHEMA " + schemaName(target.Schema) + " CASCADE，再全量重建"
	}
	fmt.Println()
	fmt.Println("======================================================================")
	fmt.Println("!! 危险操作：即将覆盖目标数据库与文件卷 !!")
	fmt.Printf("  目标库:   %s@%s:%d/%s schema=%s\n",
		orDash(target.User), target.Host, target.Port, target.DBName, schemaName(target.Schema))
	fmt.Printf("  备份源:   %s@%s:%d/%s schema=%s（创建于 %s）\n",
		manifest.Source.User, manifest.Source.Host, manifest.Source.Port,
		manifest.Source.DBName, manifest.Source.Schema,
		manifest.CreatedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("  恢复方式: %s\n", mode)
	fmt.Printf("  文件卷:   %d 个文件 → 覆盖前旧目录改名备份为 <目录>.bak-<时间戳>\n", len(manifest.Files))
	fmt.Println("======================================================================")

	if !*yes {
		if !isTerminal(os.Stdin) {
			fmt.Fprintln(os.Stderr, "\n非交互环境：请显式加 --yes 确认执行恢复。")
			os.Exit(1)
		}
		fmt.Print("\n确认恢复？输入 yes 继续，其他任意输入取消: ")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		ans := strings.ToLower(strings.TrimSpace(line))
		if ans != "y" && ans != "yes" {
			fmt.Println("已取消。")
			return
		}
	}

	opts := backup.RestoreOptions{
		File:     file,
		Target:   target,
		Drop:     *drop,
		Force:    *force,
		Root:     ".",
		PGBinDir: *pgBin,
		Timeout:  backup.DefaultTimeout,
		Stderr:   os.Stderr,
		Warn:     os.Stderr,
	}

	ctx, cancel := context.WithTimeout(context.Background(), backup.DefaultTimeout)
	defer cancel()

	res, err := backup.Restore(ctx, opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "恢复失败:", err)
		if errors.Is(err, backup.ErrBusy) {
			os.Exit(2) // 安全检查拒绝，与一般错误区分
		}
		os.Exit(1)
	}

	fmt.Println()
	fmt.Println("恢复完成")
	fmt.Printf("  数据库:   pg_restore 完成（活跃连接观测值 %d）\n", res.BusyConns)
	fmt.Printf("  文件卷:   %d 个文件落地\n", len(res.FilesRestored))
	for _, d := range res.DirsBackedUp {
		fmt.Printf("    旧目录备份: %s\n", d)
	}
	fmt.Println()
	fmt.Println("提示：若备份来自旧版本，启动平台后请核对 schema_migrations——")
	fmt.Println("      缺失的增量迁移需按文件名顺序重放 docs/sql/ 下的 migration_*.sql。")
}

func cmdList(args []string) {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	dir := fs.String("o", "backups", "备份目录")
	fs.Parse(args)

	items := backup.List(*dir)
	if len(items) == 0 {
		fmt.Printf("目录 %s 下没有 %s 备份文件\n", *dir, backup.Ext)
		return
	}
	fmt.Printf("%-26s %10s  %-19s  %-32s  %s\n", "备份名", "大小", "创建时间", "源库", "pg_dump")
	for _, it := range items {
		if it.Err != nil {
			fmt.Printf("%-26s %10s  %-19s  <manifest 读取失败: %v>\n", it.Name, humanBytes(it.Size), "-", it.Err)
			continue
		}
		m := it.Manifest
		src := fmt.Sprintf("%s@%s:%d/%s/%s", orDash(m.Source.User), m.Source.Host, m.Source.Port, m.Source.DBName, m.Source.Schema)
		fmt.Printf("%-26s %10s  %-19s  %-32s  %s\n",
			it.Name, humanBytes(it.Size), m.CreatedAt.Format("2006-01-02 15:04:05"), src, m.PgDumpVersion)
	}
}

// splitArgs 把子命令参数拆成 flag 与位置参数，允许位置参数（如备份文件路径）
// 出现在任意位置：Go 标准库 flag 遇到第一个非 flag 参数就会停止解析，
// 所以要先摘出位置参数，剩下的交给 flag.FlagSet。
// boolFlags 是无值开关集合（--yes/--drop/--force），用于跳过它们的值识别；
// 带值 flag（-config/-pg-bin/-o/-n）后面紧随的非 flag 参数视为其值。
func splitArgs(args []string) (flags []string, positional []string) {
	valueFlags := map[string]bool{"o": true, "n": true, "config": true, "pg-bin": true}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if len(a) > 1 && a[0] == '-' {
			flags = append(flags, a)
			if !strings.Contains(a, "=") {
				name := strings.TrimLeft(a, "-")
				if valueFlags[name] && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
					i++
					flags = append(flags, args[i])
				}
			}
			continue
		}
		positional = append(positional, a)
	}
	return flags, positional
}

// isTerminal 判断 f 是否为交互式终端。
func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func schemaName(s string) string {
	if s == "" {
		return "public"
	}
	return s
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

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
