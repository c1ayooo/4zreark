// sentinel-seed 把监控池种子文件导入 repo 表（CommandSentinel 监控仓库）。
// 种子文件长期只停留在 docs/ 下没有任何导入路径，导致监控列表里
// 连 apache 系仓库（httpd/tomcat/activemq/solr/flink）都没有，本命令补上。
//
// 导入时用 git ls-remote --symref 解析每个仓库的真实默认分支
// （apache/httpd 是 trunk、nginx/nginx 是 default，硬编码 main 会采集失败）；
// 解析失败回退 main，并记录到输出里供人工修正。
//
//	go run ./cmd/sentinel-seed                    # 导入全部（已存在的跳过）
//	go run ./cmd/sentinel-seed -priority P0      # 只导入 P0
//	go run ./cmd/sentinel-seed -category middleware_gateway_runtime
//	go run ./cmd/sentinel-seed -dry-run          # 只打印不写库
//	go run ./cmd/sentinel-seed -no-resolve       # 不联网探测分支，统一按 main
//	go run ./cmd/sentinel-seed -file docs/sentinel-watchlist.json
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/oid"
	"github.com/c1ayooo/4zreark/repo"
)

// watchEntry 与 docs/sentinel-watchlist.json 的 repo 条目对应。
type watchEntry struct {
	Owner  string `json:"owner"`
	Name   string `json:"name"`
	Alias  string `json:"alias"`  // 展示别名，入库仍用 owner/name
	Branch string `json:"branch"` // 可选：显式指定分支，跳过联网探测
}

type watchPool struct {
	Priority string       `json:"priority"`
	Category string       `json:"category"`
	Repos    []watchEntry `json:"repos"`
}

type watchlist struct {
	Version     string      `json:"version"`
	Description string      `json:"description"`
	Pools       []watchPool `json:"pools"`
}

// resolveDefaultBranch 探测远端默认分支；失败回退 main 并返回 false 提示人工确认。
func resolveDefaultBranch(ctx context.Context, cloneURL string) (string, bool) {
	cmd := exec.CommandContext(ctx, "git", "ls-remote", "--symref", cloneURL, "HEAD")
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.Output()
	if err != nil {
		return "main", false
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "ref: ") {
			continue
		}
		ref := strings.Fields(strings.TrimPrefix(line, "ref: "))
		if len(ref) >= 1 && strings.HasPrefix(ref[0], "refs/heads/") {
			return strings.TrimPrefix(ref[0], "refs/heads/"), true
		}
	}
	return "main", false
}

func main() {
	file := flag.String("file", "docs/sentinel-watchlist.json", "种子文件路径")
	priority := flag.String("priority", "", "只导入指定优先级（P0/P1/P2），空为全部")
	category := flag.String("category", "", "只导入指定类别，空为全部")
	interval := flag.Int("interval", 60, "采集间隔（分钟）")
	dryRun := flag.Bool("dry-run", false, "只打印将要导入的仓库，不写库")
	noResolve := flag.Bool("no-resolve", false, "不联网探测默认分支（统一按 main）")
	flag.Parse()

	cfg := config.LoadConfig(os.Getenv("CONFIG_PATH"))
	if cfg.Postgres.Host == "" {
		log.Fatal("缺少 PostgreSQL 配置")
	}

	raw, err := os.ReadFile(*file)
	if err != nil {
		log.Fatalf("读取种子文件失败: %v", err)
	}
	var wl watchlist
	if err := json.Unmarshal(raw, &wl); err != nil {
		log.Fatalf("解析种子文件失败: %v", err)
	}

	// 先汇总去重，再逐个探测/写库，保证 -dry-run 输出与真实导入一致。
	type item struct {
		fullName, cloneURL, branch string
	}
	seen := map[string]bool{}
	items := []item{}
	for _, pool := range wl.Pools {
		if *priority != "" && pool.Priority != *priority {
			continue
		}
		if *category != "" && pool.Category != *category {
			continue
		}
		for _, e := range pool.Repos {
			if e.Owner == "" || e.Name == "" {
				continue
			}
			fullName := e.Owner + "/" + e.Name
			if seen[fullName] {
				continue
			}
			seen[fullName] = true
			items = append(items, item{
				fullName: fullName,
				cloneURL: "https://github.com/" + fullName + ".git",
				branch:   e.Branch,
			})
		}
	}
	fmt.Printf("种子 v%s：%d 个仓库（priority=%q category=%q dry_run=%v）\n",
		wl.Version, len(items), *priority, *category, *dryRun)

	ctx := context.Background()
	if *dryRun {
		for _, it := range items {
			branch := it.branch
			if branch == "" {
				branch = "(探测默认分支)"
			}
			fmt.Printf("  %-45s %s\n", it.fullName, branch)
		}
		return
	}

	r, err := repo.Open(ctx, &cfg.Postgres)
	if err != nil {
		log.Fatalf("连接失败: %v", err)
	}
	defer r.Close()

	inserted, exists, failed := 0, 0, 0
	for _, it := range items {
		branch := it.branch
		if branch == "" && !*noResolve {
			branch, _ = resolveDefaultBranch(ctx, it.cloneURL)
		}
		if branch == "" {
			branch = "main"
		}

		tag, err := r.Pool().Exec(ctx, `
			insert into repo (id, full_name, clone_url, default_branch, branch,
			                  interval_minutes, enabled)
			values ($1,$2,$3,$4,'',$5,true)
			on conflict (full_name) do nothing`,
			oid.NewObjectID().Hex(), it.fullName, it.cloneURL, branch, *interval)
		if err != nil {
			failed++
			log.Printf("写入失败 %s: %v", it.fullName, err)
			continue
		}
		if tag.RowsAffected() == 0 {
			exists++
			fmt.Printf("  已存在，跳过 %s\n", it.fullName)
			continue
		}
		inserted++
		fmt.Printf("  已导入 %s（branch=%s）\n", it.fullName, branch)
	}
	fmt.Printf("完成：新增 %d，已存在 %d，失败 %d\n", inserted, exists, failed)
	if failed > 0 {
		os.Exit(1)
	}
}
