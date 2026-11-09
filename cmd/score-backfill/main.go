// score-backfill 给存量提交回填预评分（watchlist 种子关键词/路径规则变更后可重跑）。
//
//	go run ./cmd/score-backfill            # 只回填 pending
//	go run ./cmd/score-backfill -all       # 全表
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
)

func main() {
	all := flag.Bool("all", false, "回填全部提交（默认只回填 pending）")
	flag.Parse()
	cfg := config.LoadConfig(os.Getenv("CONFIG_PATH"))
	if cfg.Postgres.Host == "" {
		log.Fatal("缺少 PostgreSQL 配置")
	}
	ctx := context.Background()
	r, err := repo.Open(ctx, &cfg.Postgres)
	if err != nil {
		log.Fatalf("连接失败: %v", err)
	}
	defer r.Close()

	where := "where status='pending'"
	if *all {
		where = ""
	}
	rows, err := r.Pool().Query(ctx, `select id, subject, diff from zre.commit `+where)
	if err != nil {
		log.Fatalf("读取失败: %v", err)
	}
	type item struct {
		id    int64
		score int
	}
	items := []item{}
	for rows.Next() {
		var id int64
		var subject, diff string
		if err := rows.Scan(&id, &subject, &diff); err != nil {
			log.Fatalf("scan: %v", err)
		}
		items = append(items, item{id: id, score: service.ScoreCommit(subject, service.ParseDiff(diff))})
	}
	rows.Close()
	fmt.Println("待回填:", len(items))

	updated := 0
	for _, it := range items {
		tag, err := r.Pool().Exec(ctx, `update zre.commit set score=$2 where id=$1`, it.id, it.score)
		if err != nil {
			log.Fatalf("更新失败 id=%d: %v", it.id, err)
		}
		updated += int(tag.RowsAffected())
	}
	fmt.Printf("完成: 更新 %d 条\n", updated)
}
