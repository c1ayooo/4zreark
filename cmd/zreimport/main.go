// zreimport：把资产清单 CSV 导入 4zreark 资产治理层（P0）。
//
// CSV 列（首行表头）：project_code,project_name,value,status_code,title,ip
//
//	go run ./cmd/zreimport -csv /path/assets.csv -source csv-import
package main

import (
	"context"
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/repo"
)

func main() {
	csvPath := flag.String("csv", "", "CSV 文件路径")
	source := flag.String("source", "csv-import", "记录来源标记")
	batch := flag.Int("batch", 500, "每批写入条数")
	flag.Parse()
	if *csvPath == "" {
		log.Fatal("缺少 -csv 参数")
	}

	cfg := config.LoadConfig("config/config.yaml")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	r, err := repo.Open(ctx, &cfg.Postgres)
	if err != nil {
		log.Fatalf("连接 PostgreSQL 失败: %v", err)
	}
	defer r.Close()

	f, err := os.Open(*csvPath)
	if err != nil {
		log.Fatalf("打开 CSV 失败: %v", err)
	}
	defer f.Close()

	rd := csv.NewReader(f)
	rd.FieldsPerRecord = -1
	header, err := rd.Read()
	if err != nil {
		log.Fatalf("读取表头失败: %v", err)
	}
	idx := map[string]int{}
	for i, h := range header {
		idx[strings.TrimSpace(h)] = i
	}
	get := func(rec []string, key string) string {
		if i, ok := idx[key]; ok && i < len(rec) {
			return strings.TrimSpace(rec[i])
		}
		return ""
	}

	projects := map[string]int64{}
	assets := repo.NewAssetRepo()
	var buf []repo.RawRecord
	var bufProject int64
	total := &repo.ImportResult{}
	flush := func() {
		if len(buf) == 0 {
			return
		}
		res, err := assets.ImportRecords(ctx, bufProject, *source, buf)
		if err != nil {
			log.Fatalf("导入失败: %v", err)
		}
		total.Records += res.Records
		total.NewSites += res.NewSites
		total.DupRecords += res.DupRecords
		buf = buf[:0]
	}

	rows := 0
	for {
		rec, err := rd.Read()
		if err != nil {
			break
		}
		rows++
		code := get(rec, "project_code")
		if code == "" {
			code = "default"
		}
		pid, ok := projects[code]
		if !ok {
			name := get(rec, "project_name")
			if name == "" {
				name = code
			}
			if pid, err = ensureProject(ctx, r, code, name); err != nil {
				log.Fatalf("创建项目失败: %v", err)
			}
			projects[code] = pid
		}
		if len(buf) > 0 && bufProject != pid {
			flush()
		}
		bufProject = pid

		value := get(rec, "value")
		host, port, proto := parseValue(value)
		status, _ := strconv.Atoi(get(rec, "status_code"))
		buf = append(buf, repo.RawRecord{
			Source: *source, Host: host, Port: port, Protocol: proto, Value: value,
			StatusCode: status, Title: get(rec, "title"), IP: get(rec, "ip"),
			Evidence: map[string]any{"row": rows},
		})
		if len(buf) >= *batch {
			flush()
		}
	}
	flush()

	fmt.Printf("CSV 行数 %d，写入原始记录 %d，新增站点 %d，重复 %d\n",
		rows, total.Records, total.NewSites, total.DupRecords)
}

func ensureProject(ctx context.Context, r *repo.Repo, code, name string) (int64, error) {
	var id int64
	err := r.Pool().QueryRow(ctx, `
		INSERT INTO projects (code, name) VALUES ($1,$2)
		ON CONFLICT (code) DO UPDATE SET name = EXCLUDED.name, updated_at = now()
		RETURNING id`, code, name).Scan(&id)
	return id, err
}

func parseValue(v string) (host string, port int, proto string) {
	proto = "https"
	if strings.HasPrefix(v, "http://") {
		proto = "http"
	}
	u, err := url.Parse(v)
	if err != nil || u.Hostname() == "" {
		return strings.TrimSpace(v), 0, proto
	}
	host = u.Hostname()
	if p := u.Port(); p != "" {
		port, _ = strconv.Atoi(p)
	}
	if port == 0 {
		if proto == "http" {
			port = 80
		} else {
			port = 443
		}
	}
	return host, port, proto
}
