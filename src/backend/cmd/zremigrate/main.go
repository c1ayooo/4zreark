// zremigrate：Mongo 导出 → PostgreSQL 一次性迁移。
//
// 输入目录里每个集合一个文件：<collection>.json（JSON 数组，mongoexport --jsonArray）
// 或 <collection>.jsonl（每行一个文档）。工具按固定白名单映射到同名表，
// 把 mongoexport 的扩展 JSON（$oid/$date/$numberLong/$binary）展开后写库。
//
//	go run ./cmd/zremigrate -dir /path/to/export -batch 500
//	go run ./cmd/zremigrate -dir /path/to/export -dry-run
//	go run ./cmd/zremigrate -dir /path/to/export -collections users,tasks
package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/repo"
)

// 集合 → PG 表。只列 Mongo 时代实际存在的集合；文件不存在自动跳过。
var collectionTables = map[string]string{
	"users": "users", "roles": "roles", "permissions": "permissions",
	"operation_logs": "operation_logs", "workspaces": "workspaces",
	"tasks": "tasks", "task_templates": "task_templates",
	"task_logs": "task_logs", "task_jobs": "task_jobs",
	"scan_results": "scan_results", "result_dedup": "result_dedup",
	"vulnerabilities": "vulnerabilities", "pocs": "pocs", "vuln_reports": "vuln_reports",
	"scanner_nodes": "scanner_nodes", "plugins": "plugins",
	"fingerprint_rules": "fingerprint_rules", "dictionaries": "dictionaries",
	"cruise_tasks": "cruise_tasks", "cruise_logs": "cruise_logs",
	"vuln_intel": "vuln_intel", "vuln_intel_analysis": "vuln_intel_analysis",
	"vuln_intel_settings": "vuln_intel_settings",
	"token_blacklist":     "token_blacklist", "llm_usage": "llm_usage",
}

type collectionResult struct {
	Collection string `json:"collection"`
	Table      string `json:"table"`
	Docs       int    `json:"docs"`
	Inserted   int64  `json:"inserted"`
	Failed     int    `json:"failed"`
	Skipped    int    `json:"skipped"`
	TableRows  int64  `json:"table_rows"`
}

func main() {
	dir := flag.String("dir", "", "导出目录（每个集合一个 .json/.jsonl）")
	collections := flag.String("collections", "", "只迁移指定集合，逗号分隔")
	batch := flag.Int("batch", 500, "每批插入条数")
	dryRun := flag.Bool("dry-run", false, "只解析/统计，不写库")
	cfgPath := flag.String("config", "config/config.yaml", "配置文件路径")
	flag.Parse()
	if *dir == "" {
		log.Fatal("缺少 -dir 参数")
	}

	names, err := resolveCollections(*dir, *collections)
	if err != nil {
		log.Fatalf("读取导出目录失败: %v", err)
	}
	if len(names) == 0 {
		log.Fatal("目录里没有可识别的集合文件")
	}

	var mr repo.MigrateRepo
	var r *repo.Repo
	if !*dryRun {
		cfg := config.LoadConfig(*cfgPath)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		r, err = repo.Open(ctx, &cfg.Postgres)
		if err != nil {
			log.Fatalf("连接 PostgreSQL 失败: %v", err)
		}
		defer r.Close()
		mr = r.Migrate()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	results := make([]collectionResult, 0, len(names))
	for _, name := range names {
		table, ok := collectionTables[name]
		if !ok {
			log.Printf("[skip] 未识别的集合 %s（文件 %s）", name, name)
			continue
		}
		path := findCollectionFile(*dir, name)
		docs, rerr := readDocuments(path)
		if rerr != nil {
			log.Printf("[%s] 读取失败: %v", name, rerr)
			continue
		}
		res := collectionResult{Collection: name, Table: table, Docs: len(docs)}
		if *dryRun {
			results = append(results, res)
			log.Printf("[dry-run] %-22s docs=%d", name, len(docs))
			continue
		}
		if table == "scan_results" {
			ensureScanPartitions(ctx, mr, docs)
		}

		inserted, failed := insertDocs(ctx, mr, table, docs, *batch)
		res.Inserted = inserted
		res.Failed = failed
		res.Skipped = len(docs) - int(inserted) - failed
		res.TableRows, _ = mr.Count(ctx, table)
		results = append(results, res)
		log.Printf("[%s] docs=%d inserted=%d failed=%d skipped=%d table_rows=%d",
			name, res.Docs, res.Inserted, res.Failed, res.Skipped, res.TableRows)
	}

	printSummary(results, *dryRun)
}

func resolveCollections(dir, filter string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	want := map[string]bool{}
	if strings.TrimSpace(filter) != "" {
		for _, s := range strings.Split(filter, ",") {
			want[strings.TrimSpace(s)] = true
		}
	}
	seen := map[string]bool{}
	names := make([]string, 0)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext != ".json" && ext != ".jsonl" {
			continue
		}
		name := strings.TrimSuffix(strings.TrimSuffix(e.Name(), ext), ".jsonl")
		name = strings.TrimSuffix(name, ".json")
		if len(want) > 0 && !want[name] {
			continue
		}
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names, nil
}

func findCollectionFile(dir, name string) string {
	for _, ext := range []string{".jsonl", ".json"} {
		p := filepath.Join(dir, name+ext)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return filepath.Join(dir, name+".json")
}

func readDocuments(path string) ([]map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, nil
	}
	if strings.HasPrefix(trimmed, "[") {
		var arr []map[string]any
		if err := json.Unmarshal([]byte(trimmed), &arr); err != nil {
			return nil, err
		}
		return normalizeDocs(arr), nil
	}

	var out []map[string]any
	scanner := bufio.NewScanner(strings.NewReader(trimmed))
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	line := 0
	for scanner.Scan() {
		line++
		text := strings.TrimSpace(scanner.Text())
		if text == "" {
			continue
		}
		var doc map[string]any
		if err := json.Unmarshal([]byte(text), &doc); err != nil {
			return nil, fmt.Errorf("第 %d 行解析失败: %w", line, err)
		}
		out = append(out, normalizeDoc(doc))
	}
	return out, scanner.Err()
}

func normalizeDocs(docs []map[string]any) []map[string]any {
	out := make([]map[string]any, len(docs))
	for i := range docs {
		out[i] = normalizeDoc(docs[i])
	}
	return out
}

// normalizeDoc 展开 mongoexport 扩展 JSON，并把 _id 改名为 id。
func normalizeDoc(doc map[string]any) map[string]any {
	out := make(map[string]any, len(doc))
	for k, v := range doc {
		out[k] = normalizeValue(v)
	}
	if id, ok := out["_id"]; ok {
		if _, exists := out["id"]; !exists {
			out["id"] = id
		}
		delete(out, "_id")
	}
	return out
}

func normalizeValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		if len(x) == 1 {
			if oid, ok := x["$oid"].(string); ok {
				return oid
			}
			if d, ok := x["$date"]; ok {
				return normalizeDate(d)
			}
			if n, ok := x["$numberLong"].(string); ok {
				if i, err := strconv.ParseInt(n, 10, 64); err == nil {
					return i
				}
				return n
			}
			if n, ok := x["$numberInt"].(string); ok {
				if i, err := strconv.ParseInt(n, 10, 64); err == nil {
					return i
				}
				return n
			}
			if n, ok := x["$numberDouble"].(string); ok {
				if f, err := strconv.ParseFloat(n, 64); err == nil {
					return f
				}
				return n
			}
			if b, ok := x["$binary"].(map[string]any); ok {
				if s, ok := b["base64"].(string); ok {
					return s
				}
				return base64.StdEncoding.EncodeToString(nil)
			}
		}
		out := make(map[string]any, len(x))
		for k, val := range x {
			out[k] = normalizeValue(val)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i := range x {
			out[i] = normalizeValue(x[i])
		}
		return out
	default:
		return v
	}
}

func normalizeDate(v any) string {
	switch d := v.(type) {
	case string:
		if t, err := time.Parse(time.RFC3339Nano, d); err == nil {
			return t.UTC().Format(time.RFC3339Nano)
		}
		return d
	case map[string]any:
		if n, ok := d["$numberLong"].(string); ok {
			if ms, err := strconv.ParseInt(n, 10, 64); err == nil {
				return time.UnixMilli(ms).UTC().Format(time.RFC3339Nano)
			}
		}
	case float64:
		return time.UnixMilli(int64(d)).UTC().Format(time.RFC3339Nano)
	case int64:
		return time.UnixMilli(d).UTC().Format(time.RFC3339Nano)
	}
	return fmt.Sprintf("%v", v)
}

func ensureScanPartitions(ctx context.Context, mr repo.MigrateRepo, docs []map[string]any) {
	months := map[string]time.Time{}
	for _, doc := range docs {
		s, _ := doc["created_at"].(string)
		if s == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			continue
		}
		key := fmt.Sprintf("%04d-%02d", t.Year(), int(t.Month()))
		months[key] = t
	}
	for _, t := range months {
		if err := mr.EnsureScanResultPartition(ctx, t); err != nil {
			log.Printf("[partition] %s 创建失败: %v", t.Format("2006-01"), err)
		}
	}
}

func insertDocs(ctx context.Context, mr repo.MigrateRepo, table string, docs []map[string]any, batch int) (int64, int) {
	if batch <= 0 {
		batch = 500
	}
	cols, err := mr.Columns(ctx, table)
	if err != nil {
		log.Printf("[%s] 读取列清单失败: %v", table, err)
		return 0, len(docs)
	}
	colSet := make(map[string]bool, len(cols))
	for _, c := range cols {
		colSet[c] = true
	}

	// 文档字段集合可能不同（Mongo schemaless）：按列清单分组。
	// 只写文档里实际存在的列，缺失列走表默认值。
	type group struct {
		cols      []string
		payload   []string
		sourceIdx []int
	}
	groups := map[string]*group{}
	order := make([]string, 0)

	var inserted int64
	failed := 0
	for i, doc := range docs {
		filtered := make(map[string]any, len(doc))
		keys := make([]string, 0, len(doc))
		for k, v := range doc {
			if colSet[k] {
				filtered[k] = v
				keys = append(keys, k)
			}
		}
		if len(keys) == 0 {
			failed++
			if failed <= 5 {
				log.Printf("[%s] 第 %d 条没有可写入的列: %v", table, i+1, doc)
			}
			continue
		}
		sort.Strings(keys)
		sig := strings.Join(keys, "\x00")
		g := groups[sig]
		if g == nil {
			g = &group{cols: keys}
			groups[sig] = g
			order = append(order, sig)
		}
		b, err := json.Marshal(filtered)
		if err != nil {
			failed++
			continue
		}
		g.payload = append(g.payload, string(b))
		g.sourceIdx = append(g.sourceIdx, i)
	}

	for _, sig := range order {
		g := groups[sig]
		for start := 0; start < len(g.payload); start += batch {
			end := start + batch
			if end > len(g.payload) {
				end = len(g.payload)
			}
			chunk := g.payload[start:end]
			n, err := mr.InsertJSONDocs(ctx, table, g.cols, chunk)
			if err == nil {
				inserted += n
				continue
			}
			// 单条坏文档不拖累整批：逐行回退，报告具体错误
			log.Printf("[%s] 批量插入失败，逐行重试: %v", table, err)
			for j, p := range chunk {
				one, ierr := mr.InsertJSONDocs(ctx, table, g.cols, []string{p})
				if ierr != nil {
					failed++
					if failed <= 5 {
						log.Printf("[%s] 第 %d 条失败: %v", table, g.sourceIdx[start+j]+1, ierr)
					}
					continue
				}
				inserted += one
			}
		}
	}
	return inserted, failed
}

func printSummary(results []collectionResult, dryRun bool) {
	fmt.Println()
	if dryRun {
		fmt.Printf("%-24s %8s\n", "COLLECTION", "DOCS")
		for _, r := range results {
			fmt.Printf("%-24s %8d\n", r.Collection, r.Docs)
		}
		return
	}
	fmt.Printf("%-24s %8s %8s %8s %8s %10s\n", "COLLECTION", "DOCS", "INSERTED", "FAILED", "SKIPPED", "TABLE_ROWS")
	for _, r := range results {
		fmt.Printf("%-24s %8d %8d %8d %8d %10d\n", r.Collection, r.Docs, r.Inserted, r.Failed, r.Skipped, r.TableRows)
	}
}
