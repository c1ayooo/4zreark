// 临时验收程序：直接驱动 service.ResultService，验证结果域在 PG 上的行为。
// 验收通过后本目录会被删除，不进入交付代码。
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"

	"github.com/c1ayooo/4zreark/oid"
)

var fails int

func check(name string, cond bool, detail string) {
	if cond {
		fmt.Printf("  ✓ %s\n", name)
		return
	}
	fails++
	fmt.Printf("  ✗ %s  → %s\n", name, detail)
}

func main() {
	cfg := config.LoadConfig("config/config.yaml")
	if cfg == nil || cfg.Postgres.Host == "" {
		fmt.Println("读取配置失败")
		os.Exit(1)
	}
	if _, err := repo.Open(context.Background(), &cfg.Postgres); err != nil {
		fmt.Println("连接 PG 失败:", err)
		os.Exit(1)
	}
	svc := service.NewResultService()

	taskID := oid.NewObjectID()
	if len(os.Args) > 1 {
		id, err := oid.ObjectIDFromHex(os.Args[1])
		if err != nil {
			fmt.Println("task id 非法:", err)
			os.Exit(1)
		}
		taskID = id
	}
	wsID := oid.NewObjectID()
	fmt.Printf("task_id = %s\n\n", taskID.Hex())

	// --- 1. 普通写入与回读 ---
	fmt.Println("[1] CreateResult 回读")
	plain := &models.ScanResult{
		TaskID:      taskID,
		WorkspaceID: wsID,
		Type:        models.ResultTypeSubdomain,
		Source:      "unit",
		Project:     "p1",
		Tags:        []string{"a", "b"},
		Data: map[string]interface{}{
			"subdomain":   "plain.example.com",
			"domain":      "example.com",
			"status_code": 200,
			"port":        443,
			"ip":          "10.1.2.3",
			"url":         "https://plain.example.com:443/",
		},
	}
	check("CreateResult 无错误", svc.CreateResult(plain) == nil, "写入失败")
	check("ID 已回填", !plain.ID.IsZero(), "ID 仍为零值")

	list, total, err := svc.GetResultsByTask(taskID.Hex(), models.ResultTypeSubdomain, 1, 20, "", 0)
	check("回读 1 条", err == nil && total == 1 && len(list) == 1, fmt.Sprintf("total=%d len=%d err=%v", total, len(list), err))
	if len(list) == 1 {
		r := list[0]
		check("ID 一致", r.ID == plain.ID, "ID 不一致")
		check("task_id 一致", r.TaskID == taskID, "task_id 不一致")
		check("workspace_id 一致", r.WorkspaceID == wsID, "workspace_id 不一致")
		check("type 一致", r.Type == models.ResultTypeSubdomain, string(r.Type))
		check("tags 一致", len(r.Tags) == 2 && r.Tags[0] == "a", fmt.Sprintf("%v", r.Tags))
		check("project 一致", r.Project == "p1", r.Project)
		check("source 一致", r.Source == "unit", r.Source)
		check("data.subdomain 一致", r.Data["subdomain"] == "plain.example.com", fmt.Sprintf("%v", r.Data["subdomain"]))
		sc, ok := r.Data["status_code"].(int64)
		check("data.status_code 解成整数 200", ok && sc == 200, fmt.Sprintf("%T %v", r.Data["status_code"], r.Data["status_code"]))
		check("created_at 非零", !r.CreatedAt.IsZero(), "零值")
	}

	// --- 2. 子域名去重 ---
	fmt.Println("[2] 子域名去重")
	r1 := &models.ScanResult{TaskID: taskID, Type: models.ResultTypeSubdomain, Source: "s1",
		Data: map[string]interface{}{"subdomain": "dup.example.com", "domain": "example.com"}}
	check("首次写入", svc.CreateResultWithDedup(r1) == nil, "失败")
	r2 := &models.ScanResult{TaskID: taskID, Type: models.ResultTypeSubdomain, Source: "s2",
		Data: map[string]interface{}{"subdomain": "dup.example.com", "domain": "example.com", "title": "第二次"}}
	check("重复写入", svc.CreateResultWithDedup(r2) == nil, "失败")
	_, total, _ = svc.GetResultsByTask(taskID.Hex(), models.ResultTypeSubdomain, 1, 50, "dup.example.com", 0)
	check("重复写入不新增行", total == 1, fmt.Sprintf("total=%d", total))
	list, _, _ = svc.GetResultsByTask(taskID.Hex(), models.ResultTypeSubdomain, 1, 50, "dup.example.com", 0)
	if len(list) == 1 {
		check("重复写入按 $set 语义刷新", list[0].Source == "s2" && list[0].Data["title"] == "第二次",
			fmt.Sprintf("source=%s title=%v", list[0].Source, list[0].Data["title"]))
	}

	// --- 3. 端口去重（ip + port） ---
	fmt.Println("[3] 端口去重")
	for i, svcName := range []string{"http", "https"} {
		res := &models.ScanResult{TaskID: taskID, Type: models.ResultTypePort, Source: "nmap",
			Data: map[string]interface{}{"ip": "10.0.0.9", "host": "h1.example.com", "port": 8080, "service": svcName}}
		check(fmt.Sprintf("写入端口结果 %d", i+1), svc.CreateResultWithDedup(res) == nil, "失败")
	}
	other := &models.ScanResult{TaskID: taskID, Type: models.ResultTypePort, Source: "nmap",
		Data: map[string]interface{}{"ip": "10.0.0.9", "host": "h1.example.com", "port": 8443, "service": "https"}}
	check("不同端口另起一行", svc.CreateResultWithDedup(other) == nil, "失败")
	stats, err := svc.GetResultStats(taskID.Hex())
	check("统计按类型计数", err == nil && stats["port"] == 2, fmt.Sprintf("stats=%v err=%v", stats, err))

	// --- 4. service 结果与子域名联合查询 ---
	fmt.Println("[4] 子域名联合 service 信息")
	svcRes := &models.ScanResult{TaskID: taskID, Type: models.ResultTypeService, Source: "httpx",
		Data: map[string]interface{}{
			"url":          "https://plain.example.com:443/",
			"host":         "plain.example.com",
			"title":        "示例站点",
			"status_code":  200,
			"server":       "nginx",
			"technologies": []interface{}{"Nginx", "Vue"},
			"port":         443,
		}}
	check("写入 service 结果", svc.CreateResultWithDedup(svcRes) == nil, "失败")
	check("service 去重（:443 归一）", svcRes.Data["dedup_host"] == "plain.example.com", fmt.Sprintf("%v", svcRes.Data["dedup_host"]))
	check("service 存了 normalized_url", svcRes.Data["normalized_url"] == "https://plain.example.com/", fmt.Sprintf("%v", svcRes.Data["normalized_url"]))

	subs, _, err := svc.GetSubdomainResults(taskID.Hex(), 1, 50, "plain")
	check("子域名列表可读", err == nil && len(subs) == 1, fmt.Sprintf("len=%d err=%v", len(subs), err))
	if len(subs) == 1 {
		s := subs[0]
		check("补充 title", s["title"] == "示例站点", fmt.Sprintf("%v", s["title"]))
		check("补充 status_code", fmt.Sprint(s["status_code"]) == "200", fmt.Sprintf("%T %v", s["status_code"], s["status_code"]))
		check("补充 web_server", s["web_server"] == "nginx", fmt.Sprintf("%v", s["web_server"]))
		fp, ok := s["fingerprint"].([]string)
		check("补充 fingerprint", ok && len(fp) == 2, fmt.Sprintf("%T %v", s["fingerprint"], s["fingerprint"]))
		check("id 为 24 位十六进制", len(fmt.Sprint(s["id"])) == 24, fmt.Sprintf("%v", s["id"]))
	}

	// --- 5. 端口聚合 ---
	fmt.Println("[5] 端口聚合")
	ports, ptotal, err := svc.GetPortResultsAggregated(taskID.Hex(), 1, 10, "")
	check("聚合出 1 个 IP", err == nil && ptotal == 1 && len(ports) == 1, fmt.Sprintf("total=%d len=%d", ptotal, len(ports)))
	if len(ports) == 1 {
		pl, ok := ports[0]["ports"].([]string)
		check("端口列表合并 2 个", ok && len(pl) == 2, fmt.Sprintf("%T %v", ports[0]["ports"], ports[0]["ports"]))
		check("port_count 正确", fmt.Sprint(ports[0]["port_count"]) == "2", fmt.Sprint(ports[0]["port_count"]))
	}
	_, ptotal, _ = svc.GetPortResultsAggregated(taskID.Hex(), 1, 10, "h1.example")
	check("端口搜索命中 host", ptotal == 1, fmt.Sprintf("total=%d", ptotal))
	_, ptotal, _ = svc.GetPortResultsAggregated(taskID.Hex(), 1, 10, "no-such-ip")
	check("端口搜索无命中", ptotal == 0, fmt.Sprintf("total=%d", ptotal))

	// --- 6. 标签维护 ---
	fmt.Println("[6] 标签")
	id := plain.ID.Hex()
	check("覆盖标签", svc.UpdateResultTags(id, []string{"x", "y"}) == nil, "失败")
	check("追加标签", svc.AddResultTag(id, "z") == nil, "失败")
	check("重复追加不产生重项", svc.AddResultTag(id, "z") == nil, "失败")
	list, _, _ = svc.GetResultsByTask(taskID.Hex(), models.ResultTypeSubdomain, 1, 20, "plain", 0)
	if len(list) == 1 {
		check("标签 = x,y,z", len(list[0].Tags) == 3, fmt.Sprintf("%v", list[0].Tags))
	}
	check("移除标签", svc.RemoveResultTag(id, "y") == nil, "失败")
	list, _, _ = svc.GetResultsByTask(taskID.Hex(), models.ResultTypeSubdomain, 1, 20, "plain", 0)
	if len(list) == 1 {
		check("标签 = x,z", len(list[0].Tags) == 2, fmt.Sprintf("%v", list[0].Tags))
	}

	// --- 7. 搜索与过滤 ---
	fmt.Println("[7] 搜索与过滤")
	// 目录扫描结果同时带 status 与 status_code（改造前就是这样），status_code 筛选走的是 status
	dirRes := &models.ScanResult{TaskID: taskID, Type: models.ResultTypeDirScan, Source: "dirscan",
		Data: map[string]interface{}{"url": "https://plain.example.com/admin", "status": 403, "status_code": 403}}
	check("写入目录扫描结果", svc.CreateResultWithDedup(dirRes) == nil, "失败")
	_, st, _ := svc.GetResultsByTask(taskID.Hex(), "", 1, 50, "", 403)
	check("status_code 过滤", st == 1, fmt.Sprintf("total=%d", st))
	_, st, _ = svc.GetResultsByTask(taskID.Hex(), models.ResultTypeDirScan, 1, 50, "", 0)
	check("按类型过滤", st == 1, fmt.Sprintf("total=%d", st))
	_, st, _ = svc.GetResultsByTask(taskID.Hex(), "", 1, 50, "10.0.0.9", 0)
	check("按 ip 搜索", st == 2, fmt.Sprintf("total=%d", st))
	_, st, _ = svc.GetResultsByTask(taskID.Hex(), "", 1, 50, "%", 0)
	check("通配符被转义（不返回全量）", st == 0, fmt.Sprintf("total=%d", st))
	page1, t1, _ := svc.GetResultsByTask(taskID.Hex(), "", 1, 2, "", 0)
	_, t2, _ := svc.GetResultsByTask(taskID.Hex(), "", 2, 2, "", 0)
	check("分页 total 稳定", t1 == t2 && len(page1) <= 2, fmt.Sprintf("t1=%d t2=%d", t1, t2))

	// --- 8. 导出 ---
	fmt.Println("[8] 导出")
	all, err := svc.ExportResults(taskID.Hex(), "")
	check("导出全部", err == nil && int64(len(all)) == t1, fmt.Sprintf("len=%d total=%d", len(all), t1))
	onlyPort, _ := svc.ExportResults(taskID.Hex(), models.ResultTypePort)
	check("按类型导出", len(onlyPort) == 2, fmt.Sprintf("len=%d", len(onlyPort)))

	// --- 9. CDN 回填 ---
	fmt.Println("[9] CDN 回填")
	check("更新 CDN", svc.UpdateSubdomainCDN(taskID.Hex(), "plain.example.com", "cloudflare") == nil, "失败")
	list, _, _ = svc.GetResultsByTask(taskID.Hex(), models.ResultTypeSubdomain, 1, 20, "plain", 0)
	if len(list) == 1 {
		check("cdn/cdn_provider 落库", list[0].Data["cdn"] == true && list[0].Data["cdn_provider"] == "cloudflare",
			fmt.Sprintf("cdn=%v provider=%v", list[0].Data["cdn"], list[0].Data["cdn_provider"]))
	}

	// --- 10. 批量写与批量删 ---
	fmt.Println("[10] 批量写 / 批量删")
	batch := []models.ScanResult{
		{TaskID: taskID, Type: models.ResultTypeURL, Data: map[string]interface{}{"url": "https://a/"}},
		{TaskID: taskID, Type: models.ResultTypeURL, Data: map[string]interface{}{"url": "https://b/"}},
	}
	check("批量写入", svc.BatchCreateResults(batch) == nil, "失败")
	ins, upd, err := svc.BatchCreateResultsWithDedup([]models.ScanResult{
		{TaskID: taskID, Type: models.ResultTypeURL, Data: map[string]interface{}{"url": "https://a/"}},
		{TaskID: taskID, Type: models.ResultTypeURL, Data: map[string]interface{}{"url": "https://c/"}},
	})
	check("批量去重返回 新增1/更新1", err == nil && ins == 1 && upd == 1, fmt.Sprintf("ins=%d upd=%d err=%v", ins, upd, err))
	all, _ = svc.ExportResults(taskID.Hex(), models.ResultTypeURL)
	check("URL 结果共 3 条", len(all) == 3, fmt.Sprintf("len=%d", len(all)))

	ids := []string{all[0].ID.Hex(), all[1].ID.Hex()}
	check("批量删除", svc.BatchDeleteResults(ids) == nil, "失败")
	all, _ = svc.ExportResults(taskID.Hex(), models.ResultTypeURL)
	check("删后剩 1 条", len(all) == 1, fmt.Sprintf("len=%d", len(all)))

	// --- 11. 删任务结果要连去重账本一起清 ---
	fmt.Println("[11] 删除任务结果")
	_, before, _ := svc.GetResultsByTask(taskID.Hex(), "", 1, 1, "", 0)
	check("删除前有数据", before > 0, fmt.Sprintf("total=%d", before))
	check("DeleteResultsByTask", svc.DeleteResultsByTask(taskID.Hex()) == nil, "失败")
	_, after, _ := svc.GetResultsByTask(taskID.Hex(), "", 1, 1, "", 0)
	check("删除后为空", after == 0, fmt.Sprintf("total=%d", after))
	again := &models.ScanResult{TaskID: taskID, Type: models.ResultTypeSubdomain,
		Data: map[string]interface{}{"subdomain": "dup.example.com", "domain": "example.com"}}
	check("同一去重键可重新写入", svc.CreateResultWithDedup(again) == nil, "失败")
	_, re, _ := svc.GetResultsByTask(taskID.Hex(), "", 1, 1, "", 0)
	check("重写后 1 条", re == 1, fmt.Sprintf("total=%d", re))

	// 清理
	_ = svc.DeleteResultsByTask(taskID.Hex())

	fmt.Println()
	if fails > 0 {
		fmt.Printf("失败 %d 项\n", fails)
		os.Exit(1)
	}
	fmt.Println("全部通过")
	_ = time.Now
}
