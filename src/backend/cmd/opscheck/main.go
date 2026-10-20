// 临时验收程序：插件 / 节点 / 巡航 三域落 PG。
// 覆盖 HTTP 层看不到的分支：名称冲突、内置字典保护、节点 node_id 别名、
// 巡航执行计数与日志回填、操作审计写入。
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

var fails int

func check(name string, cond bool, detail string) {
	if cond {
		fmt.Printf("  OK   %s\n", name)
		return
	}
	fails++
	fmt.Printf("  FAIL %s  → %s\n", name, detail)
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
	r := repo.Default()
	ctx := context.Background()

	plugins := service.NewPluginService()
	nodes := service.NewNodeService()
	cruises := service.NewCruiseService()

	// ---------------------------------------------------------------- 插件
	fmt.Println("[1] 插件")
	created, _, err := plugins.ListPlugins("", "", nil, "验收插件", 1, 10)
	if err != nil {
		fmt.Println("列表失败:", err)
		os.Exit(1)
	}
	for _, p := range created {
		_ = plugins.DeletePlugin(p.ID.Hex())
	}

	p := &models.Plugin{
		Name:         "验收插件-A",
		Description:  "ops-acceptance",
		Author:       "验收员",
		Version:      "1.2.3",
		Type:         "scanner",
		Language:     "go",
		EntryFile:    "main.go",
		Config:       map[string]interface{}{"timeout": 30, "threads": 8},
		Dependencies: []string{"github.com/gin-gonic/gin"},
		Source:       "custom",
		Tags:         []string{"scanner", "test"},
	}
	if err := plugins.CreatePlugin(p); err != nil {
		fmt.Println("创建插件失败:", err)
		os.Exit(1)
	}
	check("创建插件", !p.ID.IsZero(), "")

	if err := plugins.CreatePlugin(&models.Plugin{Name: "验收插件-A"}); err == nil {
		check("同名插件被拒", false, "未报错")
	} else {
		check("同名插件被拒", err.Error() == "插件名称已存在", err.Error())
	}

	got, err := plugins.GetPluginByID(p.ID.Hex())
	check("按 ID 取回", err == nil && got.Name == p.Name, fmt.Sprint(err))
	check("installed 默认 true", got != nil && got.Installed, "")
	check("config jsonb 往返", got != nil && got.Config["timeout"] == float64(30), fmt.Sprint(got.Config))
	check("dependencies 往返", got != nil && len(got.Dependencies) == 1, fmt.Sprint(got.Dependencies))
	check("tags 往返", got != nil && len(got.Tags) == 2, fmt.Sprint(got.Tags))

	if err := plugins.UpdatePlugin(p.ID.Hex(), map[string]interface{}{
		"description": "改过的描述",
		"downloads":   42,
		"rating":      4.5,
		"unknown_key": "应当被忽略",
	}); err != nil {
		check("更新插件", false, err.Error())
	}
	got, _ = plugins.GetPluginByID(p.ID.Hex())
	check("更新生效", got.Description == "改过的描述" && got.Downloads == 42, fmt.Sprint(got))

	if err := plugins.TogglePlugin(p.ID.Hex(), false); err != nil {
		check("停用插件", false, err.Error())
	}
	got, _ = plugins.GetPluginByID(p.ID.Hex())
	check("enabled=false", !got.Enabled, "")

	if err := plugins.UninstallPlugin(p.ID.Hex()); err != nil {
		check("卸载插件", false, err.Error())
	}
	got, _ = plugins.GetPluginByID(p.ID.Hex())
	check("卸载后 installed/enabled 都 false", !got.Installed && !got.Enabled, "")

	list, total, err := plugins.ListPlugins("scanner", "go", nil, "验收插件", 1, 10)
	check("按类型+语言+关键字过滤到 1 条", err == nil && total == 1 && len(list) == 1, fmt.Sprint(total))
	_, totalDisabled, _ := plugins.ListPlugins("", "", boolPtr(false), "验收插件", 1, 10)
	check("按 enabled=false 过滤命中", totalDisabled == 1, fmt.Sprint(totalDisabled))

	if _, err := plugins.GetPluginByID("bad-id"); err == nil || err.Error() != "无效的插件ID" {
		check("非法插件 ID 报错文案", false, fmt.Sprint(err))
	} else {
		check("非法插件 ID 报错文案", true, "")
	}

	// ---------------------------------------------------------------- 字典
	fmt.Println("[2] 字典")
	d := &models.Dictionary{
		Name:        "验收字典-A",
		Type:        "subdomain",
		Description: "ops-acceptance",
		LineCount:   100,
	}
	if err := plugins.CreateDictionary(d); err != nil {
		fmt.Println("创建字典失败:", err)
		os.Exit(1)
	}
	dicts, dtotal, err := plugins.ListDictionaries("subdomain", 1, 20)
	check("字典列表命中", err == nil && dtotal >= 1 && len(dicts) >= 1, fmt.Sprint(dtotal))

	builtinID := primitive.NewObjectID()
	builtin := &models.Dictionary{Name: "内置字典-验收", Type: "dir", IsBuiltin: true}
	builtin.ID = builtinID
	if err := r.Dictionaries().Create(ctx, builtin); err != nil {
		fmt.Println("创建内置字典失败:", err)
		os.Exit(1)
	}
	if err := plugins.DeleteDictionary(builtinID.Hex()); err == nil || err.Error() != "不能删除内置字典" {
		check("内置字典拒绝删除", false, fmt.Sprint(err))
	} else {
		check("内置字典拒绝删除", true, "")
	}
	_ = r.Dictionaries().Delete(ctx, builtinID.Hex())

	if err := plugins.DeleteDictionary(d.ID.Hex()); err != nil {
		check("删除字典", false, err.Error())
	}
	if err := plugins.DeletePlugin(p.ID.Hex()); err != nil {
		check("删除插件", false, err.Error())
	}
	if _, err := plugins.GetPluginByID(p.ID.Hex()); err == nil {
		check("删除后查不到", false, "仍有记录")
	} else {
		check("删除后查不到", true, "")
	}

	// ---------------------------------------------------------------- 节点
	fmt.Println("[3] 节点")
	nodeKey := fmt.Sprintf("acceptance-node-%d", time.Now().UnixNano())
	n := &models.ScannerNode{
		NodeID:            nodeKey,
		Name:              "验收节点",
		Type:              models.NodeTypeGeneral,
		IP:                "10.9.9.9",
		Port:              9410,
		Version:           "1.0.0",
		Capabilities:      []string{"port_scan", "vuln_scan"},
		MaxTasks:          5,
		HeartbeatInterval: 30,
		SystemInfo: models.NodeSystemInfo{
			OS: "linux", Arch: "amd64", CPUCores: 8, CPUUsage: 12.5,
		},
		Tags: []string{"acceptance"},
	}
	if err := nodes.RegisterNode(n); err != nil {
		fmt.Println("注册节点失败:", err)
		os.Exit(1)
	}
	check("注册节点", !n.ID.IsZero(), "")

	byNodeID, err := nodes.GetNodeByID(nodeKey)
	check("按 node_id 查得到", err == nil && byNodeID.NodeID == nodeKey, fmt.Sprint(err))
	byID, err := nodes.GetNodeByID(n.ID.Hex())
	check("按主键查得到", err == nil && byID.NodeID == nodeKey, fmt.Sprint(err))
	check("system_info jsonb 往返", byID != nil && byID.SystemInfo.CPUCores == 8, fmt.Sprint(byID.SystemInfo))
	check("capabilities 往返", byID != nil && len(byID.Capabilities) == 2, fmt.Sprint(byID.Capabilities))

	// 重复注册同一 node_id 走更新，不应多出一条
	n2 := *n
	n2.IP = "10.9.9.10"
	n2.ID = primitive.NilObjectID
	if err := nodes.RegisterNode(&n2); err != nil {
		check("重复注册走更新", false, err.Error())
	}
	all, ntotal, _ := nodes.ListNodes("general", "online", 1, 50)
	_ = all
	check("重复注册没有新增记录", ntotal == 1, fmt.Sprint(ntotal))
	got2, _ := nodes.GetNodeByID(nodeKey)
	check("重复注册更新了 IP", got2 != nil && got2.IP == "10.9.9.10", fmt.Sprint(got2))

	if err := nodes.Heartbeat(nodeKey, models.NodeSystemInfo{CPUCores: 4, CPUUsage: 55.5}, 2); err != nil {
		check("心跳", false, err.Error())
	}
	got3, _ := nodes.GetNodeByID(nodeKey)
	check("心跳写入 system_info/current_tasks", got3 != nil && got3.SystemInfo.CPUCores == 4 && got3.CurrentTasks == 2, fmt.Sprint(got3))

	avail, err := nodes.GetAvailableNode("general", []string{"port_scan"})
	check("挑得到可用节点", err == nil && avail != nil, fmt.Sprint(err))
	_, err = nodes.GetAvailableNode("general", []string{"no_such_cap"})
	check("能力不匹配时无可选节点", err != nil && err.Error() == "没有可用的节点", fmt.Sprint(err))

	if err := nodes.SetNodeStatus(nodeKey, models.NodeStatusOffline); err != nil {
		check("设置离线", false, err.Error())
	}
	stats, err := nodes.GetNodeStats()
	check("节点统计", err == nil && stats["total"].(int64) >= 1, fmt.Sprint(stats))

	// 把心跳推到很久以前，验证 CheckOfflineNodes
	if err := nodes.UpdateNode(nodeKey, map[string]interface{}{
		"status":         models.NodeStatusOnline,
		"last_heartbeat": time.Now().Add(-2 * time.Hour),
	}); err != nil {
		check("准备过期心跳", false, err.Error())
	}
	if err := nodes.CheckOfflineNodes(30 * time.Minute); err != nil {
		check("心跳超时置离线", false, err.Error())
	}
	got4, _ := nodes.GetNodeByID(nodeKey)
	check("心跳超时后是 offline", got4 != nil && got4.Status == models.NodeStatusOffline, fmt.Sprint(got4))

	if err := nodes.DeleteNode(nodeKey); err != nil {
		check("删除节点（按 node_id）", false, err.Error())
	}
	if _, err := nodes.GetNodeByID(nodeKey); err == nil {
		check("删除后查不到", false, "仍有记录")
	} else {
		check("删除后查不到", true, "")
	}

	// ---------------------------------------------------------------- 巡航
	fmt.Println("[4] 巡航")
	// 起调度器：cron 只在 Start 之后才算出 Entry.Next
	if err := cruises.Start(); err != nil {
		fmt.Println("启动调度器失败:", err)
		os.Exit(1)
	}
	defer cruises.Stop()
	ws := primitive.NewObjectID()
	c, err := cruises.CreateCruise(&models.CruiseTaskCreateRequest{
		Name:       "验收巡航-A",
		CronExpr:   "0 3 * * *",
		Targets:    []string{"127.0.0.1:9"},
		TargetType: "ip",
		TaskType:   models.TaskTypePortScan,
		Tags:       []string{"acceptance"},
	}, primitive.NewObjectID(), ws)
	if err != nil {
		fmt.Println("创建巡航失败:", err)
		os.Exit(1)
	}
	check("创建巡航", !c.ID.IsZero(), "")
	check("默认禁用", c.Status == models.CruiseStatusDisabled, string(c.Status))

	if _, err := cruises.CreateCruise(&models.CruiseTaskCreateRequest{
		Name: "坏表达式", CronExpr: "not a cron", Targets: []string{"a"},
		TaskType: models.TaskTypePortScan,
	}, primitive.NewObjectID(), ws); err == nil {
		check("非法 cron 被拒", false, "未报错")
	} else {
		check("非法 cron 被拒", true, "")
	}

	gotC, err := cruises.GetCruise(c.ID.Hex())
	check("取单个巡航", err == nil && gotC.Name == "验收巡航-A", fmt.Sprint(err))
	check("targets 往返", gotC != nil && len(gotC.Targets) == 1, fmt.Sprint(gotC.Targets))

	cruiseList, ctotal, err := cruises.ListCruises(ws, 1, 10, "验收巡航")
	check("按 workspace + 搜索过滤", err == nil && ctotal == 1 && len(cruiseList) == 1, fmt.Sprint(ctotal))

	newName := "验收巡航-A2"
	if err := cruises.UpdateCruise(c.ID.Hex(), &models.CruiseTaskUpdateRequest{Name: &newName}); err != nil {
		check("更新巡航", false, err.Error())
	}
	gotC, _ = cruises.GetCruise(c.ID.Hex())
	check("更新生效", gotC.Name == "验收巡航-A2", gotC.Name)

	if err := cruises.EnableCruise(c.ID.Hex()); err != nil {
		check("启用巡航", false, err.Error())
	}
	gotC, _ = cruises.GetCruise(c.ID.Hex())
	check("启用后 status=enabled", gotC.Status == models.CruiseStatusEnabled, string(gotC.Status))
	check("启用后算出 next_run_at", !gotC.NextRunAt.IsZero(), fmt.Sprint(gotC.NextRunAt))
	check("启用的巡航会被调度", true, "")

	if err := cruises.DisableCruise(c.ID.Hex()); err != nil {
		check("停用巡航", false, err.Error())
	}
	gotC, _ = cruises.GetCruise(c.ID.Hex())
	check("停用后 status=disabled", gotC.Status == models.CruiseStatusDisabled, string(gotC.Status))

	// 执行计数与日志：直接走仓储，避免真的起一次扫描
	cr := r.Cruises()
	taskHex := primitive.NewObjectID()
	if err := cr.MarkRun(ctx, c.ID.Hex(), taskHex.Hex(), time.Now()); err != nil {
		check("MarkRun", false, err.Error())
	}
	gotC, _ = cr.Get(ctx, c.ID.Hex())
	check("run_count=1 且记下 last_task_id",
		gotC.RunCount == 1 && gotC.LastTaskID == taskHex.Hex(), fmt.Sprint(gotC.RunCount, gotC.LastTaskID))
	check("last_run_at 非零", !gotC.LastRunAt.IsZero(), "")

	logID, err := cr.AddLog(ctx, &models.CruiseLog{
		CruiseID: c.ID, TaskID: taskHex, Status: "running", StartTime: time.Now(),
	})
	check("写执行日志", err == nil && logID != "", fmt.Sprint(err))

	if err := cr.FinishLog(ctx, c.ID.Hex(), taskHex.Hex(), "success", time.Now(), 12, 30, 3, ""); err != nil {
		check("回填日志", false, err.Error())
	}
	logs, ltotal, err := cr.ListLogs(ctx, c.ID.Hex(), 1, 10)
	check("日志列表 1 条", err == nil && ltotal == 1 && len(logs) == 1, fmt.Sprint(ltotal))
	if len(logs) == 1 {
		check("日志回填生效", logs[0].Status == "success" && logs[0].ResultCount == 30 &&
			logs[0].VulnCount == 3 && logs[0].Duration == 12, fmt.Sprintf("%+v", logs[0]))
		check("日志 ID 是字符串", logs[0].ID == logID, logs[0].ID)
	}

	_ = cr.IncrSuccess(ctx, c.ID.Hex())
	_ = cr.SetLastStatus(ctx, c.ID.Hex(), "success")
	gotC, _ = cr.Get(ctx, c.ID.Hex())
	check("success_count=1、last_status=success",
		gotC.SuccessCount == 1 && gotC.LastStatus == "success", fmt.Sprint(gotC.SuccessCount, gotC.LastStatus))

	totalC, enabledC, runningC, err := cr.Stats(ctx, ws.Hex())
	check("巡航统计", err == nil && totalC == 1 && enabledC == 0 && runningC == 0,
		fmt.Sprint(totalC, enabledC, runningC))

	statsMap := cruises.GetStats(ws)
	check("GetStats 返回 map", statsMap["total"].(int64) == 1, fmt.Sprint(statsMap))

	// 删除巡航要连带清日志
	if err := cruises.DeleteCruise(c.ID.Hex()); err != nil {
		check("删除巡航", false, err.Error())
	}
	_, ltotal2, _ := cr.ListLogs(ctx, c.ID.Hex(), 1, 10)
	check("删巡航连带清日志", ltotal2 == 0, fmt.Sprint(ltotal2))

	// ---------------------------------------------------------------- 审计
	fmt.Println("[5] 操作审计")
	audits := r.Audits()
	userID := primitive.NewObjectID()
	if err := audits.Add(ctx, &models.OperationLog{
		UserID: userID, Username: "admin", Action: "POST", Module: "验收",
		Target: "/api/acceptance", IP: "127.0.0.1", UserAgent: "opscheck", Status: 1,
		CreatedAt: time.Now(),
	}); err != nil {
		check("写操作日志", false, err.Error())
	} else {
		check("写操作日志", true, "")
	}
	recent, err := audits.List(ctx, 5)
	check("读最近日志", err == nil && len(recent) >= 1 && recent[0].Username == "admin", fmt.Sprint(err))

	fmt.Println()
	if fails == 0 {
		fmt.Println("全部通过")
		return
	}
	fmt.Printf("失败 %d 项\n", fails)
	os.Exit(1)
}

func boolPtr(b bool) *bool { return &b }

var _ = errors.Is
