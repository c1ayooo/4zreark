package service

import (
	"log"
	"net"
	"runtime"
	"runtime/debug"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/models"
)

// NodeRuntime 让当前进程以「扫描节点」身份出现在节点管理页：
// 启动时注册、周期心跳上报负载，并把自己被管理员停用的状态同步给执行器。
//
// 节点之间不通过 HTTP 互相调度：所有节点连同一个 PostgreSQL，
// 扫描作业由 task_jobs 的 SKIP LOCKED 领取（与 4zrecon 共享 Redis 队列是同一思路）。
type NodeRuntime struct {
	cfg          *config.NodeConfig
	port         int
	nodeType     models.NodeType
	controlPlane bool
	nodes        *NodeService
	executor     *TaskExecutor

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewNodeRuntime 创建节点运行时。executor 为 nil 表示该进程不接扫描任务（role=master）。
func NewNodeRuntime(cfg *config.NodeConfig, port int, executor *TaskExecutor) *NodeRuntime {
	nodeType := models.NodeTypeMaster
	if cfg.Role == config.NodeRoleWorker {
		nodeType = models.NodeTypeWorker
	}
	return &NodeRuntime{
		cfg:          cfg,
		port:         port,
		nodeType:     nodeType,
		controlPlane: cfg.RunsControlPlane(),
		nodes:        NewNodeService(),
		executor:     executor,
		stopCh:       make(chan struct{}),
	}
}

// Start 注册节点并启动心跳循环。注册失败不阻塞启动，后续心跳会继续重试。
func (n *NodeRuntime) Start() {
	n.register()

	interval := time.Duration(n.cfg.HeartbeatInterval) * time.Second
	n.wg.Add(1)
	go n.loop(interval)
	log.Printf("[NodeRuntime] 节点 %s（id=%s, type=%s, role=%s）已启动，心跳 %s",
		n.cfg.Name, n.cfg.ID, n.nodeType, n.cfg.Role, interval)
}

// Stop 停止心跳循环，并尽量把节点标记为离线。
func (n *NodeRuntime) Stop() {
	close(n.stopCh)
	n.wg.Wait()

	// 优雅退出时立即让节点页看到离线；进程被 kill -9 时靠其他节点的超时回收兜底。
	if err := n.nodes.UpdateNode(n.cfg.ID, map[string]interface{}{
		"status":         models.NodeStatusOffline,
		"current_tasks":  0,
		"last_heartbeat": time.Now(),
	}); err != nil {
		log.Printf("[NodeRuntime] 节点下线标记失败（%s）: %v", n.cfg.ID, err)
	}
}

func (n *NodeRuntime) loop(interval time.Duration) {
	defer n.wg.Done()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	lastSweep := time.Now()
	for {
		select {
		case <-n.stopCh:
			return
		case <-ticker.C:
			n.beat()
			// 离线判定只需要控制面做一次；worker 重复扫同一张表没有意义。
			if n.controlPlane && time.Since(lastSweep) >= interval {
				n.sweepOffline(interval)
				lastSweep = time.Now()
			}
		}
	}
}

// register 把当前进程写入 scanner_nodes；同一 node_id 重复启动走更新。
func (n *NodeRuntime) register() {
	// 不跑扫描的 master 节点上报 max_tasks=0，避免在节点页看起来「可接任务」。
	maxTasks := n.cfg.MaxTasks
	if n.executor == nil {
		maxTasks = 0
	}
	node := &models.ScannerNode{
		NodeID:            n.cfg.ID,
		Name:              n.cfg.Name,
		Description:       "4zreark 扫描节点",
		Type:              n.nodeType,
		IP:                localIP(),
		Port:              n.port,
		Version:           buildVersion(),
		Capabilities:      n.cfg.Capabilities,
		MaxTasks:          maxTasks,
		CurrentTasks:      n.runningTasks(),
		SystemInfo:        collectNodeSystemInfo(),
		HeartbeatInterval: n.cfg.HeartbeatInterval,
		Tags:              n.cfg.Tags,
	}
	if err := n.nodes.RegisterNode(node); err != nil {
		log.Printf("[NodeRuntime] 节点注册失败（%s），心跳将继续重试: %v", n.cfg.ID, err)
		return
	}
	log.Printf("[NodeRuntime] 节点注册成功: %s", n.cfg.ID)
}

// beat 上报心跳。管理员把节点状态改成 disabled 时，执行器会停止领取新作业，
// 已在跑的任务继续完成；改回 online 后自动恢复。
func (n *NodeRuntime) beat() {
	existing, err := n.nodes.GetNodeByID(n.cfg.ID)
	if err != nil {
		// 记录被删除或数据库暂时不可用：重新注册即可（删除节点会阻止它再次出现，
		// 这里刻意选择「节点还活着就重新登记」，与扫描端行为一致）。
		n.register()
		return
	}

	disabled := existing.Status == models.NodeStatusDisabled
	effectiveMax := existing.MaxTasks
	if n.executor != nil {
		n.executor.SetPaused(disabled)
		// 并发上限以节点页写入的值为准，但不能超过节点启动时的 River MaxWorkers；
		// 回写实际值，避免页面显示一个做不到的并发数。
		effectiveMax = n.executor.SetMaxTasks(existing.MaxTasks)
	}

	running := n.runningTasks()
	status := models.NodeStatusOnline
	switch {
	case disabled:
		status = models.NodeStatusDisabled
	case effectiveMax > 0 && running >= effectiveMax:
		status = models.NodeStatusBusy
	}

	updates := map[string]interface{}{
		"status":         status,
		"current_tasks":  running,
		"system_info":    collectNodeSystemInfo(),
		"last_heartbeat": time.Now(),
	}
	if n.executor != nil {
		updates["max_tasks"] = effectiveMax
	}
	if err := n.nodes.UpdateNode(n.cfg.ID, updates); err != nil {
		log.Printf("[NodeRuntime] 心跳上报失败（%s）: %v", n.cfg.ID, err)
	}
}

// sweepOffline 把超过 3 个心跳周期没有上报的节点标为离线。
func (n *NodeRuntime) sweepOffline(interval time.Duration) {
	timeout := 3 * interval
	if timeout < 90*time.Second {
		timeout = 90 * time.Second
	}
	if err := n.nodes.CheckOfflineNodes(timeout); err != nil {
		log.Printf("[NodeRuntime] 离线节点回收失败: %v", err)
	}
}

func (n *NodeRuntime) runningTasks() int {
	if n.executor == nil {
		return 0
	}
	return n.executor.Running()
}

// collectNodeSystemInfo 采集节点负载。CPU 采样需要 500ms，心跳周期只有几十秒，代价可接受。
func collectNodeSystemInfo() models.NodeSystemInfo {
	info := models.NodeSystemInfo{
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		CPUCores: runtime.NumCPU(),
	}
	raw, err := NewSystemService().GetSystemInfo("")
	if err != nil {
		return info
	}
	info.CPUUsage = floatValue(raw["cpu_usage"])
	info.MemoryTotal = int64Value(raw["memory_total"])
	info.MemoryUsed = int64Value(raw["memory_used"])
	info.MemoryUsage = floatValue(raw["memory_usage"])
	info.DiskTotal = int64Value(raw["disk_total"])
	info.DiskUsed = int64Value(raw["disk_used"])
	info.DiskUsage = floatValue(raw["disk_usage"])
	return info
}

func floatValue(v interface{}) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case float32:
		return float64(x)
	case int:
		return float64(x)
	case int64:
		return float64(x)
	case uint64:
		return float64(x)
	default:
		return 0
	}
}

func int64Value(v interface{}) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case int:
		return int64(x)
	case uint64:
		return int64(x)
	case float64:
		return int64(x)
	default:
		return 0
	}
}

// localIP 取第一个非回环 IPv4。拿不到时留空，节点页仍能按名称识别节点。
func localIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok || ipNet.IP.IsLoopback() {
			continue
		}
		if ip4 := ipNet.IP.To4(); ip4 != nil {
			return ip4.String()
		}
	}
	return ""
}

// buildVersion 优先用链接期版本，其次用 git revision，最后退回 dev。
func buildVersion() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		if bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			return bi.Main.Version
		}
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" && len(s.Value) >= 7 {
				return s.Value[:7]
			}
		}
	}
	return "dev"
}
