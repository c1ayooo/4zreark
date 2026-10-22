package api

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/service"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// NodeHub 维护 worker 主动连上来的 WebSocket 控制通道。
// 平台不再需要节点开放入站端口，也不需要保存节点密钥原文（库里只有 hash）。
type NodeHub struct {
	mu      sync.RWMutex
	conns   map[string]*nodeConn
	pending map[string]map[string]chan scanReply
	// taskConns 记录 task_id → 当前执行的节点连接，用于暂停/取消时发 cancel 指令。
	taskConns map[string]*nodeConn

	nodes *service.NodeService
	tasks *service.TaskService

	// binaryVersion 返回平台托管的 worker 二进制版本；为空表示不提供自更新。
	binaryVersion func() string
}

// SetBinaryVersionFn 注入 worker 二进制版本来源，供心跳回包下发给节点比对。
func (h *NodeHub) SetBinaryVersionFn(fn func() string) {
	h.mu.Lock()
	h.binaryVersion = fn
	h.mu.Unlock()
}

// workerBinaryVersion 读取当前托管的 worker 版本，未配置时返回空串。
func (h *NodeHub) workerBinaryVersion() string {
	h.mu.RLock()
	fn := h.binaryVersion
	h.mu.RUnlock()
	if fn == nil {
		return ""
	}
	return fn()
}

type nodeConn struct {
	nodeID       string
	ws           *websocket.Conn
	send         chan []byte
	done         chan struct{}
	closeOnce    sync.Once
	mu           sync.Mutex
	active       int
	max          int
	capabilities []string
}

type scanReply struct {
	ok  bool
	err string
}

type wsCommand struct {
	Type          string `json:"type"`
	RequestID     string `json:"request_id,omitempty"`
	TaskID        string `json:"task_id,omitempty"`
	Status        string `json:"status,omitempty"`
	NodeID        string `json:"node_id,omitempty"`
	ServerVersion string `json:"server_version,omitempty"`
	BinaryURL     string `json:"binary_url,omitempty"`
}

type wsNodeMessage struct {
	Type         string                `json:"type"`
	RequestID    string                `json:"request_id,omitempty"`
	OK           bool                  `json:"ok,omitempty"`
	Error        string                `json:"error,omitempty"`
	Name         string                `json:"name,omitempty"`
	Version      string                `json:"version,omitempty"`
	MaxTasks     int                   `json:"max_tasks,omitempty"`
	CurrentTasks int                   `json:"current_tasks,omitempty"`
	Capabilities []string              `json:"capabilities,omitempty"`
	Tags         []string              `json:"tags,omitempty"`
	SystemInfo   models.NodeSystemInfo `json:"system_info,omitempty"`
}

func NewNodeHub() *NodeHub {
	return &NodeHub{
		conns:     make(map[string]*nodeConn),
		pending:   make(map[string]map[string]chan scanReply),
		taskConns: make(map[string]*nodeConn),
		nodes:     service.NewNodeService(),
		tasks:     service.NewTaskService(),
	}
}

// CloseNode 在密钥吊销后立刻踢掉节点；读循环退出时也会做同样的清理。
func (h *NodeHub) CloseNode(nodeID string) {
	h.mu.RLock()
	c := h.conns[nodeID]
	h.mu.RUnlock()
	if c != nil {
		c.close()
	}
}

// CancelTask 通知正在执行该任务的 worker 取消扫描 context。
// 节点不在本进程或任务已经结束时返回 false，不影响控制面状态回收。
func (h *NodeHub) CancelTask(taskID string) bool {
	h.mu.RLock()
	c := h.taskConns[taskID]
	h.mu.RUnlock()
	if c == nil {
		return false
	}
	if err := c.sendJSON(wsCommand{Type: "cancel", TaskID: taskID}); err != nil {
		log.Printf("[NodeHub] 发送取消指令失败 task=%s node=%s: %v", taskID, c.nodeID, err)
		return false
	}
	log.Printf("[NodeHub] 已发送取消指令 task=%s node=%s", taskID, c.nodeID)
	return true
}

// Dispatch 选一个在线且有容量的节点，把任务 id 发过去并等待 scan_done。
func (h *NodeHub) Dispatch(ctx context.Context, taskID string) error {
	task, err := h.tasks.GetTaskByID(taskID)
	if err != nil {
		return err
	}
	capability := capabilityForTask(task.Type)

	// 任务带 node_id 时优先派给指定节点：用户在前端选过执行节点，就该按选择走，
	// 不能被「负载最低」抢走（曾出现指定自有节点、结果落到第三方节点的情况）。
	c, err := h.pick(capability, task.NodeID)
	if err != nil {
		return err
	}

	// 先落 node_id 再发指令：worker 抓取任务时会校验「任务是否分配给自己」。
	// 上一次执行节点崩溃后重试到新节点时，这里会覆盖旧 node_id。
	if err := h.tasks.UpdateTask(taskID, map[string]interface{}{"node_id": c.nodeID}); err != nil {
		return err
	}

	h.mu.Lock()
	reqID := uuid.NewString()
	if h.pending[c.nodeID] == nil {
		h.pending[c.nodeID] = make(map[string]chan scanReply)
	}
	replyCh := make(chan scanReply, 1)
	h.pending[c.nodeID][reqID] = replyCh
	h.taskConns[taskID] = c
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.pending[c.nodeID], reqID)
		if h.taskConns[taskID] == c {
			delete(h.taskConns, taskID)
		}
		h.mu.Unlock()
	}()

	if !c.reserve() {
		return service.ErrNoNodeAvailable
	}
	defer c.release()

	if err := c.sendJSON(wsCommand{Type: "scan", RequestID: reqID, TaskID: taskID, NodeID: c.nodeID}); err != nil {
		return err
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.done:
		return errors.New("节点连接已断开")
	case reply := <-replyCh:
		if !reply.ok {
			return errors.New(reply.err)
		}
		return nil
	}
}

func (h *NodeHub) pick(capability string, preferNodeID string) (*nodeConn, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	candidates := make([]*nodeConn, 0, len(h.conns))
	for _, c := range h.conns {
		if !c.available() {
			continue
		}
		if capability != "" && len(c.capabilities) > 0 && !contains(c.capabilities, capability) {
			continue
		}
		candidates = append(candidates, c)
	}
	// 指定节点优先：调用方给了 node_id，就只在这台节点上跑。
	// 它不在线/满载时直接返回「无可用节点」，任务留在队列里等，不再悄悄换到别的节点
	// —— 换到未授权节点会把流量打到第三方主机上。
	if preferNodeID != "" {
		for _, c := range candidates {
			if c.nodeID != preferNodeID {
				continue
			}
			if node, err := h.nodes.GetNodeByID(c.nodeID); err == nil &&
				node.Status != models.NodeStatusDisabled && node.Status != models.NodeStatusOffline &&
				node.TokenHash != "" && node.RevokedAt == nil {
				return c, nil
			}
		}
		return nil, service.ErrNoNodeAvailable
	}
	// 优先派给负载最低的节点；数据库里被停用/吊销的节点跳过，继续看下一台。
	// 不能因为排序第一的节点不可用就整体报「无节点」，否则本机节点一停用整套派单就瘫痪。
	sort.SliceStable(candidates, func(i, j int) bool {
		return candidates[i].load() < candidates[j].load()
	})
	for _, c := range candidates {
		node, err := h.nodes.GetNodeByID(c.nodeID)
		if err != nil || node.Status == models.NodeStatusDisabled || node.Status == models.NodeStatusOffline ||
			node.TokenHash == "" || node.RevokedAt != nil {
			continue
		}
		return c, nil
	}
	return nil, service.ErrNoNodeAvailable
}

// Serve 接管一条已通过 token 鉴权的节点连接。
func (h *NodeHub) Serve(c *gin.Context, node *models.ScannerNode, ws *websocket.Conn) {
	nc := &nodeConn{
		nodeID:       node.NodeID,
		ws:           ws,
		send:         make(chan []byte, 32),
		done:         make(chan struct{}),
		max:          node.MaxTasks,
		capabilities: node.Capabilities,
	}
	h.register(nc)
	defer h.unregister(nc)

	go nc.writePump()
	nc.readPump(h)

	if c.Request.Context().Err() != nil {
		return
	}
}

func (h *NodeHub) register(c *nodeConn) {
	h.mu.Lock()
	if old := h.conns[c.nodeID]; old != nil {
		old.close()
	}
	h.conns[c.nodeID] = c
	h.mu.Unlock()
	log.Printf("[NodeHub] 节点 %s 已连接", c.nodeID)
}

func (h *NodeHub) unregister(c *nodeConn) {
	h.mu.Lock()
	isCurrent := h.conns[c.nodeID] == c
	if isCurrent {
		delete(h.conns, c.nodeID)
	}
	pending := h.pending[c.nodeID]
	if isCurrent {
		delete(h.pending, c.nodeID)
	}
	h.mu.Unlock()

	if isCurrent {
		for _, ch := range pending {
			select {
			case ch <- scanReply{ok: false, err: "节点连接已断开"}:
			default:
			}
		}
	}
	c.close()

	// 只有当前连接仍是它时才标离线，避免重连被旧连接误标。
	if isCurrent {
		_ = h.nodes.UpdateNode(c.nodeID, map[string]interface{}{
			"status": models.NodeStatusOffline,
		})
	}
	log.Printf("[NodeHub] 节点 %s 已断开", c.nodeID)
}

func (c *nodeConn) readPump(h *NodeHub) {
	defer c.close()
	_ = c.ws.SetReadDeadline(time.Now().Add(90 * time.Second))
	c.ws.SetPongHandler(func(string) error {
		return c.ws.SetReadDeadline(time.Now().Add(90 * time.Second))
	})
	c.ws.SetReadLimit(1 << 20)

	for {
		_, data, err := c.ws.ReadMessage()
		if err != nil {
			return
		}
		var msg wsNodeMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}
		switch msg.Type {
		case "hello":
			updates := map[string]interface{}{
				"status":         models.NodeStatusOnline,
				"last_heartbeat": time.Now(),
				"current_tasks":  msg.CurrentTasks,
				"system_info":    msg.SystemInfo,
			}
			if msg.Name != "" {
				updates["name"] = msg.Name
			}
			if msg.Version != "" {
				updates["version"] = msg.Version
			}
			if msg.MaxTasks > 0 {
				updates["max_tasks"] = msg.MaxTasks
			}
			if msg.Capabilities != nil {
				updates["capabilities"] = msg.Capabilities
			}
			if msg.Tags != nil {
				updates["tags"] = msg.Tags
			}
			_ = h.nodes.UpdateNode(c.nodeID, updates)
			c.setCapacity(msg.MaxTasks, msg.Capabilities)
			helloAck := wsCommand{Type: "hello_ack", NodeID: c.nodeID, Status: string(models.NodeStatusOnline)}
			if v := h.workerBinaryVersion(); v != "" {
				helloAck.ServerVersion = v
				helloAck.BinaryURL = "/api/node/binary"
			}
			_ = c.sendJSON(helloAck)
			log.Printf("[NodeHub] 节点 %s hello: max_tasks=%d caps=%v", c.nodeID, msg.MaxTasks, msg.Capabilities)

		case "heartbeat":
			existing, err := h.nodes.GetNodeByID(c.nodeID)
			if err != nil || existing.TokenHash == "" || existing.RevokedAt != nil {
				// 密钥在连接期间被吊销：立刻断开，节点无法继续上报。
				log.Printf("[NodeHub] 节点 %s 密钥已失效，断开连接", c.nodeID)
				c.close()
				return
			}
			status := models.NodeStatusOnline
			if existing.Status == models.NodeStatusDisabled {
				status = models.NodeStatusDisabled
			}
			_ = h.nodes.UpdateNode(c.nodeID, map[string]interface{}{
				"status":         status,
				"current_tasks":  msg.CurrentTasks,
				"system_info":    msg.SystemInfo,
				"last_heartbeat": time.Now(),
			})
			ack := wsCommand{Type: "heartbeat_ack", Status: string(status)}
			if v := h.workerBinaryVersion(); v != "" {
				ack.ServerVersion = v
				ack.BinaryURL = "/api/node/binary"
			}
			_ = c.sendJSON(ack)

		case "scan_done":
			h.mu.RLock()
			ch := h.pending[c.nodeID][msg.RequestID]
			h.mu.RUnlock()
			if ch != nil {
				select {
				case ch <- scanReply{ok: msg.OK, err: msg.Error}:
				default:
				}
			}

		case "log":
			log.Printf("[node:%s] %s", c.nodeID, msg.Error)
		}
	}
}

func (c *nodeConn) writePump() {
	ticker := time.NewTicker(30 * time.Second)
	defer func() {
		ticker.Stop()
		c.close()
	}()
	for {
		select {
		case <-c.done:
			return
		case data := <-c.send:
			_ = c.ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.ws.WriteMessage(websocket.TextMessage, data); err != nil {
				return
			}
		case <-ticker.C:
			_ = c.ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.ws.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

func (c *nodeConn) sendJSON(v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	select {
	case c.send <- data:
		return nil
	case <-c.done:
		return errors.New("节点连接已断开")
	case <-time.After(10 * time.Second):
		return errors.New("节点发送队列已满")
	}
}

func (c *nodeConn) load() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.active
}

func (c *nodeConn) available() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.max > 0 && c.active < c.max
}

func (c *nodeConn) reserve() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.max <= 0 || c.active >= c.max {
		return false
	}
	c.active++
	return true
}

func (c *nodeConn) release() {
	c.mu.Lock()
	if c.active > 0 {
		c.active--
	}
	c.mu.Unlock()
}

func (c *nodeConn) setCapacity(max int, caps []string) {
	c.mu.Lock()
	c.max = max
	if caps != nil {
		c.capabilities = caps
	}
	c.mu.Unlock()
}

func (c *nodeConn) close() {
	c.closeOnce.Do(func() {
		close(c.done)
		_ = c.ws.Close()
	})
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func capabilityForTask(t models.TaskType) string {
	switch t {
	case models.TaskTypeSubdomain, models.TaskTypeTakeover:
		return "subdomain"
	case models.TaskTypePortScan, models.TaskTypeAssetDiscovery:
		return "port_scan"
	case models.TaskTypeFingerprint:
		return "fingerprint"
	case models.TaskTypeVulnScan:
		return "vuln_scan"
	case models.TaskTypeDirScan:
		return "dir_scan"
	case models.TaskTypeCrawler:
		return "crawler"
	default:
		return ""
	}
}
