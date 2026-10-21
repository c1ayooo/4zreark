package service

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/models"

	"github.com/gorilla/websocket"
)

type agentCommand struct {
	Type          string `json:"type"`
	RequestID     string `json:"request_id,omitempty"`
	TaskID        string `json:"task_id,omitempty"`
	Status        string `json:"status,omitempty"`
	NodeID        string `json:"node_id,omitempty"`
	ServerVersion string `json:"server_version,omitempty"`
	BinaryURL     string `json:"binary_url,omitempty"`
}

type agentMessage struct {
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

// RemoteAgent 是 worker 侧的长连接客户端：主动连平台，收 scan 指令，回报心跳。
// 它只使用 node.token，不需要 PostgreSQL 连接。
type RemoteAgent struct {
	cfg      *config.NodeConfig
	client   *RemoteClient
	executor *TaskExecutor

	mu      sync.Mutex
	ws      *websocket.Conn
	cancels map[string]context.CancelFunc
}

func NewRemoteAgent(cfg *config.NodeConfig, client *RemoteClient, executor *TaskExecutor) *RemoteAgent {
	return &RemoteAgent{
		cfg:      cfg,
		client:   client,
		executor: executor,
		cancels:  make(map[string]context.CancelFunc),
	}
}

func (a *RemoteAgent) wsURL() string {
	base := strings.TrimRight(a.cfg.PlatformURL, "/")
	base = strings.Replace(base, "https://", "wss://", 1)
	base = strings.Replace(base, "http://", "ws://", 1)
	return base + "/api/node/ws"
}

// Run 阻塞运行，断线自动重连；密钥被吊销时直接退出，不再重试。
func (a *RemoteAgent) Run(ctx context.Context) {
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		err := a.connectAndServe(ctx)
		if errors.Is(err, ErrNodeRevoked) {
			log.Printf("[RemoteAgent] 节点密钥已吊销，停止连接平台")
			return
		}
		if ctx.Err() != nil {
			return
		}
		log.Printf("[RemoteAgent] 连接平台失败/断开: %v，%s 后重连", err, backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func (a *RemoteAgent) connectAndServe(ctx context.Context) error {
	header := http.Header{}
	header.Set("Authorization", "Bearer "+a.cfg.Token)
	ws, resp, err := a.client.WebSocketDialer().DialContext(ctx, a.wsURL(), header)
	if err != nil {
		if resp != nil && (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) {
			return ErrNodeRevoked
		}
		return err
	}
	defer ws.Close()

	a.mu.Lock()
	a.ws = ws
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		if a.ws == ws {
			a.ws = nil
		}
		a.mu.Unlock()
		// 不在这里 cancelAll：ws 只是心跳与指令通道，任务结果走 HTTP 上报。
		// 网络一抖就取消正在跑的长任务，会让限速后的慢扫描永远跑不完；
		// 进程退出时 parent ctx 会传播取消，不需要连接层兜底。
	}()

	log.Printf("[RemoteAgent] 已连接平台 %s（node=%s）", a.cfg.PlatformURL, a.cfg.Name)
	a.send(agentMessage{
		Type:         "hello",
		Name:         a.cfg.Name,
		Version:      SelfVersion(),
		MaxTasks:     a.cfg.MaxTasks,
		CurrentTasks: a.executor.Running(),
		Capabilities: a.cfg.Capabilities,
		Tags:         a.cfg.Tags,
		SystemInfo:   collectNodeSystemInfo(),
	})

	done := make(chan struct{})
	go a.heartbeatLoop(ctx, ws, done)
	defer close(done)

	for {
		_, data, err := ws.ReadMessage()
		if err != nil {
			return err
		}
		var msg agentCommand
		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}
		switch msg.Type {
		case "scan":
			if msg.NodeID != "" {
				a.executor.SetIdentity(msg.NodeID, a.cfg.Name)
			}
			a.startScan(ctx, ws, msg)
		case "hello_ack":
			if msg.NodeID != "" {
				a.executor.SetIdentity(msg.NodeID, a.cfg.Name)
				log.Printf("[RemoteAgent] 平台节点 ID=%s", msg.NodeID)
			}
		case "heartbeat_ack":
			if msg.Status == string(models.NodeStatusDisabled) {
				a.executor.SetPaused(true)
			} else {
				a.executor.SetPaused(false)
			}
			// 平台下发的版本号就是 worker 二进制的 sha256 前 12 位；
			// 与本地不一致就拉新版替换后 exec 重启，配置原文仍在内存里。
			if msg.ServerVersion != "" && msg.ServerVersion != SelfVersion() {
				go func(version, url string) {
					if err := TrySelfUpdate(a.cfg.PlatformURL, a.cfg.Token, url, version); err != nil {
						log.Printf("[RemoteAgent] 自更新失败: %v", err)
					}
				}(msg.ServerVersion, msg.BinaryURL)
			}
		}
	}
}

func (a *RemoteAgent) heartbeatLoop(ctx context.Context, ws *websocket.Conn, done <-chan struct{}) {
	interval := time.Duration(a.cfg.HeartbeatInterval) * time.Second
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case <-ticker.C:
			a.send(agentMessage{
				Type:         "heartbeat",
				CurrentTasks: a.executor.Running(),
				SystemInfo:   collectNodeSystemInfo(),
			})
		}
	}
}

func (a *RemoteAgent) startScan(parent context.Context, ws *websocket.Conn, msg agentCommand) {
	if msg.TaskID == "" {
		return
	}
	taskCtx, cancel := context.WithCancel(parent)
	a.mu.Lock()
	a.cancels[msg.RequestID] = cancel
	a.mu.Unlock()

	go func() {
		defer func() {
			cancel()
			a.mu.Lock()
			delete(a.cancels, msg.RequestID)
			a.mu.Unlock()
		}()

		err := a.executor.RunScanJob(taskCtx, msg.TaskID, 0)
		reply := agentMessage{Type: "scan_done", RequestID: msg.RequestID, OK: err == nil}
		if err != nil {
			reply.Error = err.Error()
		}
		a.sendTo(ws, reply)
	}()
}

func (a *RemoteAgent) cancelAll() {
	a.mu.Lock()
	for id, cancel := range a.cancels {
		cancel()
		delete(a.cancels, id)
	}
	a.mu.Unlock()
}

func (a *RemoteAgent) send(msg agentMessage) {
	a.mu.Lock()
	ws := a.ws
	a.mu.Unlock()
	if ws != nil {
		a.sendTo(ws, msg)
	}
}

func (a *RemoteAgent) sendTo(ws *websocket.Conn, msg agentMessage) {
	data, err := json.Marshal(msg)
	if err != nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.ws != ws {
		return
	}
	_ = ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_ = ws.WriteMessage(websocket.TextMessage, data)
}
