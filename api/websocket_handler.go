package api

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/middleware"
	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

// WebSocketHandler handles WebSocket connections for real-time data
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		// Origin 校验与 CORS 白名单保持一致（精确匹配，含 ZRE_CORS_ORIGINS）；
		// 非浏览器客户端没有 Origin，放行（仍要过下面的 token 校验）。
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true
		}
		if middleware.OriginAllowed(origin) {
			return true
		}
		// 同源访问放行：页面由本服务（或其反代）直接托管时，浏览器 WS 必带
		// Origin 头且等于页面源，而它不在 5173/3000 白名单里；反代场景优先
		// 比对 X-Forwarded-Host，直连时 Host 即原始地址。
		u, err := url.Parse(origin)
		if err != nil {
			return false
		}
		host := r.Header.Get("X-Forwarded-Host")
		if host == "" {
			host = r.Host
		}
		return u.Host == host
	},
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

// Client represents a WebSocket client
type Client struct {
	conn        *websocket.Conn
	send        chan []byte
	hub         *Hub
	clientID    string
	userID      string
	workspaceID string

	// closed 标记 send 是否已关闭，由 Hub.mu 独占保护。
	// 广播路径与 unregister 路径都会剔除客户端，用该标记保证 close 只发生一次。
	closed bool
}

// Hub maintains the active clients and broadcasts messages
type Hub struct {
	clients    map[*Client]bool
	broadcast  chan []byte
	register   chan *Client
	unregister chan *Client
	mu         sync.RWMutex

	// stopCh 关闭后 Run/StartMonitorTask/各连接 goroutine 依次退出，
	// 避免进程关停时仍向无人消费的 channel 发送。
	stopCh   chan struct{}
	stopOnce sync.Once
	// done 在 Run 退出后关闭，供关停流程与测试等待事件循环收口。
	done chan struct{}
}

// NewHub creates a new Hub
func NewHub() *Hub {
	return &Hub{
		clients:    make(map[*Client]bool),
		broadcast:  make(chan []byte),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		stopCh:     make(chan struct{}),
		done:       make(chan struct{}),
	}
}

// Stop 通知 Hub 与其上所有连接退出；可重复调用。
func (h *Hub) Stop() {
	h.stopOnce.Do(func() { close(h.stopCh) })
}

// Run starts the Hub
func (h *Hub) Run() {
	if h.done != nil {
		defer close(h.done)
	}
	for {
		select {
		case <-h.stopCh:
			h.closeAll()
			return

		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()

		case client := <-h.unregister:
			h.mu.Lock()
			h.dropClientLocked(client)
			h.mu.Unlock()

		case message := <-h.broadcast:
			// 广播本身持写锁：剔除客户端与关闭 send 都是写操作，
			// 在读锁下执行会触发 concurrent map writes / close of closed channel。
			// 发送用 select+default 不阻塞，锁持有时间只与客户端数量相关。
			h.mu.Lock()
			for client := range h.clients {
				select {
				case client.send <- message:
				default:
					h.dropClientLocked(client)
				}
			}
			h.mu.Unlock()
		}
	}
}

// dropClientLocked 把客户端移出广播表并关闭 send（幂等）。调用方必须持写锁。
func (h *Hub) dropClientLocked(client *Client) {
	if client.closed {
		return
	}
	client.closed = true
	if _, ok := h.clients[client]; ok {
		delete(h.clients, client)
	}
	close(client.send)
}

// closeAll 关停时断开所有客户端，让 writePump 自然退出。
func (h *Hub) closeAll() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for client := range h.clients {
		h.dropClientLocked(client)
	}
}

// enqueue 向客户端非阻塞投递一条消息。客户端已关闭或缓冲区满时返回 false，
// 保证不会向已关闭的 channel 发送（慢客户端由广播路径负责剔除）。
func (h *Hub) enqueue(client *Client, payload []byte) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if client.closed {
		return false
	}
	select {
	case client.send <- payload:
		return true
	default:
		return false
	}
}

// StartMonitorTask starts broadcasting monitoring data
func (h *Hub) StartMonitorTask() {
	ticker := time.NewTicker(5 * time.Second) // Update every 5 seconds
	defer ticker.Stop()

	sysService := service.NewSystemService()
	nodeService := service.NewNodeService()

	for {
		select {
		case <-h.stopCh:
			return
		case <-ticker.C:
			monitorData := h.getMonitorData(sysService, nodeService)
			data, err := json.Marshal(monitorData)
			if err != nil {
				log.Printf("WebSocket monitor marshal error: %v", err)
				continue
			}
			// Hub.Run 退出后 broadcast 无人消费，这里必须能被 stopCh 打断。
			select {
			case h.broadcast <- data:
			case <-h.stopCh:
				return
			}
		}
	}
}

// getMonitorData collects real-time monitoring data
func (h *Hub) getMonitorData(sysService *service.SystemService, nodeService *service.NodeService) map[string]interface{} {
	sysInfo, _ := sysService.GetSystemInfo("")
	nodeStats, _ := nodeService.GetNodeStats()

	return map[string]interface{}{
		"type":      "monitor_data",
		"timestamp": time.Now().Unix(),
		"system": map[string]interface{}{
			"cpu_usage":    sysInfo["cpu_usage"],
			"memory_usage": sysInfo["memory_usage"],
			"memory_total": sysInfo["memory_total"],
			"memory_used":  sysInfo["memory_used"],
			"disk_usage":   sysInfo["disk_usage"],
			"disk_total":   sysInfo["disk_total"],
			"disk_used":    sysInfo["disk_used"],
		},
		"nodes": map[string]interface{}{
			"total":   nodeStats["total"],
			"online":  nodeStats["online"],
			"offline": nodeStats["offline"],
		},
		"analytics": map[string]interface{}{
			"monthly_users":        0,
			"monthly_spend":        0,
			"monthly_revenue":      0,
			"monthly_transactions": 0,
		},
	}
}

// WebSocketHandler handles WebSocket connections
func (h *Hub) WebSocketHandler(c *gin.Context) {
	// 升级前鉴权：该通道每 5 秒广播系统资源与节点统计，不允许匿名接入。
	// token 走 ?token= 查询参数（浏览器 WebSocket 不能自定义请求头）；
	// 吊销检查与 HTTP 中间件同一套。
	token := c.Query("token")
	if token == "" {
		if auth := c.GetHeader("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			token = strings.TrimPrefix(auth, "Bearer ")
		}
	}
	claims, err := utils.ParseToken(token)
	if err != nil {
		utils.Error(c, utils.ErrCodeTokenInvalid, "WebSocket 连接需要有效 token（?token=）")
		return
	}
	// 失败关闭（审计 M2）：吊销检查出错时拒绝建立 WebSocket，不让被吊销令牌连入。
	revoked, rerr := service.NewUserService().IsTokenRevoked(token, claims.UserID, claims.Ver)
	if rerr != nil {
		utils.Error(c, 503, "认证服务暂不可用，请稍后重试")
		return
	}
	if revoked {
		utils.Error(c, utils.ErrCodeTokenInvalid, "Token已失效")
		return
	}

	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		utils.Error(c, utils.ErrCodeInvalidParams, "WebSocket upgrade failed")
		return
	}

	client := &Client{
		conn:        conn,
		send:        make(chan []byte, 256),
		hub:         h,
		clientID:    "", // Generate unique client ID
		userID:      claims.UserID,
		workspaceID: c.Query("workspace_id"),
	}

	// Hub 已停止时直接断开，避免向无人消费的 register 发送造成 goroutine 泄漏。
	select {
	case client.hub.register <- client:
	case <-h.stopCh:
		_ = conn.Close()
		return
	}

	go client.writePump()
	client.readPump()
}

func (c *Client) readPump() {
	defer func() {
		select {
		case c.hub.unregister <- c:
		case <-c.hub.stopCh:
		}
		c.conn.Close()
	}()

	c.conn.SetReadLimit(65536) // 64KB
	c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket unexpected close: %v", err)
			}
			break
		}

		// Handle client messages (pings, commands, etc.)
		var msg map[string]string
		if err := json.Unmarshal(message, &msg); err == nil {
			if msg["type"] == "ping" {
				// 连接可能已被广播路径剔除，直接写 channel 会 panic。
				c.hub.enqueue(c, []byte(`{"type":"pong"}`))
			}
		}

		c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	}
}

func (c *Client) writePump() {
	ticker := time.NewTicker(54 * time.Second)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			if err := c.conn.WriteMessage(websocket.TextMessage, message); err != nil {
				log.Printf("WebSocket write error: %v", err)
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				log.Printf("WebSocket ping error: %v", err)
				return
			}
		}
	}
}
