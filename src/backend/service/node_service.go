package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/repo"

	"github.com/google/uuid"
)

// NodeTokenHash 把节点密钥原文转成库里的 SHA-256 十六进制。
func NodeTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func newNodeToken() (string, string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	token := base64.RawURLEncoding.EncodeToString(buf)
	return token, NodeTokenHash(token), nil
}

// NodeService 扫描节点服务。读写全部走 repo 层。
type NodeService struct{}

func NewNodeService() *NodeService {
	return &NodeService{}
}

func (s *NodeService) store() (repo.NodeRepo, error) {
	r := repo.Default()
	if r == nil {
		return nil, errors.New("数据库未就绪")
	}
	return r.Nodes(), nil
}

// RegisterNode 注册节点；同一 node_id 重复注册走更新。
func (s *NodeService) RegisterNode(node *models.ScannerNode) error {
	store, err := s.store()
	if err != nil {
		return err
	}
	ctx, cancel := dbCtx()
	defer cancel()

	if node.NodeID == "" {
		node.NodeID = uuid.New().String()
	}
	if node.MaxTasks < 0 {
		node.MaxTasks = 0
	}
	if node.MaxTasks > MaxNodeWorkers {
		node.MaxTasks = MaxNodeWorkers
	}
	node.Status = models.NodeStatusOnline
	node.LastHeartbeat = time.Now()

	if existing, err := store.GetByNodeID(ctx, node.NodeID); err == nil {
		updates := map[string]interface{}{
			"status":             models.NodeStatusOnline,
			"name":               node.Name,
			"description":        node.Description,
			"type":               node.Type,
			"ip":                 node.IP,
			"port":               node.Port,
			"version":            node.Version,
			"capabilities":       node.Capabilities,
			"max_tasks":          node.MaxTasks,
			"system_info":        node.SystemInfo,
			"last_heartbeat":     node.LastHeartbeat,
			"heartbeat_interval": node.HeartbeatInterval,
			"tags":               node.Tags,
		}
		if node.Name == "" {
			delete(updates, "name")
		}
		// status 需要保持在线：节点进程已经起来了，管理员之前的停用应由启动动作解除。
		return s.UpdateNode(existing.ID.Hex(), updates)
	}

	node.CreatedAt = time.Now()
	node.UpdatedAt = time.Now()
	if err := store.Create(ctx, node); err != nil {
		return errors.New("注册节点失败")
	}
	return nil
}

// CreateNodeWithToken 在平台侧预创建节点并签发一次性密钥。
// 节点侧只保存密钥原文，不再保存数据库账号。
func (s *NodeService) CreateNodeWithToken(node *models.ScannerNode) (string, error) {
	store, err := s.store()
	if err != nil {
		return "", err
	}
	ctx, cancel := dbCtx()
	defer cancel()

	token, hash, err := newNodeToken()
	if err != nil {
		return "", errors.New("生成节点密钥失败")
	}
	if node.NodeID == "" {
		node.NodeID = uuid.New().String()
	}
	if node.MaxTasks < 0 {
		node.MaxTasks = 0
	}
	if node.MaxTasks > MaxNodeWorkers {
		node.MaxTasks = MaxNodeWorkers
	}
	node.TokenHash = hash
	node.RevokedAt = nil
	node.Status = models.NodeStatusOffline
	node.CreatedAt = time.Now()
	node.UpdatedAt = node.CreatedAt
	if err := store.Create(ctx, node); err != nil {
		if errors.Is(err, repo.ErrDuplicate) {
			return "", errors.New("节点已存在")
		}
		return "", errors.New("创建节点失败")
	}
	return token, nil
}

// RotateNodeToken 重新签发节点密钥，旧密钥立即失效。
func (s *NodeService) RotateNodeToken(nodeID string) (string, error) {
	store, err := s.store()
	if err != nil {
		return "", err
	}
	ctx, cancel := dbCtx()
	defer cancel()

	hexID, err := s.resolveID(ctx, store, nodeID)
	if err != nil {
		return "", err
	}
	token, hash, err := newNodeToken()
	if err != nil {
		return "", errors.New("生成节点密钥失败")
	}
	if err := store.SetToken(ctx, hexID, hash); err != nil {
		return "", errors.New("更新节点密钥失败")
	}
	return token, nil
}

// RevokeNodeToken 吊销节点密钥；节点之后的 HTTP/WS 连接都会失败。
func (s *NodeService) RevokeNodeToken(nodeID string) error {
	store, err := s.store()
	if err != nil {
		return err
	}
	ctx, cancel := dbCtx()
	defer cancel()

	hexID, err := s.resolveID(ctx, store, nodeID)
	if err != nil {
		return err
	}
	if err := store.RevokeToken(ctx, hexID); err != nil {
		return errors.New("吊销节点密钥失败")
	}
	return nil
}

// GetNodeByToken 用密钥原文查未吊销节点（只在平台侧调用）。
func (s *NodeService) GetNodeByToken(token string) (*models.ScannerNode, error) {
	if token == "" {
		return nil, errors.New("缺少节点密钥")
	}
	store, err := s.store()
	if err != nil {
		return nil, err
	}
	ctx, cancel := dbCtx()
	defer cancel()

	node, err := store.GetByTokenHash(ctx, NodeTokenHash(token))
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			return nil, errors.New("节点密钥无效或已吊销")
		}
		return nil, errors.New("查询节点失败")
	}
	return node, nil
}

// GetNodeByID 按主键或 node_id 取节点
func (s *NodeService) GetNodeByID(nodeID string) (*models.ScannerNode, error) {
	store, err := s.store()
	if err != nil {
		return nil, err
	}
	ctx, cancel := dbCtx()
	defer cancel()

	if repo.ValidID(nodeID) {
		if node, err := store.GetByID(ctx, nodeID); err == nil {
			return node, nil
		}
	}
	node, err := store.GetByNodeID(ctx, nodeID)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			return nil, errors.New("节点不存在")
		}
		return nil, errors.New("查询节点失败")
	}
	return node, nil
}

// ListNodes 分页查询节点
func (s *NodeService) ListNodes(nodeType, status string, page, pageSize int) ([]*models.ScannerNode, int64, error) {
	store, err := s.store()
	if err != nil {
		return nil, 0, err
	}
	ctx, cancel := dbCtx()
	defer cancel()

	nodes, total, err := store.List(ctx, nodeType, status, page, pageSize)
	if err != nil {
		return nil, 0, errors.New("查询节点列表失败")
	}
	return nodes, total, nil
}

// resolveID 把「主键或 node_id」统一成主键 hex。
func (s *NodeService) resolveID(ctx context.Context, store repo.NodeRepo, idOrNodeID string) (string, error) {
	if repo.ValidID(idOrNodeID) {
		if _, err := store.GetByID(ctx, idOrNodeID); err == nil {
			return idOrNodeID, nil
		}
	}
	node, err := store.GetByNodeID(ctx, idOrNodeID)
	if err != nil {
		return "", errors.New("节点不存在")
	}
	return node.ID.Hex(), nil
}

// UpdateNode 更新节点
func (s *NodeService) UpdateNode(nodeID string, updates map[string]interface{}) error {
	// 并发上限是节点执行器的硬约束，落库前统一夹到 [0, MaxNodeWorkers]。
	if raw, ok := updates["max_tasks"]; ok {
		maxTasks := 0
		switch v := raw.(type) {
		case int:
			maxTasks = v
		case int64:
			maxTasks = int(v)
		case float64:
			maxTasks = int(v)
		}
		if maxTasks < 0 {
			maxTasks = 0
		}
		if maxTasks > MaxNodeWorkers {
			maxTasks = MaxNodeWorkers
		}
		updates["max_tasks"] = maxTasks
	}

	store, err := s.store()
	if err != nil {
		return err
	}
	ctx, cancel := dbCtx()
	defer cancel()

	hexID, err := s.resolveID(ctx, store, nodeID)
	if err != nil {
		return err
	}
	if err := store.UpdateFields(ctx, hexID, updates); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			return errors.New("节点不存在")
		}
		return errors.New("更新节点失败")
	}
	return nil
}

// DeleteNode 删除节点
func (s *NodeService) DeleteNode(nodeID string) error {
	store, err := s.store()
	if err != nil {
		return err
	}
	ctx, cancel := dbCtx()
	defer cancel()

	hexID, err := s.resolveID(ctx, store, nodeID)
	if err != nil {
		return err
	}
	if err := store.Delete(ctx, hexID); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			return errors.New("节点不存在")
		}
		return errors.New("删除节点失败")
	}
	return nil
}

// Heartbeat 心跳上报
func (s *NodeService) Heartbeat(nodeID string, systemInfo models.NodeSystemInfo, currentTasks int) error {
	return s.UpdateNode(nodeID, map[string]interface{}{
		"last_heartbeat": time.Now(),
		"system_info":    systemInfo,
		"current_tasks":  currentTasks,
		"status":         models.NodeStatusOnline,
	})
}

// SetNodeStatus 设置节点状态
func (s *NodeService) SetNodeStatus(nodeID string, status models.NodeStatus) error {
	return s.UpdateNode(nodeID, map[string]interface{}{"status": status})
}

// GetAvailableNode 取一个可用节点（在线、未满载、当前任务最少）
func (s *NodeService) GetAvailableNode(nodeType string, capabilities []string) (*models.ScannerNode, error) {
	store, err := s.store()
	if err != nil {
		return nil, err
	}
	ctx, cancel := dbCtx()
	defer cancel()

	node, err := store.Available(ctx, nodeType, capabilities)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			return nil, errors.New("没有可用的节点")
		}
		return nil, errors.New("查询可用节点失败")
	}
	return node, nil
}

// GetNodeStats 节点统计
func (s *NodeService) GetNodeStats() (map[string]interface{}, error) {
	store, err := s.store()
	if err != nil {
		return nil, err
	}
	ctx, cancel := dbCtx()
	defer cancel()

	byStatus, total, err := store.Stats(ctx)
	if err != nil {
		return nil, errors.New("统计失败")
	}
	cpu, memory, err := store.UsageAverages(ctx)
	if err != nil {
		cpu, memory = 0, 0
	}
	return map[string]interface{}{
		"total":          total,
		"online":         byStatus[string(models.NodeStatusOnline)],
		"offline":        byStatus[string(models.NodeStatusOffline)],
		"busy":           byStatus[string(models.NodeStatusBusy)],
		"disabled":       byStatus[string(models.NodeStatusDisabled)],
		"average_cpu":    cpu,
		"average_memory": memory,
		"by_status":      byStatus,
	}, nil
}

// CheckOfflineNodes 把长时间没心跳的在线节点标为离线
func (s *NodeService) CheckOfflineNodes(timeout time.Duration) error {
	store, err := s.store()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err = store.MarkOffline(ctx, time.Now().Add(-timeout))
	return err
}
