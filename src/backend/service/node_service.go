package service

import (
	"context"
	"errors"
	"time"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/repo"

	"github.com/google/uuid"
)

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
	node.Status = models.NodeStatusOnline
	node.LastHeartbeat = time.Now()

	if existing, err := store.GetByNodeID(ctx, node.NodeID); err == nil {
		return s.UpdateNode(existing.ID.Hex(), map[string]interface{}{
			"status":         models.NodeStatusOnline,
			"ip":             node.IP,
			"port":           node.Port,
			"version":        node.Version,
			"capabilities":   node.Capabilities,
			"max_tasks":      node.MaxTasks,
			"system_info":    node.SystemInfo,
			"last_heartbeat": node.LastHeartbeat,
		})
	}

	node.CreatedAt = time.Now()
	node.UpdatedAt = time.Now()
	if err := store.Create(ctx, node); err != nil {
		return errors.New("注册节点失败")
	}
	return nil
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
	return map[string]interface{}{
		"by_status": byStatus,
		"total":     total,
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
