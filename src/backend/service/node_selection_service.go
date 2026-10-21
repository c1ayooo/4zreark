package service

import (
	"context"
	"errors"
	"strings"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/repo"
)

const (
	settingsKeyDefaultNode = "scanner.default_node_id"
)

// NodeSelectionService 管理默认扫描节点，并在任务创建时把它落到 task.node_id。
//
// 规则：
//   - 任务显式带 node_id → 原样使用（节点网关注入时会校验归属）；
//   - 没带 → 用默认节点；
//   - 默认节点不可用（不存在/已停用/已吊销）→ 保持空，由任意在线节点领取。
type NodeSelectionService struct{}

func NewNodeSelectionService() *NodeSelectionService { return &NodeSelectionService{} }

func (s *NodeSelectionService) settings() (repo.SettingsRepo, error) {
	r := repo.Default()
	if r == nil {
		return nil, errors.New("数据层未初始化")
	}
	return r.Settings(), nil
}

// DefaultNodeID 返回默认扫描节点的 node_id（客户端 UUID），未设置时为空。
func (s *NodeSelectionService) DefaultNodeID(ctx context.Context) string {
	repo, err := s.settings()
	if err != nil {
		return ""
	}
	var v struct {
		NodeID string `json:"node_id"`
	}
	ok, err := repo.Get(ctx, settingsKeyDefaultNode, &v)
	if err != nil || !ok {
		return ""
	}
	return strings.TrimSpace(v.NodeID)
}

// SetDefaultNode 设置默认节点；nodeID 为空表示清除。
func (s *NodeSelectionService) SetDefaultNode(ctx context.Context, nodeID string) (string, error) {
	nodeID = strings.TrimSpace(nodeID)
	repo, err := s.settings()
	if err != nil {
		return "", err
	}
	if nodeID == "" {
		return "", repo.Delete(ctx, settingsKeyDefaultNode)
	}
	nodes := NewNodeService()
	node, err := nodes.GetNodeByID(nodeID)
	if err != nil {
		return "", errors.New("节点不存在")
	}
	if err := CheckNodeUsable(node); err != nil {
		return "", err
	}
	if err := repo.Set(ctx, settingsKeyDefaultNode, map[string]string{"node_id": node.NodeID}); err != nil {
		return "", err
	}
	return node.NodeID, nil
}

// CheckNodeUsable 节点是否可被指定/作为默认：必须在线或繁忙，且未被吊销。
func CheckNodeUsable(node *models.ScannerNode) error {
	if node == nil {
		return errors.New("节点不存在")
	}
	if node.TokenHash != "" && node.RevokedAt != nil {
		return errors.New("节点凭证已被吊销，请先重新签发")
	}
	switch node.Status {
	case models.NodeStatusOnline, models.NodeStatusBusy:
		return nil
	case models.NodeStatusDisabled:
		return errors.New("节点已停用，请先在节点管理启用")
	default:
		return errors.New("节点离线，暂不可选为默认节点")
	}
}

// ResolveTaskNode 返回该任务应使用的 node_id（空 = 任意节点）。
// 默认节点不可用时返回空，让任务先入队，等任意节点上线再派发；
// 不能把离线节点写进 task.node_id，否则任务会一直卡在派发阶段。
func (s *NodeSelectionService) ResolveTaskNode(ctx context.Context, requested string) string {
	if v := strings.TrimSpace(requested); v != "" {
		return v
	}
	id := s.DefaultNodeID(ctx)
	if id == "" {
		return ""
	}
	node, err := NewNodeService().GetNodeByID(id)
	if err != nil || CheckNodeUsable(node) != nil {
		return ""
	}
	return node.NodeID
}
