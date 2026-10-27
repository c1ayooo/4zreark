package api

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

type NodeHandler struct {
	nodeService *service.NodeService
	selection   *service.NodeSelectionService
	hub         *NodeHub
}

func NewNodeHandler(hub *NodeHub) *NodeHandler {
	return &NodeHandler{
		nodeService: service.NewNodeService(),
		selection:   service.NewNodeSelectionService(),
		hub:         hub,
	}
}

// GetDefaultScanNode GET /api/nodes/default
func (h *NodeHandler) GetDefaultScanNode(c *gin.Context) {
	id := h.selection.DefaultNodeID(c.Request.Context())
	var node *models.ScannerNode
	if id != "" {
		if n, err := h.nodeService.GetNodeByID(id); err == nil {
			node = n
		}
	}
	utils.Success(c, gin.H{"node_id": id, "node": node})
}

// SetDefaultScanNode PUT /api/nodes/default  body: {"node_id":"..."}；空 = 清除
func (h *NodeHandler) SetDefaultScanNode(c *gin.Context) {
	var body struct {
		NodeID string `json:"node_id"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	id, err := h.selection.SetDefaultNode(c.Request.Context(), body.NodeID)
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "默认扫描节点已更新", gin.H{"node_id": id})
}

// EnrollNode 预创建节点并签发一次性密钥，节点侧只保存密钥原文。
// POST /api/nodes/enroll
func (h *NodeHandler) EnrollNode(c *gin.Context) {
	var req struct {
		Name         string                `json:"name" binding:"required"`
		Description  string                `json:"description"`
		MaxTasks     int                   `json:"max_tasks"`
		Capabilities []string              `json:"capabilities"`
		Tags         []string              `json:"tags"`
		SystemInfo   models.NodeSystemInfo `json:"system_info"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	node := &models.ScannerNode{
		Name:              req.Name,
		Description:       req.Description,
		Type:              models.NodeTypeWorker,
		Capabilities:      req.Capabilities,
		MaxTasks:          req.MaxTasks,
		SystemInfo:        req.SystemInfo,
		HeartbeatInterval: 30,
		Tags:              req.Tags,
	}
	if node.MaxTasks == 0 {
		node.MaxTasks = 5
	}
	token, err := h.nodeService.CreateNodeWithToken(node)
	if err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "节点已创建，请保存密钥（只显示一次）", gin.H{
		"node_id": node.NodeID,
		"id":      node.ID.Hex(),
		"token":   token,
	})
}

// RotateNodeToken 重新签发密钥，旧连接会被断开。
// POST /api/nodes/:id/token
func (h *NodeHandler) RotateNodeToken(c *gin.Context) {
	nodeID := c.Param("id")
	token, err := h.nodeService.RotateNodeToken(nodeID)
	if err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}
	if h.hub != nil {
		if node, err := h.nodeService.GetNodeByID(nodeID); err == nil {
			h.hub.CloseNode(node.NodeID)
		}
	}
	utils.SuccessWithMessage(c, "新密钥已生成，旧密钥立即失效", gin.H{"token": token})
}

// RevokeNodeToken 吊销密钥并踢掉在线连接。
// DELETE /api/nodes/:id/token
func (h *NodeHandler) RevokeNodeToken(c *gin.Context) {
	nodeID := c.Param("id")
	node, _ := h.nodeService.GetNodeByID(nodeID)
	if err := h.nodeService.RevokeNodeToken(nodeID); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}
	if node != nil {
		stopLocalRemTunnel(node.NodeID)
		if h.hub != nil {
			h.hub.CloseNode(node.NodeID)
		}
	}
	utils.SuccessWithMessage(c, "节点密钥已吊销，节点无法再连接平台", nil)
}

// ListNodes lists all scanner nodes
// GET /api/nodes
func (h *NodeHandler) ListNodes(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "10"))
	nodeType := c.Query("type")
	status := c.Query("status")

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 10
	}

	nodes, total, err := h.nodeService.ListNodes(nodeType, status, page, pageSize)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}

	utils.SuccessWithPagination(c, nodes, total, page, pageSize)
}

// GetNode gets a single node by ID
// GET /api/nodes/:id
func (h *NodeHandler) GetNode(c *gin.Context) {
	nodeID := c.Param("id")

	node, err := h.nodeService.GetNodeByID(nodeID)
	if err != nil {
		utils.NotFound(c, err.Error())
		return
	}

	utils.Success(c, node)
}

// RegisterNode registers a new scanner node
// POST /api/nodes/register
func (h *NodeHandler) RegisterNode(c *gin.Context) {
	var req struct {
		NodeID       string                `json:"node_id"`
		Name         string                `json:"name" binding:"required"`
		Description  string                `json:"description"`
		Type         models.NodeType       `json:"type" binding:"required"`
		IP           string                `json:"ip" binding:"required"`
		Port         int                   `json:"port" binding:"required"`
		Version      string                `json:"version"`
		Capabilities []string              `json:"capabilities"`
		MaxTasks     int                   `json:"max_tasks"`
		SystemInfo   models.NodeSystemInfo `json:"system_info"`
		Tags         []string              `json:"tags"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}

	// 审计 M4：节点 ID 强制白名单（字母/数字/下划线/连字符，≤64），
	// 拒绝路径分隔符与 ".."，隧道记录文件路径不再可被构造逃逸。
	if err := validateNodeID(req.NodeID); err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	node := &models.ScannerNode{
		NodeID:            req.NodeID,
		Name:              req.Name,
		Description:       req.Description,
		Type:              req.Type,
		IP:                req.IP,
		Port:              req.Port,
		Version:           req.Version,
		Capabilities:      req.Capabilities,
		MaxTasks:          req.MaxTasks,
		SystemInfo:        req.SystemInfo,
		Tags:              req.Tags,
		HeartbeatInterval: 30,
	}

	if node.MaxTasks == 0 {
		node.MaxTasks = 10
	}

	if err := h.nodeService.RegisterNode(node); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}

	utils.SuccessWithMessage(c, "注册成功", gin.H{
		"id":      node.ID.Hex(),
		"node_id": node.NodeID,
	})
}

// UpdateNode updates a node
// PUT /api/nodes/:id
func (h *NodeHandler) UpdateNode(c *gin.Context) {
	nodeID := c.Param("id")

	var req map[string]interface{}
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误")
		return
	}

	// Remove protected fields
	delete(req, "id")
	delete(req, "_id")
	delete(req, "node_id")
	delete(req, "created_at")

	if err := h.nodeService.UpdateNode(nodeID, req); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}

	utils.SuccessWithMessage(c, "更新成功", nil)
}

// DeleteNode deletes a node
// DELETE /api/nodes/:id
func (h *NodeHandler) DeleteNode(c *gin.Context) {
	nodeID := c.Param("id")

	node, _ := h.nodeService.GetNodeByID(nodeID)
	if err := h.nodeService.DeleteNode(nodeID); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}
	if node != nil {
		stopLocalRemTunnel(node.NodeID)
		if h.hub != nil {
			h.hub.CloseNode(node.NodeID)
		}
	}

	utils.SuccessWithMessage(c, "删除成功", nil)
}

// Heartbeat handles node heartbeat
// POST /api/nodes/:id/heartbeat
func (h *NodeHandler) Heartbeat(c *gin.Context) {
	nodeID := c.Param("id")

	var req struct {
		SystemInfo   models.NodeSystemInfo `json:"system_info"`
		CurrentTasks int                   `json:"current_tasks"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误")
		return
	}

	if err := h.nodeService.Heartbeat(nodeID, req.SystemInfo, req.CurrentTasks); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}

	utils.SuccessWithMessage(c, "心跳更新成功", nil)
}

// SetNodeStatus sets node status
// PUT /api/nodes/:id/status
func (h *NodeHandler) SetNodeStatus(c *gin.Context) {
	nodeID := c.Param("id")

	var req struct {
		Status models.NodeStatus `json:"status" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误")
		return
	}

	if err := h.nodeService.SetNodeStatus(nodeID, req.Status); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}

	utils.SuccessWithMessage(c, "状态更新成功", nil)
}

// GetNodeStats returns node statistics
// GET /api/nodes/stats
func (h *NodeHandler) GetNodeStats(c *gin.Context) {
	stats, err := h.nodeService.GetNodeStats()
	if err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}

	utils.Success(c, stats)
}

// validateNodeID 节点 ID 白名单（审计 M4）：非空且 ≤64 字符，
// 只允许字母/数字/下划线/连字符；空值由服务层生成 UUID。
func validateNodeID(id string) error {
	if id == "" {
		return nil
	}
	if len(id) > 64 {
		return errors.New("node_id 最长 64 字符")
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
		default:
			return fmt.Errorf("node_id 只允许字母/数字/下划线/连字符，收到 %q", id)
		}
	}
	return nil
}
