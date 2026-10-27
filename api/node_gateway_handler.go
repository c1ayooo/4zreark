package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

// NodeGatewayHandler 是 worker 专用 API：token 鉴权，不经过用户 JWT。
// worker 只拿得到任务数据、结果上报和 POC，不接触数据库连接串。
type NodeGatewayHandler struct {
	hub   *NodeHub
	nodes *service.NodeService
	tasks *service.TaskService
	pocs  *service.POCService
}

func NewNodeGatewayHandler(hub *NodeHub) *NodeGatewayHandler {
	return &NodeGatewayHandler{
		hub:   hub,
		nodes: service.NewNodeService(),
		tasks: service.NewTaskService(),
		pocs:  service.NewPOCService(),
	}
}

// NodeAuthMiddleware 校验 Bearer token；吊销/删除后的节点在这里直接 401。
func NodeAuthMiddleware(nodes *service.NodeService) gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		token := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
		if token == "" || token == header {
			utils.Unauthorized(c, "缺少节点密钥")
			c.Abort()
			return
		}
		node, err := nodes.GetNodeByToken(token)
		if err != nil {
			utils.Unauthorized(c, "节点密钥无效或已吊销")
			c.Abort()
			return
		}
		c.Set("node", node)
		c.Next()
	}
}

func nodeFromContext(c *gin.Context) *models.ScannerNode {
	v, _ := c.Get("node")
	node, _ := v.(*models.ScannerNode)
	return node
}

var nodeUpgrader = websocket.Upgrader{
	ReadBufferSize:  16 * 1024,
	WriteBufferSize: 16 * 1024,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

// WS 是节点主动连上来的控制通道；平台通过它下发 scan 指令。
func (h *NodeGatewayHandler) WS(c *gin.Context) {
	node := nodeFromContext(c)
	if node == nil {
		utils.Unauthorized(c, "缺少节点身份")
		return
	}
	conn, err := nodeUpgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return
	}
	h.hub.Serve(c, node, conn)
}

// GetTask 返回任务详情；节点只能读分配给自己的任务。
func (h *NodeGatewayHandler) GetTask(c *gin.Context) {
	node := nodeFromContext(c)
	task, err := h.tasks.GetTaskByID(c.Param("id"))
	if err != nil {
		utils.NotFound(c, err.Error())
		return
	}
	// 审计 M14：空归属任务对节点一律拒绝，控制面显式派单后节点才能访问；
	if task.NodeID == "" || task.NodeID != node.NodeID {
		utils.Forbidden(c, "任务未分配给该节点")
		return
	}
	utils.Success(c, task)
}

// UpdateTask 更新任务进度/状态。只允许执行过程中的字段，防止节点改目标/归属。
func (h *NodeGatewayHandler) UpdateTask(c *gin.Context) {
	node := nodeFromContext(c)
	taskID := c.Param("id")
	task, err := h.tasks.GetTaskByID(taskID)
	if err != nil {
		utils.NotFound(c, err.Error())
		return
	}
	// 审计 M14：空归属任务对节点一律拒绝，控制面显式派单后节点才能访问；
	if task.NodeID == "" || task.NodeID != node.NodeID {
		utils.Forbidden(c, "任务未分配给该节点")
		return
	}

	var raw map[string]interface{}
	if err := c.ShouldBindJSON(&raw); err != nil {
		utils.BadRequest(c, "参数错误")
		return
	}
	allowed := map[string]bool{
		"status": true, "progress": true, "progress_details": true,
		"started_at": true, "completed_at": true, "last_error": true,
		"discovered_assets": true, "discovered_ports": true, "discovered_vulns": true,
		"total_targets": true, "scanned_targets": true, "last_scanned_index": true,
		"completed_stages": true,
		// "node_id" 已移除（审计 M14）：节点不能改派/清空/认领任务归属，
		// 归属只能由控制面派单逻辑修改。
	}
	updates := make(map[string]interface{}, len(raw))
	for k, v := range raw {
		if !allowed[k] {
			continue
		}
		switch k {
		case "started_at", "completed_at":
			if t, err := parseNodeTime(v); err == nil {
				updates[k] = t
			}
		case "progress", "discovered_assets", "discovered_ports", "discovered_vulns",
			"total_targets", "scanned_targets", "last_scanned_index":
			updates[k] = intFromJSON(v)
		default:
			updates[k] = v
		}
	}
	if err := h.tasks.UpdateTask(taskID, updates); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "更新成功", nil)
}

// TouchTask 节点活性心跳：只推进任务的 updated_at，防止安静的大扫描被
// StaleReaper 误判为无进展而回收。
// PUT /api/node/tasks/:id/touch
func (h *NodeGatewayHandler) TouchTask(c *gin.Context) {
	node := nodeFromContext(c)
	taskID := c.Param("id")
	task, err := h.tasks.GetTaskByID(taskID)
	if err != nil {
		utils.NotFound(c, err.Error())
		return
	}
	// 审计 M14：空归属任务对节点一律拒绝，控制面显式派单后节点才能访问；
	if task.NodeID == "" || task.NodeID != node.NodeID {
		utils.Forbidden(c, "任务未分配给该节点")
		return
	}
	if err := h.tasks.TouchTask(taskID); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}
	utils.Success(c, nil)
}

// PostResults 接收一批扫描结果，由平台去重后写 scan_results。
func (h *NodeGatewayHandler) PostResults(c *gin.Context) {
	node := nodeFromContext(c)
	taskID := c.Param("id")
	task, err := h.tasks.GetTaskByID(taskID)
	if err != nil {
		utils.NotFound(c, err.Error())
		return
	}
	// 审计 M14：空归属任务对节点一律拒绝，控制面显式派单后节点才能访问；
	if task.NodeID == "" || task.NodeID != node.NodeID {
		utils.Forbidden(c, "任务未分配给该节点")
		return
	}

	var body struct {
		Results []*models.ScanResult `json:"results"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}

	rs := service.NewResultService()
	results := make([]*models.ScanResult, 0, len(body.Results))
	for _, r := range body.Results {
		if r == nil {
			continue
		}
		r.TaskID = task.ID
		r.WorkspaceID = task.WorkspaceID
		if r.CreatedAt.IsZero() {
			r.CreatedAt = time.Now().UTC()
		}
		results = append(results, r)
	}
	inserted, updated, err := rs.BatchCreateResultPtrsWithDedup(results)
	if err != nil {
		utils.Error(c, utils.ErrCodeInternalError, "结果写入失败: "+err.Error())
		return
	}
	utils.Success(c, gin.H{"saved": inserted + updated, "inserted": inserted, "updated": updated})
}

// PostAssets 接收节点侧归并好的资产和路由，由平台写 sites/raw_records/site_routes。
func (h *NodeGatewayHandler) PostAssets(c *gin.Context) {
	node := nodeFromContext(c)
	taskID := c.Param("id")
	task, err := h.tasks.GetTaskByID(taskID)
	if err != nil {
		utils.NotFound(c, err.Error())
		return
	}
	// 审计 M14：空归属任务对节点一律拒绝，控制面显式派单后节点才能访问；
	if task.NodeID == "" || task.NodeID != node.NodeID {
		utils.Forbidden(c, "任务未分配给该节点")
		return
	}

	var body struct {
		Records []repo.RawRecord          `json:"records"`
		Routes  []service.CrawledEndpoint `json:"routes"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	assetSvc := service.NewAssetService()
	if task.ProjectID > 0 && len(body.Records) > 0 {
		const chunk = 5000
		for start := 0; start < len(body.Records); start += chunk {
			end := start + chunk
			if end > len(body.Records) {
				end = len(body.Records)
			}
			if _, err := assetSvc.Ingest(ctx, task.ProjectID, "scan", body.Records[start:end]); err != nil {
				utils.Error(c, utils.ErrCodeInternalError, "资产写入失败: "+err.Error())
				return
			}
		}
	}
	if len(body.Routes) > 0 {
		if _, _, err := assetSvc.SaveCrawledRoutes("pipeline", body.Routes); err != nil {
			utils.Error(c, utils.ErrCodeInternalError, "路由写入失败: "+err.Error())
			return
		}
	}
	utils.Success(c, gin.H{"records": len(body.Records), "routes": len(body.Routes)})
}

// PostCDN 接收节点侧发现的子域名 CDN 信息。
func (h *NodeGatewayHandler) PostCDN(c *gin.Context) {
	node := nodeFromContext(c)
	taskID := c.Param("id")
	task, err := h.tasks.GetTaskByID(taskID)
	if err != nil {
		utils.NotFound(c, err.Error())
		return
	}
	// 审计 M14：空归属任务对节点一律拒绝，控制面显式派单后节点才能访问；
	if task.NodeID == "" || task.NodeID != node.NodeID {
		utils.Forbidden(c, "任务未分配给该节点")
		return
	}

	var body struct {
		Domain string `json:"domain"`
		CDN    string `json:"cdn"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Domain == "" {
		utils.BadRequest(c, "参数错误")
		return
	}
	if err := service.NewResultService().UpdateSubdomainCDN(taskID, body.Domain, body.CDN); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "更新成功", nil)
}

// PostDictLearning 接收节点侧的字典学习观测（子域首标签/归一路径），平台侧计频晋升。
func (h *NodeGatewayHandler) PostDictLearning(c *gin.Context) {
	node := nodeFromContext(c)
	taskID := c.Param("id")
	task, err := h.tasks.GetTaskByID(taskID)
	if err != nil {
		utils.NotFound(c, err.Error())
		return
	}
	// 审计 M14：空归属任务对节点一律拒绝，控制面显式派单后节点才能访问；
	if task.NodeID == "" || task.NodeID != node.NodeID {
		utils.Forbidden(c, "任务未分配给该节点")
		return
	}

	var body struct {
		SubLabels []string `json:"sub_labels"`
		Paths     []string `json:"paths"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	service.RecordDictObservations(ctx, task.ProjectID, body.SubLabels, body.Paths)
	utils.Success(c, gin.H{"sub_labels": len(body.SubLabels), "paths": len(body.Paths)})
}

// ListPOCs 把启用中的 nuclei POC 下发给节点；节点本地缓存后执行漏洞扫描。
func (h *NodeGatewayHandler) ListPOCs(c *gin.Context) {
	enabled := true
	const pageSize = 500
	out := make([]models.POC, 0, 1024)
	for page := int64(1); ; page++ {
		res, err := h.pocs.List(service.POCListParams{
			Page: page, PageSize: pageSize, Type: "nuclei", Enabled: &enabled,
		})
		if err != nil {
			utils.Error(c, utils.ErrCodeInternalError, err.Error())
			return
		}
		out = append(out, res.POCs...)
		if len(res.POCs) < pageSize || int64(len(out)) >= res.Total {
			break
		}
	}
	utils.Success(c, out)
}

func parseNodeTime(v interface{}) (time.Time, error) {
	switch x := v.(type) {
	case time.Time:
		return x, nil
	case string:
		return time.Parse(time.RFC3339Nano, x)
	case float64:
		return time.Unix(int64(x), 0), nil
	default:
		return time.Time{}, errors.New("unsupported time")
	}
}

func intFromJSON(v interface{}) int {
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		return int(x)
	case json.Number:
		n, _ := x.Int64()
		return int(n)
	default:
		return 0
	}
}
