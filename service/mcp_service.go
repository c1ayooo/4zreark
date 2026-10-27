package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/repo"
)

// MCPService 实现一个无状态的 MCP 服务（Streamable HTTP 传输）。
//
// 协议层覆盖 initialize / ping / tools/list / tools/call，
// 业务层按 API key 的 scopes 分发到资产、项目、治理、任务、扫描、漏洞等工具。
// 所有写操作与扫描在工具描述里标注，并在执行前校验 scope 与项目边界。
const (
	MCPServerName    = "4zreark"
	MCPServerVersion = "1.1.0"
)

var mcpProtocolVersions = []string{"2025-06-18", "2025-03-26", "2024-11-05"}

// RPCRequest 是 JSON-RPC 2.0 请求；ID 为 nil 表示通知。
type RPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// RPCResponse 是 JSON-RPC 2.0 响应。ID 原样回传（字符串或数字）。
type RPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

type mcpTool struct {
	Name        string         `json:"name"`
	Title       string         `json:"title,omitempty"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
	Annotations map[string]any `json:"annotations,omitempty"`
}

type mcpToolCall struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

type mcpContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type mcpToolResult struct {
	Content           []mcpContent `json:"content"`
	StructuredContent any          `json:"structuredContent,omitempty"`
	IsError           bool         `json:"isError,omitempty"`
}

// mcpToolHandler 把工具定义、所需权限和实现绑在一起。
// Scopes 是「全部满足」语义；写/扫描类工具通常同时要求域写权限与 scans:run。
type mcpToolHandler struct {
	Tool      mcpTool
	Scopes    []string // 全部满足
	AnyScopes []string // 至少满足一个；和 Scopes 同时存在时两者都要满足
	Run       func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult
}

// MCPService 的组合根：服务层对象在构造时创建，工具实现只调用服务层。
type MCPService struct {
	assets     *AssetService
	governance *GovernanceService
	tasks      *TaskService
	results    *ResultService
	scans      *ScanService
	vulns      *VulnService
	pocs       *POCService
	enterprise *EnterpriseService
}

func NewMCPService() *MCPService {
	return &MCPService{
		assets:     NewAssetService(),
		governance: NewGovernanceService(),
		tasks:      NewTaskService(),
		results:    NewResultService(),
		scans:      NewScanService(),
		vulns:      NewVulnService(),
		pocs:       NewPOCService(),
		enterprise: NewEnterpriseService(),
	}
}

// toolRegistry 是工具清单的唯一来源；tools/list 与 tools/call 共用。
func (s *MCPService) toolRegistry() []mcpToolHandler {
	out := make([]mcpToolHandler, 0, 64)
	out = append(out, s.assetTools()...)
	out = append(out, s.projectTools()...)
	out = append(out, s.governanceTools()...)
	out = append(out, s.taskTools()...)
	out = append(out, s.scanTools()...)
	out = append(out, s.vulnTools()...)
	out = append(out, s.pocTools()...)
	out = append(out, s.enterpriseTools()...)
	return out
}

func (s *MCPService) toolList() []mcpTool {
	reg := s.toolRegistry()
	out := make([]mcpTool, 0, len(reg))
	for _, h := range reg {
		out = append(out, h.Tool)
	}
	return out
}

// Handle 处理一条 JSON-RPC 请求。通知返回 (nil, nil)，由 handler 回 202。
func (s *MCPService) Handle(ctx context.Context, req *RPCRequest, key *repo.APIKey) (*RPCResponse, error) {
	if req == nil || req.Method == "" {
		return rpcError(req, -32600, "无效的 JSON-RPC 请求"), nil
	}
	if req.JSONRPC != "" && req.JSONRPC != "2.0" {
		return rpcError(req, -32600, "仅支持 JSON-RPC 2.0"), nil
	}
	if len(req.ID) == 0 {
		return nil, nil
	}

	resp := &RPCResponse{JSONRPC: "2.0", ID: req.ID}
	switch req.Method {
	case "initialize":
		resp.Result = s.initialize(req.Params)
	case "ping":
		resp.Result = map[string]any{}
	case "tools/list":
		resp.Result = map[string]any{"tools": s.toolList()}
	case "tools/call":
		resp.Result = s.callTool(ctx, key, req.Params)
	default:
		return rpcError(req, -32601, "未知方法: "+req.Method), nil
	}
	return resp, nil
}

func rpcError(req *RPCRequest, code int, msg string) *RPCResponse {
	r := &RPCResponse{JSONRPC: "2.0", Error: &RPCError{Code: code, Message: msg}}
	if req != nil {
		r.ID = req.ID
	}
	if len(r.ID) == 0 {
		r.ID = json.RawMessage("null")
	}
	return r
}

func (s *MCPService) initialize(params json.RawMessage) map[string]any {
	var in struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	_ = json.Unmarshal(params, &in)

	version := mcpProtocolVersions[0]
	for _, v := range mcpProtocolVersions {
		if v == in.ProtocolVersion {
			version = v
			break
		}
	}
	return map[string]any{
		"protocolVersion": version,
		"capabilities": map[string]any{
			"tools": map[string]any{"listChanged": false},
		},
		"serverInfo": map[string]any{
			"name":    MCPServerName,
			"title":   "4zreark 资产治理与扫描",
			"version": MCPServerVersion,
		},
		"instructions": "按 API key 的权限操作 4zreark：资产/项目/治理/任务/扫描/漏洞/POC。" +
			"每个 key 可绑定单个项目，绑定后所有项目内资源只在该项目范围内读写；" +
			"写操作与扫描工具会在描述中标注，执行前请确认目标与影响。" +
			"先用 list_projects 确认可访问项目，再按需调用 read/write 工具。",
	}
}

func (s *MCPService) callTool(ctx context.Context, key *repo.APIKey, params json.RawMessage) any {
	var call mcpToolCall
	if err := json.Unmarshal(params, &call); err != nil {
		return toolError("解析工具参数失败: " + err.Error())
	}
	if call.Name == "" {
		return toolError("缺少工具名")
	}
	if key == nil {
		return toolError("缺少 API key 上下文")
	}

	for _, h := range s.toolRegistry() {
		if h.Tool.Name != call.Name {
			continue
		}
		for _, scope := range h.Scopes {
			if !hasScope(key, scope) {
				return toolError("该 API key 缺少 " + scope + " 权限")
			}
		}
		if len(h.AnyScopes) > 0 {
			allowed := false
			for _, scope := range h.AnyScopes {
				if hasScope(key, scope) {
					allowed = true
					break
				}
			}
			if !allowed {
				return toolError("该 API key 缺少以下任一权限: " + strings.Join(h.AnyScopes, " / "))
			}
		}
		res := h.Run(ctx, key, call.Arguments)
		if h.Tool.Annotations["readOnlyHint"] != true {
			s.auditToolCall(key, h.Tool.Name, res)
		}
		return res
	}
	return toolError("未知工具: " + call.Name)
}

// auditToolCall 把写/扫描类工具调用落到 operation_logs，读工具不记，避免噪音。
// 用独立短超时，调用方断开也尽量留下审计。
func (s *MCPService) auditToolCall(key *repo.APIKey, toolName string, res *mcpToolResult) {
	r := repo.Default()
	if r == nil || key == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	status := 1
	if res == nil || res.IsError {
		status = 0
	}
	entry := &models.OperationLog{
		Username:  "apikey:" + key.Name,
		Action:    "mcp:" + toolName,
		Module:    "MCP",
		Target:    key.KeyPrefix,
		Detail:    "scopes=" + strings.Join(key.Scopes, ","),
		IP:        "",
		UserAgent: "mcp",
		Status:    status,
		CreatedAt: time.Now(),
	}
	_ = r.Audits().Add(ctx, entry)
}

// resolveKeyProject 统一项目边界：绑定项目的 key 只能读自己项目，
// 未绑定的 key 必须显式传 project_id，避免一次调用扫全库。
func resolveKeyProject(key *repo.APIKey, requested *int64) (int64, error) {
	if key.ProjectID != nil {
		if requested != nil && *requested > 0 && *requested != *key.ProjectID {
			return 0, fmt.Errorf("该 API key 只能访问项目 %d", *key.ProjectID)
		}
		return *key.ProjectID, nil
	}
	if requested == nil || *requested <= 0 {
		return 0, errors.New("未绑定项目的 API key 需要显式传 project_id")
	}
	return *requested, nil
}

// optionalProject 用于列表类工具：绑定 key 固定自己的项目，全项目 key 可传 0 表示全部。
func optionalProject(key *repo.APIKey, requested *int64) (int64, error) {
	if key.ProjectID != nil {
		if requested != nil && *requested > 0 && *requested != *key.ProjectID {
			return 0, fmt.Errorf("该 API key 只能访问项目 %d", *key.ProjectID)
		}
		return *key.ProjectID, nil
	}
	if requested == nil {
		return 0, nil
	}
	if *requested < 0 {
		return 0, errors.New("项目 ID 非法")
	}
	return *requested, nil
}

func ensureProjectAllowed(key *repo.APIKey, projectID int64) error {
	if key.ProjectID != nil && *key.ProjectID != projectID {
		return errors.New("资源不存在或不在该 API key 的授权范围内")
	}
	return nil
}

// requireGlobalKey 用于没有项目维度、或天然跨项目的工具（漏洞/POC、全库归档、建项目等）。
func requireGlobalKey(key *repo.APIKey) error {
	if key.ProjectID != nil {
		return errors.New("该工具只对「全部项目」的 API key 开放")
	}
	return nil
}

// ensureSiteAllowed 用站点的 project_id 做归属校验；
// 越权时按“不存在”处理，不泄露其它项目里是否有这个 site_id。
func ensureSiteAllowed(ctx context.Context, key *repo.APIKey, siteID int64) error {
	if key.ProjectID == nil {
		return nil
	}
	r := repo.Default()
	if r == nil {
		return errors.New("数据层未初始化")
	}
	projectID, err := r.APIKeys().ProjectIDBySiteID(ctx, siteID)
	if errors.Is(err, repo.ErrNotFound) {
		return errors.New("资产不存在或不在该 API key 的授权范围内")
	}
	if err != nil {
		return fmt.Errorf("校验资产归属失败: %w", err)
	}
	if !key.AllowsProject(projectID) {
		return errors.New("资产不存在或不在该 API key 的授权范围内")
	}
	return nil
}

func ensureSitesAllowed(ctx context.Context, key *repo.APIKey, siteIDs []int64) error {
	if key.ProjectID == nil {
		return nil
	}
	for _, id := range siteIDs {
		if err := ensureSiteAllowed(ctx, key, id); err != nil {
			return err
		}
	}
	return nil
}

func decodeArgs(raw json.RawMessage, dst any) error {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return fmt.Errorf("参数格式错误: %w", err)
	}
	return nil
}

// inputSchema 是 JSON Schema 的公共骨架，减少各工具定义里的重复。
func inputSchema(props map[string]any, required ...string) map[string]any {
	s := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func toolOK(v any) *mcpToolResult {
	body, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return toolError("序列化结果失败: " + err.Error())
	}
	return &mcpToolResult{
		Content:           []mcpContent{{Type: "text", Text: string(body)}},
		StructuredContent: v,
	}
}

func toolError(msg string) *mcpToolResult {
	return &mcpToolResult{
		Content: []mcpContent{{Type: "text", Text: strings.TrimSpace(msg)}},
		IsError: true,
	}
}

// readOnlyAnnotations 与 writeAnnotations 是工具注解的公共片段，帮助 MCP 客户端提示风险。
func readOnlyAnnotations() map[string]any {
	return map[string]any{"readOnlyHint": true, "openWorldHint": false, "idempotentHint": true}
}

func writeAnnotations(destructive bool) map[string]any {
	return map[string]any{
		"readOnlyHint":    false,
		"destructiveHint": destructive,
		"openWorldHint":   true,
		"idempotentHint":  false,
	}
}
