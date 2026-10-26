package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

// MCPHandler 把 MCP Streamable HTTP 传输映射到 JSON-RPC 服务。
//
//	POST /api/mcp    JSON-RPC 请求（initialize / tools/list / tools/call ...）
//	GET  /api/mcp    本服务不主动推送 SSE，返回 405
//	DELETE /api/mcp  无会话状态，返回 204
//
// 鉴权不走 JWT：由 middleware.APIKeyMiddleware 校验 API key，
// 并把绑定项目放进 context，后续工具调用只在这个项目内读取。
type MCPHandler struct {
	mcp *service.MCPService
}

func NewMCPHandler() *MCPHandler {
	return &MCPHandler{mcp: service.NewMCPService()}
}

func (h *MCPHandler) Serve(c *gin.Context) {
	switch c.Request.Method {
	case http.MethodPost:
		h.post(c)
	case http.MethodDelete:
		c.Status(http.StatusNoContent)
	case http.MethodGet:
		c.Header("Allow", "POST, DELETE")
		c.JSON(http.StatusMethodNotAllowed, gin.H{
			"error": "本 MCP 服务不使用 SSE 推送，请用 POST 发送 JSON-RPC 请求",
		})
	default:
		c.Header("Allow", "POST, DELETE")
		c.Status(http.StatusMethodNotAllowed)
	}
}

func (h *MCPHandler) post(c *gin.Context) {
	const maxBody = 4 << 20 // 4 MiB，查询请求足够用
	body, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, maxBody))
	if err != nil {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "请求体过大"})
		return
	}

	var req service.RPCRequest
	if err := json.Unmarshal(body, &req); err != nil {
		c.JSON(http.StatusOK, service.RPCResponse{
			JSONRPC: "2.0",
			ID:      json.RawMessage("null"),
			Error:   &service.RPCError{Code: -32700, Message: "JSON 解析失败: " + err.Error()},
		})
		return
	}

	// 通知（notifications/initialized 等）不需要响应体。
	if len(req.ID) == 0 {
		c.Status(http.StatusAccepted)
		return
	}

	keyVal, ok := c.Get("api_key")
	key, _ := keyVal.(*repo.APIKey)
	if !ok || key == nil {
		utils.Unauthorized(c, "缺少 API key 上下文")
		return
	}

	resp, err := h.mcp.Handle(c.Request.Context(), &req, key)
	if err != nil {
		if errors.Is(err, service.ErrInvalidAPIKey) ||
			errors.Is(err, service.ErrAPIKeyDisabled) ||
			errors.Is(err, service.ErrAPIKeyExpired) {
			utils.Unauthorized(c, err.Error())
			return
		}
		c.JSON(http.StatusOK, service.RPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &service.RPCError{Code: -32603, Message: err.Error()},
		})
		return
	}
	if resp == nil {
		c.Status(http.StatusAccepted)
		return
	}
	c.Header("Content-Type", "application/json; charset=utf-8")
	c.JSON(http.StatusOK, resp)
}
