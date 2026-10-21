// aiprobe.go AI 协议暴露面探测:按 4zreco aiprobe 的探测面精简实现——三类端点:
// LLM/OpenAI 兼容(/v1/models 探测,响应含 model 列表即暴露)、MCP(/mcp 的
// JSON-RPC initialize)、A2A(/.well-known/agent.json)。只读 GET/POST 探测,
// 不利用。完整版(4zreco aiprobe 4k 行,含指纹引擎联动)按需后续补齐。
package oob

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// AIProbeResult 一类端点的探测结论。
type AIProbeResult struct {
	Kind    string `json:"kind"` // llm | mcp | a2a
	Path    string `json:"path"`
	Exposed bool   `json:"exposed"`
	Detail  string `json:"detail,omitempty"`
}

// aiProbePaths 三类端点的探测路径与判定。
var aiProbePaths = []struct {
	kind string
	path string
}{
	{"llm", "/v1/models"},
	{"a2a", "/.well-known/agent.json"},
	{"mcp", "/mcp"},
	{"llm", "/api/v1/models"},
}

// AIProtocolScan 对目标基 URL 做 AI 端点暴露面探测。
func AIProtocolScan(ctx context.Context, baseURL string, timeout time.Duration) ([]AIProbeResult, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if !strings.Contains(baseURL, "://") {
		return nil, fmt.Errorf("目标需为 http(s):// 形态")
	}
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	client := &http.Client{Timeout: timeout}
	var out []AIProbeResult
	for _, p := range aiProbePaths {
		res := probeAIEndpoint(ctx, client, p.kind, baseURL+p.path)
		out = append(out, res)
	}
	return out, nil
}

func probeAIEndpoint(ctx context.Context, client *http.Client, kind, rawURL string) AIProbeResult {
	res := AIProbeResult{Kind: kind, Path: rawURL[strings.LastIndex(rawURL, "/"):]}
	if kind == "mcp" {
		// MCP:JSON-RPC initialize(POST)。
		body, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0", "id": 1, "method": "initialize",
			"params": map[string]any{
				"protocolVersion": "2024-11-05",
				"capabilities":    map[string]any{},
				"clientInfo":      map[string]any{"name": "4zrec-probe", "version": "1.0"},
			},
		})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(body))
		if err != nil {
			return res
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		resp, err := client.Do(req)
		if err != nil {
			return res
		}
		defer resp.Body.Close()
		rb, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
		if resp.StatusCode == 200 && strings.Contains(string(rb), "serverInfo") {
			res.Exposed = true
			res.Detail = fmt.Sprintf("[%d] MCP 端点暴露(initialize 应答)", resp.StatusCode)
		}
		return res
	}
	// LLM/A2A:GET 探测。
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return res
	}
	resp, err := client.Do(req)
	if err != nil {
		return res
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	body := string(rb)
	switch {
	case kind == "llm" && resp.StatusCode == 200 && (strings.Contains(body, "\"data\"") || strings.Contains(body, "model")):
		res.Exposed = true
		res.Detail = fmt.Sprintf("[%d] LLM/OpenAI 兼容端点暴露(/v1/models 可枚举)", resp.StatusCode)
	case kind == "a2a" && resp.StatusCode == 200 && (strings.Contains(body, "capabilities") || strings.Contains(body, "agent")):
		res.Exposed = true
		res.Detail = fmt.Sprintf("[%d] A2A agent 清单暴露", resp.StatusCode)
	}
	return res
}
