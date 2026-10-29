package service

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service/pipeline"

	"github.com/gorilla/websocket"
	xproxy "golang.org/x/net/proxy"
)

// ErrNodeRevoked 表示平台返回 401/403：密钥被吊销或节点被删除。
var ErrNodeRevoked = errors.New("节点密钥无效或已吊销")

// RemoteClient 是远程 worker 访问平台节点 API 的唯一入口。
// 节点只持有一个可吊销的 token，不持有数据库账号。
type RemoteClient struct {
	baseURL  string
	token    string
	http     *http.Client
	wsDialer *websocket.Dialer

	pocMu  sync.Mutex
	pocs   []*models.POC
	pocAt  time.Time
	pocTTL time.Duration
}

// NewRemoteClient 创建平台客户端。proxyURL 为空表示直连；支持
// socks5://user:pass@host:port 与 http(s)://host:port 两种代理。
func NewRemoteClient(baseURL, token, proxyURL, caFile string) *RemoteClient {
	transport := &http.Transport{}
	dialer := &websocket.Dialer{HandshakeTimeout: 20 * time.Second}

	tlsCfg := &tls.Config{}
	if strings.TrimSpace(caFile) != "" {
		if pemData, err := os.ReadFile(caFile); err != nil {
			log.Printf("[RemoteClient] 读取节点网关 CA 失败（%s）: %v", caFile, err)
		} else {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM(pemData) {
				tlsCfg.RootCAs = pool
			} else {
				log.Printf("[RemoteClient] 节点网关 CA 内容无效: %s", caFile)
			}
		}
	}
	transport.TLSClientConfig = tlsCfg
	dialer.TLSClientConfig = tlsCfg

	if raw := strings.TrimSpace(proxyURL); raw != "" {
		if u, err := url.Parse(raw); err == nil {
			switch strings.ToLower(u.Scheme) {
			case "socks5", "socks5h":
				var auth *xproxy.Auth
				if u.User != nil {
					pass, _ := u.User.Password()
					auth = &xproxy.Auth{User: u.User.Username(), Password: pass}
				}
				if d, derr := xproxy.SOCKS5("tcp", u.Host, auth, xproxy.Direct); derr == nil {
					dialCtx := func(ctx context.Context, network, addr string) (net.Conn, error) {
						if cd, ok := d.(xproxy.ContextDialer); ok {
							return cd.DialContext(ctx, network, addr)
						}
						return d.Dial(network, addr)
					}
					transport.DialContext = dialCtx
					dialer.NetDialContext = dialCtx
				}
			default:
				transport.Proxy = http.ProxyURL(u)
				dialer.Proxy = http.ProxyURL(u)
			}
		}
	}

	return &RemoteClient{
		baseURL:  strings.TrimRight(baseURL, "/"),
		token:    token,
		http:     &http.Client{Timeout: 5 * time.Minute, Transport: transport},
		wsDialer: dialer,
		pocTTL:   10 * time.Minute,
	}
}

// WebSocketDialer 供 RemoteAgent 建立控制通道，自动带上代理配置。
func (c *RemoteClient) WebSocketDialer() *websocket.Dialer {
	if c.wsDialer == nil {
		return websocket.DefaultDialer
	}
	return c.wsDialer
}

type apiEnvelope struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

func (c *RemoteClient) call(ctx context.Context, method, path string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return ErrNodeRevoked
	}
	// 404 统一映射为 ErrNotFound 哨兵：调用方要能区分「不存在」和「平台故障」，
	// 否则瞬时网络问题会被误判成任务已删除而取消在跑的扫描。
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("平台返回 HTTP 404: %w", repo.ErrNotFound)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("平台返回 HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var env apiEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("解析平台响应失败: %w", err)
	}
	if env.Code != 0 {
		return fmt.Errorf("平台返回错误(%d): %s", env.Code, env.Message)
	}
	if out != nil && len(env.Data) > 0 && string(env.Data) != "null" {
		return json.Unmarshal(env.Data, out)
	}
	return nil
}

func (c *RemoteClient) GetTask(ctx context.Context, taskID string) (*models.Task, error) {
	var task models.Task
	if err := c.call(ctx, http.MethodGet, "/api/node/tasks/"+taskID, nil, &task); err != nil {
		return nil, err
	}
	return &task, nil
}

// ToolsManifestEntry 平台工具清单条目。
type ToolsManifestEntry struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
	GOOS    string `json:"goos"`
	GOARCH  string `json:"goarch"`
}

// ToolsManifest 平台托管工具清单。
type ToolsManifest struct {
	Hash  string               `json:"hash"`
	Tools []ToolsManifestEntry `json:"tools"`
}

// FetchToolsManifest 拉取平台工具清单（含每个工具的 sha256）。
func (c *RemoteClient) FetchToolsManifest(ctx context.Context) (*ToolsManifest, error) {
	var m ToolsManifest
	if err := c.call(ctx, http.MethodGet, "/api/node/tools", nil, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// DownloadTool 下载平台托管的工具二进制（gzip 流），返回解压后的原始字节
// 和响应头里的 sha256。不走 envelope，是原始字节流。
func (c *RemoteClient) DownloadTool(ctx context.Context, name string) (data []byte, sha string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/node/tools/"+name, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, "", ErrNodeRevoked
	}
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, "", fmt.Errorf("平台返回 HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	zr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("工具流不是合法 gzip: %w", err)
	}
	defer zr.Close()
	raw, err := io.ReadAll(io.LimitReader(zr, 512<<20))
	if err != nil {
		return nil, "", err
	}
	return raw, resp.Header.Get("X-Tool-Sha256"), nil
}

func (c *RemoteClient) UpdateTask(ctx context.Context, taskID string, updates map[string]interface{}) error {
	return c.call(ctx, http.MethodPut, "/api/node/tasks/"+taskID, updates, nil)
}

// TouchTask 节点活性心跳：只推进任务 updated_at。
// ClaimTask 执行认领上报（跨执行器分配凭证）。
func (c *RemoteClient) ClaimTask(ctx context.Context, taskID, executorID, claimNodeID string) (bool, error) {
	var out struct {
		Claimed bool `json:"claimed"`
	}
	err := c.call(ctx, http.MethodPost,
		fmt.Sprintf("/api/node/tasks/%s/claim", taskID),
		map[string]any{"executor_id": executorID, "claim_node_id": claimNodeID}, &out)
	if err != nil {
		return false, err
	}
	return out.Claimed, nil
}

// ReleaseTask 释放执行认领。
func (c *RemoteClient) ReleaseTask(ctx context.Context, taskID string) error {
	return c.call(ctx, http.MethodPost,
		fmt.Sprintf("/api/node/tasks/%s/claim", taskID),
		map[string]any{"executor_id": ""}, nil)
}

// AddTaskLogCategory 把动作日志上报给平台（worker 侧无库，经网关落 task_logs）。
func (c *RemoteClient) AddTaskLogCategory(ctx context.Context, taskID, category, level, message string) error {
	return c.call(ctx, http.MethodPost,
		fmt.Sprintf("/api/node/tasks/%s/logs", taskID),
		map[string]any{"category": category, "level": level, "message": message},
		nil)
}

func (c *RemoteClient) TouchTask(ctx context.Context, taskID string) error {
	return c.call(ctx, http.MethodPut, "/api/node/tasks/"+taskID+"/touch", nil, nil)
}

func (c *RemoteClient) PostResults(ctx context.Context, taskID string, results []*models.ScanResult) error {
	return c.call(ctx, http.MethodPost, "/api/node/tasks/"+taskID+"/results",
		map[string]interface{}{"results": results}, nil)
}

func (c *RemoteClient) PostAssets(ctx context.Context, taskID string, records []repo.RawRecord, routes []CrawledEndpoint) error {
	return c.call(ctx, http.MethodPost, "/api/node/tasks/"+taskID+"/assets",
		map[string]interface{}{"records": records, "routes": routes}, nil)
}

// PostDictLearning 上报节点侧观察到的字典学习热词（子域首标签/归一路径），
// 平台侧统一计频与晋升，学习闭环覆盖分布式部署。
func (c *RemoteClient) PostDictLearning(ctx context.Context, taskID string, subLabels, paths []string) error {
	return c.call(ctx, http.MethodPost, "/api/node/tasks/"+taskID+"/dict-learning",
		map[string]interface{}{"sub_labels": subLabels, "paths": paths}, nil)
}

func (c *RemoteClient) UpdateCDN(ctx context.Context, taskID, domain, provider string) error {
	return c.call(ctx, http.MethodPost, "/api/node/tasks/"+taskID+"/cdn",
		map[string]string{"domain": domain, "cdn": provider}, nil)
}

func (c *RemoteClient) ListPOCs(ctx context.Context) ([]*models.POC, error) {
	c.pocMu.Lock()
	if len(c.pocs) > 0 && time.Since(c.pocAt) < c.pocTTL {
		cached := c.pocs
		c.pocMu.Unlock()
		return cached, nil
	}
	c.pocMu.Unlock()

	var pocs []*models.POC
	if err := c.call(ctx, http.MethodGet, "/api/node/pocs", nil, &pocs); err != nil {
		return nil, err
	}
	c.pocMu.Lock()
	c.pocs = pocs
	c.pocAt = time.Now()
	c.pocMu.Unlock()
	return pocs, nil
}

// InstallPOCLoader 让本地流水线的漏洞模块从平台拉取 POC，而不是读数据库。
func (c *RemoteClient) InstallPOCLoader() {
	pipeline.SetPOCLoader(func(ctx context.Context) ([]*models.POC, error) {
		return c.ListPOCs(ctx)
	})
}

// remoteTaskStore 让 TaskExecutor 的任务读写走平台 HTTP。
type remoteTaskStore struct{ client *RemoteClient }

func (s *remoteTaskStore) GetTaskByID(taskID string) (*models.Task, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return s.client.GetTask(ctx, taskID)
}

func (s *remoteTaskStore) UpdateTask(taskID string, updates map[string]interface{}) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return s.client.UpdateTask(ctx, taskID, updates)
}

func (s *remoteTaskStore) AddLogCategory(ctx context.Context, taskID, category, level, message, detail string) error {
	return s.client.AddTaskLogCategory(ctx, taskID, category, level, message)
}

func (s *remoteTaskStore) ClaimExecution(ctx context.Context, taskID, executorID, claimNodeID string) (bool, error) {
	return s.client.ClaimTask(ctx, taskID, executorID, claimNodeID)
}

func (s *remoteTaskStore) ReleaseExecution(ctx context.Context, taskID string) error {
	return s.client.ReleaseTask(ctx, taskID)
}

func (s *remoteTaskStore) TouchTask(taskID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return s.client.TouchTask(ctx, taskID)
}

// remoteResultStore 缓存结果并按批上传，避免每条结果一次 HTTP。
type remoteResultStore struct {
	client *RemoteClient
	mu     sync.Mutex
	buf    map[string][]*models.ScanResult
}

func newRemoteResultStore(client *RemoteClient) *remoteResultStore {
	return &remoteResultStore{client: client, buf: make(map[string][]*models.ScanResult)}
}

func (s *remoteResultStore) add(result *models.ScanResult) error {
	if result == nil {
		return nil
	}
	taskID := result.TaskID.Hex()
	s.mu.Lock()
	s.buf[taskID] = append(s.buf[taskID], result)
	batch := len(s.buf[taskID])
	s.mu.Unlock()
	// 小批量回传：worker 侧发现结果就尽快让平台可见，而不是等 200 条或任务结束。
	if batch >= 20 {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		return s.Flush(ctx, taskID)
	}
	return nil
}

func (s *remoteResultStore) CreateResult(result *models.ScanResult) error {
	return s.add(result)
}

func (s *remoteResultStore) CreateResultWithDedup(result *models.ScanResult) error {
	return s.add(result)
}

// BatchCreateResultPtrsWithDedup 逐条进本地缓冲，真正的批量由 Flush 完成
// （远程路径的瓶颈是 HTTP 往返，不是本地事务）。
func (s *remoteResultStore) BatchCreateResultPtrsWithDedup(results []*models.ScanResult) (int, int, error) {
	for _, res := range results {
		if err := s.add(res); err != nil {
			return 0, 0, err
		}
	}
	return len(results), 0, nil
}

func (s *remoteResultStore) UpdateSubdomainCDN(taskID, domain, cdnProvider string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return s.client.UpdateCDN(ctx, taskID, domain, cdnProvider)
}

func (s *remoteResultStore) Flush(ctx context.Context, taskID string) error {
	s.mu.Lock()
	batch := s.buf[taskID]
	if len(batch) > 0 {
		delete(s.buf, taskID)
	}
	s.mu.Unlock()
	if len(batch) == 0 {
		return nil
	}
	if err := s.client.PostResults(ctx, taskID, batch); err != nil {
		// 保留未上传的结果，任务结束前再试一次。
		s.mu.Lock()
		s.buf[taskID] = append(batch, s.buf[taskID]...)
		s.mu.Unlock()
		return err
	}
	return nil
}
