package api

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/internal/toolruntime"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

// NodeToolsHandler 把 master 托管的外部扫描工具分发给 worker：
// 清单（含 sha256）+ gzip 二进制流。worker 侧自行校验后原子替换。
//
// 注意：清单只包含 master 本机平台（GOOS/GOARCH）的二进制——当前部署
// 形态 master 与 worker 同为 linux/amd64；异构 worker 回退 vendored/PATH。
type NodeToolsHandler struct {
	mgr *toolruntime.Manager

	mu       sync.Mutex
	hash     string
	manifest []toolManifestEntry
	stamp    time.Time
}

// toolManifestEntry 清单条目：版本仅供参考，sha256 才是安装依据。
type toolManifestEntry struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
	GOOS    string `json:"goos"`
	GOARCH  string `json:"goarch"`
}

type toolManifest struct {
	Hash  string              `json:"hash"`
	Tools []toolManifestEntry `json:"tools"`
}

func NewNodeToolsHandler() *NodeToolsHandler {
	return &NodeToolsHandler{mgr: toolruntime.Default()}
}

// build 清单内容变化时重算（缓存 30 秒，心跳高频调用不至于反复哈希大文件）。
func (h *NodeToolsHandler) build() toolManifest {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.manifest != nil && time.Since(h.stamp) < 30*time.Second {
		return toolManifest{Hash: h.hash, Tools: h.manifest}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var entries []toolManifestEntry
	for _, st := range h.mgr.Status(ctx) {
		if st.Path == "" || st.DiskSHA256 == "" {
			continue
		}
		fi, err := os.Stat(st.Path)
		if err != nil {
			continue
		}
		version := st.InstalledVersion
		if version == "" {
			version = st.DiskVersion
		}
		entries = append(entries, toolManifestEntry{
			Name: st.Name, Version: version, SHA256: st.DiskSHA256,
			Size: fi.Size(), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH,
		})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })

	raw, _ := json.Marshal(entries)
	sum := sha256.Sum256(raw)
	h.manifest, h.hash, h.stamp = entries, hex.EncodeToString(sum[:])[:12], time.Now()
	return toolManifest{Hash: h.hash, Tools: h.manifest}
}

// ManifestHash 供 NodeHub 随心跳下发；空串表示无托管工具。
func (h *NodeToolsHandler) ManifestHash() string {
	return h.build().Hash
}

// List GET /api/node/tools
func (h *NodeToolsHandler) List(c *gin.Context) {
	m := h.build()
	if m.Tools == nil {
		m.Tools = []toolManifestEntry{}
	}
	utils.Success(c, m)
}

// Download GET /api/node/tools/:name —— gzip 流式返回，X-Tool-Sha256 供核对。
func (h *NodeToolsHandler) Download(c *gin.Context) {
	name := strings.TrimSpace(c.Param("name"))
	if _, ok := toolruntime.Spec(name); !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "未知工具: " + name})
		return
	}
	path := h.mgr.ResolveToolPath(name)
	if path == "" {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": name + " 在平台上不可用"})
		return
	}
	sum, err := fileSHA256WithPath(path)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	f, err := os.Open(path)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": name + " 打开失败"})
		return
	}
	defer f.Close()
	c.Header("Content-Type", "application/gzip")
	c.Header("X-Tool-Sha256", sum)
	c.Header("X-Tool-Name", name)
	c.Status(http.StatusOK)
	gz := gzip.NewWriter(c.Writer)
	defer gz.Close()
	_, _ = io.Copy(gz, f)
}

func fileSHA256WithPath(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("计算 %s sha256 失败: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
