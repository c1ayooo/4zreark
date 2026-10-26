package api

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// NodeBinaryHandler 托管 worker 二进制，供节点自更新下载。
//
// 版本号取「解压后二进制」的 SHA-256 前 12 位：节点侧对自身可执行文件算同一个值，
// 两边不依赖 git 信息即可比对，改写二进制必然换版本。
type NodeBinaryHandler struct {
	path string

	mu      sync.Mutex
	version string
	modTime time.Time
}

func NewNodeBinaryHandler(path string) *NodeBinaryHandler {
	return &NodeBinaryHandler{path: path}
}

// Path 返回托管文件路径，空串表示平台没准备二进制。
func (h *NodeBinaryHandler) Path() string { return h.path }

// Version 返回当前 worker 二进制版本，文件不存在或读不出来时返回空串。
func (h *NodeBinaryHandler) Version() string {
	if h.path == "" {
		return ""
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	st, err := os.Stat(h.path)
	if err != nil {
		return ""
	}
	if h.version != "" && st.ModTime().Equal(h.modTime) && st.Size() > 0 {
		return h.version
	}

	f, err := os.Open(h.path)
	if err != nil {
		return ""
	}
	defer f.Close()

	var r io.Reader = f
	if strings.HasSuffix(h.path, ".gz") {
		zr, zerr := gzip.NewReader(f)
		if zerr != nil {
			return ""
		}
		defer zr.Close()
		r = zr
	}

	sum := sha256.New()
	if _, err := io.Copy(sum, r); err != nil {
		return ""
	}

	h.version = hex.EncodeToString(sum.Sum(nil))[:12]
	h.modTime = st.ModTime()
	return h.version
}

// Download 下发 worker 二进制。节点网关已做 token 鉴权，这里只负责流式返回。
func (h *NodeBinaryHandler) Download(c *gin.Context) {
	if h.path == "" {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "平台未配置 worker 二进制"})
		return
	}
	if _, err := os.Stat(h.path); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "worker 二进制不存在"})
		return
	}

	version := h.Version()
	if version != "" {
		c.Header("X-Worker-Version", version)
	}
	if strings.HasSuffix(h.path, ".gz") {
		c.Header("Content-Type", "application/gzip")
	} else {
		c.Header("Content-Type", "application/octet-stream")
	}
	c.File(h.path)
}
