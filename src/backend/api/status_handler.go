package api

import (
	"context"
	"net"
	"time"

	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

// StatusHandler 提供进程/数据库/DNS 的健康状态。
type StatusHandler struct{}

func NewStatusHandler() *StatusHandler { return &StatusHandler{} }

// Status GET /api/status
func (h *StatusHandler) Status(c *gin.Context) {
	out := gin.H{
		"status": "ok",
		"time":   time.Now().UTC(),
	}
	if repo.Default() == nil {
		out["database"] = "uninitialized"
		out["status"] = "degraded"
		utils.Success(c, out)
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
	defer cancel()
	if err := repo.Default().Ping(ctx); err != nil {
		out["database"] = "down"
		out["status"] = "degraded"
		out["database_error"] = err.Error()
	} else {
		out["database"] = "ok"
	}
	utils.Success(c, out)
}

// DNSStatus GET /dns/status
// 只做一次短超时的公网解析，回答「当前进程的 DNS 是否可用」。
func (h *StatusHandler) DNSStatus(c *gin.Context) {
	host := c.DefaultQuery("host", "example.com")
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	start := time.Now()
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	elapsed := time.Since(start).Milliseconds()
	if err != nil {
		utils.Success(c, gin.H{"ok": false, "host": host, "elapsed_ms": elapsed, "error": err.Error()})
		return
	}
	addrs := make([]string, 0, len(ips))
	for _, ip := range ips {
		addrs = append(addrs, ip.String())
	}
	utils.Success(c, gin.H{"ok": true, "host": host, "elapsed_ms": elapsed, "addresses": addrs})
}
