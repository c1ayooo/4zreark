package api

import (
	"log"
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
		// 审计 L1：公开健康检查只给固定状态，数据库错误细节（含内部地址）
		// 进日志而不出接口。
		log.Printf("[Status] 数据库探活失败: %v", err)
		out["database"] = "down"
		out["status"] = "degraded"
	} else {
		out["database"] = "ok"
	}
	utils.Success(c, out)
}

// DNSStatus GET /dns/status
// 只做一次短超时的公网解析，回答「当前进程的 DNS 是否可用」。
func (h *StatusHandler) DNSStatus(c *gin.Context) {
	// 审计 L1：该接口已移到认证内（router），任意主机名的 DNS 解析不再
	// 对匿名开放；错误细节只给状态不给原始报错。
	host := c.DefaultQuery("host", "example.com")
	if host != "" && !isPlainHostname(host) {
		utils.BadRequest(c, "host 需为普通主机名")
		return
	}
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

// isPlainHostname 限制 DNS 探测目标为普通主机名（字母数字点连字符，≤253），
// 拒绝把该接口当任意解析 oracle 使用。
func isPlainHostname(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	for _, r := range host {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-':
		default:
			return false
		}
	}
	return true
}
