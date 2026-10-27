package middleware

import (
	"github.com/c1ayooo/4zreark/config"
	"github.com/gin-gonic/gin"
)

// ForceHTTPS 落实审计 M11 的传输安全边界：
//   - 原生 TLS（server.tls_cert/tls_key）：直接放行并下发 HSTS；
//   - 反向代理终止 TLS（force_https 开启）：X-Forwarded-Proto 不是 https 的
//     明文请求一律 301 到 https 同路径，并下发 HSTS；
//   - 本地开发（两者都没开）：不介入，保持 0 配置可跑。
//
// HSTS 只在浏览器确认的 HTTPS 响应上生效；在明文重定向里携带该头无副作用，
// 能覆盖「先 https 访问过、证书后误配」的回退窗口。
func ForceHTTPS() gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg := config.GetConfig()
		nativeTLS := c.Request.TLS != nil
		if !cfg.Server.ForceHTTPS && !nativeTLS {
			c.Next()
			return
		}
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		if nativeTLS {
			c.Next()
			return
		}
		if c.GetHeader("X-Forwarded-Proto") == "https" {
			c.Next()
			return
		}
		// 明文请求：301 到 https。Host 取 Host 头（反代场景即对外域名），
		// 路径与查询串原样保留。
		scheme := "https"
		url := scheme + "://" + c.Request.Host + c.Request.URL.RequestURI()
		c.Redirect(301, url)
		c.Abort()
	}
}
