package middleware

import (
	"compress/gzip"
	"strings"

	"github.com/gin-gonic/gin"
)

// gzipResponseWriter 延迟到第一次写 body 时才开启压缩，
// 这样 204/304 这类无 body 响应不会被塞进 gzip 头。
type gzipResponseWriter struct {
	gin.ResponseWriter
	writer  *gzip.Writer
	started bool
}

func (w *gzipResponseWriter) Write(b []byte) (int, error) {
	if !w.started {
		w.started = true
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Add("Vary", "Accept-Encoding")
		w.Header().Del("Content-Length")
	}
	return w.writer.Write(b)
}

func (w *gzipResponseWriter) WriteString(s string) (int, error) {
	return w.Write([]byte(s))
}

// Gzip 只压缩 /api/ JSON；静态资源交给前端/反向代理处理。
func Gzip() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !strings.HasPrefix(c.Request.URL.Path, "/api/") ||
			!strings.Contains(c.GetHeader("Accept-Encoding"), "gzip") {
			c.Next()
			return
		}
		gz := gzip.NewWriter(c.Writer)
		gw := &gzipResponseWriter{ResponseWriter: c.Writer, writer: gz}
		c.Writer = gw
		c.Next()
		if gw.started {
			_ = gz.Close()
		}
	}
}
