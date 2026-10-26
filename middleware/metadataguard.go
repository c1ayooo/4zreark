package middleware

import (
	"bytes"
	"io"
	"net/http"
	"regexp"

	"github.com/gin-gonic/gin"
)

// metadataIPPatterns 匹配云厂商元数据地址的字面量：
//   - 169.254.0.0/16 链路本地（AWS/GCP/Azure/OpenStack 元数据 169.254.169.254）
//   - 100.100.100.200（阿里云 ECS 元数据）
//
// 作为侦察平台，扫描内网是特性；这里只拦「平台替用户请求元数据」这条
// 变成跳板的路径。域名形态（metadata.google.internal 等）解析发生在
// 目标环境内部，字面量拦截覆盖主流云的实际风险面。
var metadataIPPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\b169\.254\.\d{1,3}\.\d{1,3}\b`),
	regexp.MustCompile(`\b100\.100\.100\.200\b`),
}

// MetadataTargetGuard 检查 JSON 请求体里是否包含云元数据地址字面量，
// 命中直接 400。挂在与「平台主动对用户输入发请求」相关的路由组上（/api/scan/*）。
// body 会原样恢复给后续 handler。
func MetadataTargetGuard() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Body == nil || c.Request.Body == http.NoBody {
			c.Next()
			return
		}
		// 读取上限 1MiB 足够覆盖 target/domains 字段；更大的 body（字典等）
		// 截断检查前 1MiB，不阻塞请求本身。
		raw, err := io.ReadAll(io.LimitReader(c.Request.Body, 1<<20))
		_ = c.Request.Body.Close()
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"code":    http.StatusBadRequest,
				"message": "读取请求体失败",
			})
			return
		}
		// 恢复 body：把已读内容与剩余部分重新拼回去。
		c.Request.Body = io.NopCloser(io.MultiReader(bytes.NewReader(raw), c.Request.Body))

		for _, re := range metadataIPPatterns {
			if re.Match(raw) {
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
					"code":    http.StatusBadRequest,
					"message": "目标包含云元数据地址（169.254.0.0/16 / 100.100.100.200），已拒绝",
				})
				return
			}
		}
		c.Next()
	}
}
