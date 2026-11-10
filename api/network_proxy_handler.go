package api

import (
	"github.com/gin-gonic/gin"

	"github.com/c1ayooo/4zreark/internal/outbound"
	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"
)

// NetworkProxyHandler 平台出网代理设置（规则同步/工具下载/情报等出网走代理）。
type NetworkProxyHandler struct {
	svc *service.NetworkProxyService
}

func NewNetworkProxyHandler() *NetworkProxyHandler {
	return &NetworkProxyHandler{svc: service.NewNetworkProxyService()}
}

// GetConfig 读代理配置
// @Summary 平台出网代理配置
// @Tags network-proxy
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /api/network/proxy [get]
func (h *NetworkProxyHandler) GetConfig(c *gin.Context) {
	cfg, err := h.svc.GetConfig(c.Request.Context())
	if err != nil {
		utils.InternalError(c, "读取代理配置失败: "+err.Error())
		return
	}
	utils.Success(c, gin.H{"config": cfg, "modules": outbound.Modules()})
}

// UpdateConfig 保存代理配置（保存后立即生效，无需重启）
// @Summary 更新平台出网代理配置
// @Tags network-proxy
// @Accept json
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /api/network/proxy [put]
func (h *NetworkProxyHandler) UpdateConfig(c *gin.Context) {
	var cfg outbound.Config
	if err := c.ShouldBindJSON(&cfg); err != nil {
		utils.BadRequest(c, "请求体不是合法 JSON")
		return
	}
	norm, err := h.svc.UpdateConfig(c.Request.Context(), cfg)
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	utils.Success(c, gin.H{"config": norm, "modules": outbound.Modules()})
}

// TestProxy 测连通性（category 非空 = 按模块生效配置测真实下载链路；
// 否则 url 非空测指定代理，url 为空测直连）
// @Summary 测试代理连通性
// @Tags network-proxy
// @Accept json
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /api/network/proxy/test [post]
func (h *NetworkProxyHandler) TestProxy(c *gin.Context) {
	var in struct {
		URL      string `json:"url"`
		Category string `json:"category"`
	}
	if err := c.ShouldBindJSON(&in); err != nil {
		utils.BadRequest(c, "请求体不是合法 JSON")
		return
	}
	utils.Success(c, h.svc.TestProxy(c.Request.Context(), in.URL, in.Category))
}
