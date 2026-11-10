package api

// 扫描安全设置：全局禁扫黑名单（config 只读展示）与 nuclei 误报黑名单（KV 可写）。
//
// 禁扫黑名单的生效值来自 config.yaml 的 scanner.deny_*（master/worker 共读同一份
// 配置才能保证两端判定一致，所以只读展示，不提供运行时改写）；nuclei 黑名单
// 的 KV 层可运行时增删，生效值 = KV ∪ config 兜底，创建任务时盖章下发。

import (
	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"
	"github.com/gin-gonic/gin"
)

// ScannerDenylistHandler 扫描安全黑名单端点。
type ScannerDenylistHandler struct{}

// NewScannerDenylistHandler 创建 handler。
func NewScannerDenylistHandler() *ScannerDenylistHandler { return &ScannerDenylistHandler{} }

// GetScannerDenylist GET /api/scanner/denylist
// 返回全局禁扫黑名单的生效值（config 只读）。
func (h *ScannerDenylistHandler) GetScannerDenylist(c *gin.Context) {
	cfg := config.Loaded()
	suffixes, cidrs := []string{}, []string{}
	if cfg != nil {
		suffixes = cfg.Scanner.DenyDomainSuffixes
		cidrs = cfg.Scanner.DenyCIDRs
	}
	utils.Success(c, gin.H{
		"deny_domain_suffixes": suffixes,
		"deny_cidrs":           cidrs,
		"editable":             false, // 只读：改 config.yaml，master/worker 必须一致
	})
}

// GetNucleiDenylist GET /api/nuclei/denylist
func (h *ScannerDenylistHandler) GetNucleiDenylist(c *gin.Context) {
	kvIDs, found, err := service.GetNucleiDenyTemplateIDs(c.Request.Context())
	if err != nil {
		utils.InternalError(c, "读取 nuclei 黑名单失败: "+err.Error())
		return
	}
	if !found {
		kvIDs = []string{}
	}
	var fileCfg []string
	if cfg := config.Loaded(); cfg != nil {
		fileCfg = cfg.Scanner.NucleiDenyTemplateIDs
	}
	utils.Success(c, gin.H{
		"ids":        service.ResolveNucleiDenyTemplateIDs(c.Request.Context()),
		"kv_ids":     kvIDs,
		"config_ids": fileCfg,
	})
}

// UpdateNucleiDenylist PUT /api/nuclei/denylist
// body: {"ids": ["cve-2023-xxxx", ...]} 全量覆盖 KV 层。
func (h *ScannerDenylistHandler) UpdateNucleiDenylist(c *gin.Context) {
	var body struct {
		IDs []string `json:"ids"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, "请求体格式错误")
		return
	}
	if err := service.SaveNucleiDenyTemplateIDs(c.Request.Context(), body.IDs); err != nil {
		utils.InternalError(c, "保存 nuclei 黑名单失败: "+err.Error())
		return
	}
	utils.SuccessWithMessage(c, "已保存 nuclei 误报黑名单（新任务创建时生效）", gin.H{
		"ids": service.ResolveNucleiDenyTemplateIDs(c.Request.Context()),
	})
}
