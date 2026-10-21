package api

import (
	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

// ToolkitHandler 手工验证工具面：OOB、凭据只读验证、HTTP 差分、JS 侦察。
type ToolkitHandler struct {
	svc *service.ToolkitService
}

func NewToolkitHandler() *ToolkitHandler {
	return &ToolkitHandler{svc: service.NewToolkitService()}
}

// OOBDomain 申请带外验证域名
// @Router /api/tools/oob/domain [post]
func (h *ToolkitHandler) OOBDomain(c *gin.Context) {
	var req struct {
		Base string `json:"base"`
	}
	_ = c.ShouldBindJSON(&req)
	domain, err := h.svc.OOBDomain(c.Request.Context(), req.Base)
	if err != nil {
		utils.InternalError(c, "申请 OOB 域名失败: "+err.Error())
		return
	}
	utils.Success(c, gin.H{"domain": domain})
}

// OOBRecords 查询带外记录
// @Router /api/tools/oob/records [post]
func (h *ToolkitHandler) OOBRecords(c *gin.Context) {
	var req struct {
		Base        string `json:"base"`
		Domain      string `json:"domain" binding:"required"`
		WaitSeconds int    `json:"wait_seconds"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	records, err := h.svc.OOBRecords(c.Request.Context(), req.Base, req.Domain, req.WaitSeconds)
	if err != nil {
		utils.InternalError(c, "查询 OOB 记录失败: "+err.Error())
		return
	}
	utils.Success(c, gin.H{"domain": req.Domain, "records": records})
}

// VerifyCloudCredential 云 AK/SK 只读验证
// @Router /api/tools/creds/cloud [post]
func (h *ToolkitHandler) VerifyCloudCredential(c *gin.Context) {
	var in service.CloudCredInput
	if err := c.ShouldBindJSON(&in); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	res, err := h.svc.VerifyCloudCredential(c.Request.Context(), in)
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	utils.Success(c, res)
}

// VerifyDB 数据库凭据只读验证
// @Router /api/tools/creds/db [post]
func (h *ToolkitHandler) VerifyDB(c *gin.Context) {
	var in service.DBCredInput
	if err := c.ShouldBindJSON(&in); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	res, err := h.svc.VerifyDB(c.Request.Context(), in)
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	utils.Success(c, res)
}

// VerifySSH SSH 凭据只读验证
// @Router /api/tools/creds/ssh [post]
func (h *ToolkitHandler) VerifySSH(c *gin.Context) {
	var in service.SSHCredInput
	if err := c.ShouldBindJSON(&in); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	res, err := h.svc.VerifySSH(c.Request.Context(), in)
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	utils.Success(c, res)
}

// DiffProbe HTTP 差分测量
// @Router /api/tools/diffprobe [post]
func (h *ToolkitHandler) DiffProbe(c *gin.Context) {
	var in service.DiffProbeInput
	if err := c.ShouldBindJSON(&in); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	res, err := h.svc.DiffProbe(c.Request.Context(), in)
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	utils.Success(c, res)
}

// WebRecon JS 端点与敏感信息侦察
// @Router /api/tools/webrecon [post]
func (h *ToolkitHandler) WebRecon(c *gin.Context) {
	var in service.WebReconInput
	if err := c.ShouldBindJSON(&in); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	res, err := h.svc.WebRecon(c.Request.Context(), in)
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	utils.Success(c, res)
}

// QuoteCheck 证据引文子串校验
// @Router /api/tools/quote-check [post]
func (h *ToolkitHandler) QuoteCheck(c *gin.Context) {
	var req struct {
		Quote string `json:"quote"`
		Text  string `json:"text" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	ok, err := h.svc.QuoteCheck(req.Quote, req.Text)
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	utils.Success(c, gin.H{"found": ok})
}

// Playbooks 列出内置验证剧本
// @Router /api/tools/playbooks [get]
func (h *ToolkitHandler) Playbooks(c *gin.Context) {
	items, errs, err := h.svc.Playbooks()
	if err != nil {
		utils.InternalError(c, "读取剧本失败: "+err.Error())
		return
	}
	utils.Success(c, gin.H{"items": items, "errors": errs})
}

// RunPlaybook 执行验证剧本
// @Router /api/tools/playbooks/run [post]
func (h *ToolkitHandler) RunPlaybook(c *gin.Context) {
	var in service.RunPlaybookInput
	if err := c.ShouldBindJSON(&in); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	res, err := h.svc.RunPlaybook(c.Request.Context(), in)
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	utils.Success(c, res)
}

// GithubLeakDorks 内置 GitHub 泄露检索模板
// @Router /api/tools/github-leak/dorks [get]
func (h *ToolkitHandler) GithubLeakDorks(c *gin.Context) {
	utils.Success(c, service.NewGithubLeakService().Dorks())
}

// GithubLeakScan 执行 GitHub 泄露检索与本地检测
// @Router /api/tools/github-leak/scan [post]
func (h *ToolkitHandler) GithubLeakScan(c *gin.Context) {
	var in service.LeakScanInput
	if err := c.ShouldBindJSON(&in); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	res, err := service.NewGithubLeakService().Scan(c.Request.Context(), in)
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	utils.Success(c, res)
}

// EnterpriseProviders 企业数据源清单
// @Router /api/tools/enterprise/providers [get]
func (h *ToolkitHandler) EnterpriseProviders(c *gin.Context) {
	utils.Success(c, h.svc.EnterpriseProviders())
}

// EnterpriseSearch 企业信息检索（会话凭据只在本次请求内使用）
// @Router /api/tools/enterprise/search [post]
func (h *ToolkitHandler) EnterpriseSearch(c *gin.Context) {
	var in service.EnterpriseSearchInput
	if err := c.ShouldBindJSON(&in); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	res, err := h.svc.EnterpriseSearch(c.Request.Context(), in)
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	utils.Success(c, res)
}

// Extract 按模板 id 解析命中报文中的结构化产物
// @Router /api/tools/extract [post]
func (h *ToolkitHandler) Extract(c *gin.Context) {
	var in service.ExtractInput
	if err := c.ShouldBindJSON(&in); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	f, err := h.svc.Extract(c.Request.Context(), in)
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	if f == nil {
		utils.Success(c, gin.H{"found": false})
		return
	}
	utils.Success(c, gin.H{"found": true, "finding": f})
}
