package service

import (
	"github.com/c1ayooo/4zreark/internal/safehttp"
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/internal/creds"
	"github.com/c1ayooo/4zreark/internal/diffprobe"
	"github.com/c1ayooo/4zreark/internal/enterprise"
	"github.com/c1ayooo/4zreark/internal/evidenceguard"
	"github.com/c1ayooo/4zreark/internal/extractor"
	"github.com/c1ayooo/4zreark/internal/httpprobe"
	"github.com/c1ayooo/4zreark/internal/oob"
	"github.com/c1ayooo/4zreark/internal/recon/webrecon"
	"github.com/c1ayooo/4zreark/internal/verifyrunner"
)

// ToolkitService 是手工验证工具的后端：OOB、凭据只读验证、HTTP 差分、JS 侦察。
// 所有会发流量的入口都要求 project_id，并按项目种子做强 scope 校验。
type ToolkitService struct{}

func NewToolkitService() *ToolkitService { return &ToolkitService{} }

// --- OOB ---

// OOBDomain 申请一个带外验证域名。
func (s *ToolkitService) OOBDomain(ctx context.Context, base string) (string, error) {
	domain, err := oob.DnslogGetDomain(ctx, base)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(domain) == "" {
		return "", errors.New("dnslog 返回空域名")
	}
	return domain, nil
}

// OOBRecords 查询带外记录；waitSeconds 给目标触发 DNS 的时间。
func (s *ToolkitService) OOBRecords(ctx context.Context, base, domain string, waitSeconds int) ([]string, error) {
	if waitSeconds < 0 {
		waitSeconds = 0
	}
	if waitSeconds > 60 {
		waitSeconds = 60
	}
	return oob.DnslogGetRecords(ctx, base, domain, waitSeconds)
}

// --- 凭据只读验证 ---

// CloudCredInput 云 AK/SK 验证入参。
type CloudCredInput struct {
	Provider    string `json:"provider" binding:"required"`
	AccessKeyID string `json:"access_key_id" binding:"required"`
	SecretKey   string `json:"secret_key" binding:"required"`
}

func (s *ToolkitService) VerifyCloudCredential(ctx context.Context, in CloudCredInput) (creds.VerifyResult, error) {
	if !creds.ValidProvider(in.Provider) {
		return creds.VerifyResult{}, errors.New("不支持的云厂商（aliyun/tencent/aws/huawei/volc）")
	}
	// 审计 M3：携云凭据出站走 strict 档（私网/loopback/元数据全禁，官方 API 固定上游）。
	client := safehttp.Client(safehttp.ModeStrict, 20*time.Second)
	return creds.Verify(ctx, client, in.Provider, in.AccessKeyID, in.SecretKey)
}

// DBCredInput 数据库凭据验证入参。
type DBCredInput struct {
	ProjectID int64  `json:"project_id" binding:"required"`
	Type      string `json:"type" binding:"required"`
	Host      string `json:"host" binding:"required"`
	Port      int    `json:"port"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	Database  string `json:"database"`
	Timeout   int    `json:"timeout_seconds"`
}

func (s *ToolkitService) VerifyDB(ctx context.Context, in DBCredInput) (*creds.DBProbeResult, error) {
	if err := checkTargetScope(ctx, in.ProjectID, in.Host); err != nil {
		return nil, err
	}
	return creds.VerifyDB(ctx, creds.DBProbeInput{
		Type: in.Type, Host: in.Host, Port: in.Port, Username: in.Username,
		Password: in.Password, Database: in.Database,
		Timeout: time.Duration(in.Timeout) * time.Second,
	})
}

// SSHCredInput SSH 凭据验证入参。
type SSHCredInput struct {
	ProjectID  int64  `json:"project_id" binding:"required"`
	Host       string `json:"host" binding:"required"`
	Port       int    `json:"port"`
	Username   string `json:"username" binding:"required"`
	Password   string `json:"password"`
	PrivateKey string `json:"private_key"`
	Timeout    int    `json:"timeout_seconds"`
}

func (s *ToolkitService) VerifySSH(ctx context.Context, in SSHCredInput) (*creds.SSHProbeResult, error) {
	if err := checkTargetScope(ctx, in.ProjectID, in.Host); err != nil {
		return nil, err
	}
	return creds.VerifySSH(ctx, creds.SSHProbeInput{
		Host: in.Host, Port: in.Port, Username: in.Username,
		Password: in.Password, PrivateKey: in.PrivateKey,
		Timeout: time.Duration(in.Timeout) * time.Second,
	})
}

// --- HTTP 差分 ---

// DiffProbeInput 差分探测入参。Baseline/Variants 的结构直接复用 diffprobe 的类型。
type DiffProbeInput struct {
	ProjectID int64               `json:"project_id" binding:"required"`
	Baseline  diffprobe.Request   `json:"baseline" binding:"required"`
	Variants  []diffprobe.Request `json:"variants" binding:"required"`
	Options   diffprobe.Options   `json:"options"`
}

func (s *ToolkitService) DiffProbe(ctx context.Context, in DiffProbeInput) (*diffprobe.Report, error) {
	if err := checkTargetScope(ctx, in.ProjectID, in.Baseline.URL); err != nil {
		return nil, err
	}
	for _, v := range in.Variants {
		if err := checkTargetScope(ctx, in.ProjectID, v.URL); err != nil {
			return nil, err
		}
	}
	doer := func(ctx context.Context, req httpprobe.Request) (diffprobe.Response, error) {
		res, err := httpprobe.DoRequest(ctx, req)
		if err != nil {
			return diffprobe.Response{}, err
		}
		return diffprobe.Response{Result: res}, nil
	}
	return diffprobe.Run(ctx, in.Baseline, in.Variants, in.Options, doer)
}

// --- JS 侦察 ---

// WebReconInput JS 端点与硬编码敏感信息侦察入参。
type WebReconInput struct {
	ProjectID int64             `json:"project_id" binding:"required"`
	BaseURL   string            `json:"base_url" binding:"required"`
	Headers   map[string]string `json:"headers"`
	Unauth    bool              `json:"unauth_sweep"`
	Bypass    bool              `json:"bypass"`
}

// WebReconResult 是 JS 侦察与未授权扫描的合并结果。
type WebReconResult struct {
	Recon *webrecon.Result `json:"recon"`
	Hits  []webrecon.Hit   `json:"unauth_hits,omitempty"`
}

func (s *ToolkitService) WebRecon(ctx context.Context, in WebReconInput) (*WebReconResult, error) {
	if err := checkTargetScope(ctx, in.ProjectID, in.BaseURL); err != nil {
		return nil, err
	}
	out := &WebReconResult{Recon: webrecon.JSReconFetch(in.BaseURL, in.Headers)}
	if in.Unauth {
		hits, _ := webrecon.UnauthSweep(ctx, in.BaseURL, webrecon.Dict(), in.Headers, in.Bypass)
		out.Hits = hits
	}
	return out, nil
}

// QuoteCheck 证据引文校验：引文必须是回执文本的子串（空白归一后）。
func (s *ToolkitService) QuoteCheck(quote, text string) (bool, error) {
	if strings.TrimSpace(text) == "" {
		return false, errors.New("text 不能为空")
	}
	return evidenceguard.QuoteFoundInText(quote, text), nil
}

// --- 验证剧本 ---

// PlaybookDir 返回验证剧本目录（可用 ZRE_VERIFY_PLAYBOOKS 覆盖）。
// 依次尝试进程工作目录与上一级目录，兼容「二进制在 src/backend 运行」和
// 「go test 在包目录运行」两种形态。
func PlaybookDir() string {
	candidates := []string{
		strings.TrimSpace(os.Getenv("ZRE_VERIFY_PLAYBOOKS")),
		filepath.Join("configs", "verify-playbooks"),
		filepath.Join("..", "configs", "verify-playbooks"),
	}
	for _, dir := range candidates {
		if dir == "" {
			continue
		}
		if st, err := os.Stat(dir); err == nil && st.IsDir() {
			return dir
		}
	}
	return filepath.Join("configs", "verify-playbooks")
}

// PlaybookInfo 是剧本列表项。
type PlaybookInfo struct {
	ID           string   `json:"id"`
	Name         string   `json:"name,omitempty"`
	VarsRequired []string `json:"vars_required,omitempty"`
	Steps        int      `json:"steps"`
	Note         string   `json:"note,omitempty"`
}

// Playbooks 列出内置验证剧本。
func (s *ToolkitService) Playbooks() ([]PlaybookInfo, []string, error) {
	books, errs := verifyrunner.LoadPlaybooksFromDir(PlaybookDir())
	out := make([]PlaybookInfo, 0, len(books))
	for _, pb := range books {
		out = append(out, PlaybookInfo{
			ID: pb.ID, Name: pb.Name, VarsRequired: pb.VarsRequired,
			Steps: len(pb.Steps), Note: pb.Note,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	errText := make([]string, 0, len(errs))
	for _, e := range errs {
		errText = append(errText, e.Error())
	}
	return out, errText, nil
}

// RunPlaybookInput 执行验证剧本的入参。
type RunPlaybookInput struct {
	ProjectID int64             `json:"project_id" binding:"required"`
	Playbook  string            `json:"playbook" binding:"required"`
	BaseURL   string            `json:"base_url" binding:"required"`
	Vars      map[string]string `json:"vars"`
}

// RunPlaybook 确定性执行一个内置剧本（只读探测，限速由剧本 limits 硬顶）。
func (s *ToolkitService) RunPlaybook(ctx context.Context, in RunPlaybookInput) (*verifyrunner.RunResult, error) {
	if err := checkTargetScope(ctx, in.ProjectID, in.BaseURL); err != nil {
		return nil, err
	}
	books, _ := verifyrunner.LoadPlaybooksFromDir(PlaybookDir())
	pb := books[in.Playbook]
	if pb == nil {
		return nil, errors.New("剧本不存在: " + in.Playbook)
	}
	vars := map[string]string{}
	for k, v := range in.Vars {
		vars[k] = v
	}
	if strings.TrimSpace(vars["host"]) == "" {
		if u, err := url.Parse(in.BaseURL); err == nil {
			vars["host"] = u.Hostname()
		}
	}
	return verifyrunner.Run(ctx, pb, verifyrunner.RunOptions{
		Vars: vars, BaseURL: in.BaseURL, Timeout: 20 * time.Second,
	})
}

// --- 企业数据源 ---

// EnterpriseProviders 返回企业数据源清单。
func (s *ToolkitService) EnterpriseProviders() []enterprise.ProviderKind {
	return enterprise.Registry
}

// EnterpriseSearchInput 企业数据源检索入参。
type EnterpriseSearchInput struct {
	Provider string            `json:"provider" binding:"required"`
	Config   map[string]string `json:"config"`
	Keyword  string            `json:"keyword" binding:"required"`
	Limit    int               `json:"limit"`
	Detail   bool              `json:"detail"`
}

// EnterpriseSearchResult 检索结果。
type EnterpriseSearchResult struct {
	Provider string                    `json:"provider"`
	Items    []enterprise.CompanyRef   `json:"items"`
	Detail   *enterprise.CompanyDetail `json:"detail,omitempty"`
}

// EnterpriseSearch 用网页端会话检索企业。凭据只在本次请求内使用，不落库。
func (s *ToolkitService) EnterpriseSearch(ctx context.Context, in EnterpriseSearchInput) (*EnterpriseSearchResult, error) {
	provider, err := enterprise.NewProvider(in.Provider, in.Config, in.Config["proxy_url"])
	if err != nil {
		return nil, err
	}
	limit := in.Limit
	if limit <= 0 || limit > 50 {
		limit = 10
	}
	items, err := provider.Search(ctx, in.Keyword, limit)
	if err != nil {
		return nil, err
	}
	out := &EnterpriseSearchResult{Provider: provider.Name(), Items: items}
	if in.Detail && len(items) > 0 {
		if d, derr := provider.Detail(ctx, items[0].ExtID); derr == nil {
			out.Detail = d
		}
	}
	return out, nil
}

// --- 命中报文提取 ---

// ExtractInput 手工提取入参（模板 id + 命中报文）。
type ExtractInput struct {
	TemplateID string `json:"template_id" binding:"required"`
	Target     string `json:"target"`
	MatchURL   string `json:"match_url"`
	Request    string `json:"request"`
	Response   string `json:"response"`
}

// Extract 按模板 id 分派提取器，解析命中报文里的凭据/备份/仓库信息。
func (s *ToolkitService) Extract(ctx context.Context, in ExtractInput) (*extractor.Finding, error) {
	ex := extractor.ForTemplate(in.TemplateID)
	if ex == nil {
		return nil, errors.New("该模板没有注册提取器: " + in.TemplateID)
	}
	return ex.Extract(ctx, &extractor.Ctx{
		Target: in.Target, MatchURL: in.MatchURL, TemplateID: in.TemplateID,
		Request: in.Request, Response: in.Response,
	})
}
