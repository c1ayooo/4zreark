package service

import (
	"context"
	"errors"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/internal/enterprise"
	"github.com/c1ayooo/4zreark/repo"
)

// EnterpriseService 企业身份线索：手工维护 + 企业数据源采集 + 与数字资产名单对齐。
// 采集只产生线索，不创建站点、不触发 DNS/扫描。
type EnterpriseService struct{}

func NewEnterpriseService() *EnterpriseService { return &EnterpriseService{} }

func (s *EnterpriseService) repo() (repo.EnterpriseRepo, error) {
	r := repo.Default()
	if r == nil {
		return nil, errors.New("数据层未初始化")
	}
	return r.Enterprises(), nil
}

func (s *EnterpriseService) List(ctx context.Context, f repo.EnterpriseFilter) ([]*repo.EnterpriseEntity, int64, error) {
	r, err := s.repo()
	if err != nil {
		return nil, 0, err
	}
	return r.List(ctx, f)
}

func (s *EnterpriseService) Get(ctx context.Context, id int64) (*repo.EnterpriseEntity, error) {
	r, err := s.repo()
	if err != nil {
		return nil, err
	}
	return r.Get(ctx, id)
}

func (s *EnterpriseService) Upsert(ctx context.Context, projectID int64, in repo.EnterpriseInput) (*repo.EnterpriseEntity, error) {
	r, err := s.repo()
	if err != nil {
		return nil, err
	}
	return r.Upsert(ctx, projectID, in)
}

func (s *EnterpriseService) Delete(ctx context.Context, id int64) error {
	r, err := s.repo()
	if err != nil {
		return err
	}
	ok, err := r.Delete(ctx, id)
	if err != nil {
		return err
	}
	if !ok {
		return repo.ErrNotFound
	}
	return nil
}

func (s *EnterpriseService) Import(ctx context.Context, projectID int64, rows []repo.EnterpriseInput, source string) (int, int, error) {
	r, err := s.repo()
	if err != nil {
		return 0, 0, err
	}
	if len(rows) == 0 {
		return 0, 0, errors.New("没有可导入的企业线索")
	}
	if len(rows) > 1000 {
		return 0, 0, errors.New("单次最多导入 1000 条")
	}
	return r.UpsertMany(ctx, projectID, rows, source)
}

func (s *EnterpriseService) AlignedAssets(ctx context.Context, projectID int64, name string) ([]*repo.DigitalAsset, error) {
	r, err := s.repo()
	if err != nil {
		return nil, err
	}
	return r.AlignedDigitalAssets(ctx, projectID, name)
}

// Providers 返回已接入的企业数据源清单（含未校准的 qcc）。
func (s *EnterpriseService) Providers() []enterprise.ProviderKind {
	return enterprise.Registry
}

type EnterpriseCollectInput struct {
	ProjectID int64  `json:"project_id"`
	Provider  string `json:"provider"`
	Keyword   string `json:"keyword"`
	Limit     int    `json:"limit"`
	Cookie    string `json:"cookie"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	ProxyURL  string `json:"proxy_url"`
}

func (in EnterpriseCollectInput) buildProvider() (enterprise.Provider, error) {
	cfg := map[string]string{
		"cookie":    strings.TrimSpace(in.Cookie),
		"username":  strings.TrimSpace(in.Username),
		"password":  in.Password,
		"proxy_url": strings.TrimSpace(in.ProxyURL),
	}
	return enterprise.NewProvider(in.Provider, cfg, "")
}

type EnterpriseCollectResult struct {
	Provider string                   `json:"provider"`
	Keyword  string                   `json:"keyword"`
	Found    int                      `json:"found"`
	Entities []*repo.EnterpriseEntity `json:"entities"`
	Domains  []repo.EnterpriseDomain  `json:"domains"`
	Warnings []string                 `json:"warnings,omitempty"`
}

// Collect 调用企业数据源做一次检索，并把结果落成线索；域名只回显，不入站点库。
func (s *EnterpriseService) Collect(ctx context.Context, in EnterpriseCollectInput) (*EnterpriseCollectResult, error) {
	if in.ProjectID <= 0 {
		return nil, errors.New("project_id 必填")
	}
	keyword := strings.TrimSpace(in.Keyword)
	if keyword == "" {
		return nil, errors.New("检索关键词（企业名）必填")
	}
	limit := in.Limit
	if limit <= 0 || limit > 10 {
		limit = 5
	}
	provider, err := in.buildProvider()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	refs, err := provider.Search(ctx, keyword, limit)
	if err != nil {
		return nil, err
	}
	out := &EnterpriseCollectResult{
		Provider: provider.Name(), Keyword: keyword, Found: len(refs),
		Entities: []*repo.EnterpriseEntity{}, Domains: []repo.EnterpriseDomain{},
	}
	r, err := s.repo()
	if err != nil {
		return nil, err
	}
	for _, ref := range refs {
		detail, derr := provider.Detail(ctx, ref.ExtID)
		if derr != nil || detail == nil {
			out.Warnings = append(out.Warnings, ref.Name+"：详情获取失败")
			continue
		}
		icps := map[string]bool{}
		domains := make([]repo.EnterpriseDomain, 0, len(detail.Domains))
		for _, d := range detail.Domains {
			domains = append(domains, repo.EnterpriseDomain{
				Domain: d.Domain, Site: d.Site, ICP: d.ICP, Evidence: d.Evidence,
			})
			if d.ICP != "" {
				icps[d.ICP] = true
			}
			out.Domains = append(out.Domains, repo.EnterpriseDomain{
				Domain: d.Domain, Site: d.Site, ICP: d.ICP, Evidence: d.Evidence,
			})
		}
		icpList := make([]string, 0, len(icps))
		for v := range icps {
			icpList = append(icpList, v)
		}
		name := detail.Name
		if strings.TrimSpace(name) == "" {
			name = ref.Name
		}
		entity, uerr := r.Upsert(ctx, in.ProjectID, repo.EnterpriseInput{
			Name: name, LegalPerson: detail.LegalPerson, OpenStatus: detail.OpenStatus,
			ICPNumbers: icpList, Domains: domains, Source: provider.Name(),
			Status: "unverified", Notes: "来自 " + provider.Name() + " 检索",
		})
		if uerr != nil {
			out.Warnings = append(out.Warnings, name+"：线索入库失败")
			continue
		}
		out.Entities = append(out.Entities, entity)
	}
	return out, nil
}

// ---------------------------------------------------------------- 深度采集（BFS）

var (
	enterpriseCollectorMu sync.Mutex
	enterpriseCollector   *enterprise.Collector
)

func (s *EnterpriseService) collector() (*enterprise.Collector, error) {
	r := repo.Default()
	if r == nil {
		return nil, errors.New("数据层未初始化")
	}
	enterpriseCollectorMu.Lock()
	defer enterpriseCollectorMu.Unlock()
	if enterpriseCollector == nil {
		enterpriseCollector = enterprise.NewCollector(r, log.Default())
	}
	return enterpriseCollector, nil
}

// SearchProvider 只做企业搜索，不落库；供深度采集前的候选选择。
func (s *EnterpriseService) SearchProvider(ctx context.Context, in EnterpriseCollectInput) ([]enterprise.CompanyRef, error) {
	keyword := strings.TrimSpace(in.Keyword)
	if keyword == "" {
		return nil, errors.New("检索关键词（企业名）必填")
	}
	limit := in.Limit
	if limit <= 0 || limit > 20 {
		limit = 10
	}
	provider, err := in.buildProvider()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return provider.Search(ctx, keyword, limit)
}

type EnterpriseDiscoverInput struct {
	ProjectID int64  `json:"project_id"`
	Provider  string `json:"provider"`
	ExtID     string `json:"ext_id"`
	Name      string `json:"name"`
	Owner     string `json:"-"`
	Depth     int    `json:"depth"`
	MaxNodes  int    `json:"max_nodes"`
	Cookie    string `json:"cookie"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	ProxyURL  string `json:"proxy_url"`
}

// Discover 启动后台 BFS 采集：分支/投资逐层展开，域名进入候选资产。
// 采集只写 enterprise_entities / enterprise_candidates，不创建站点、不触发扫描。
func (s *EnterpriseService) Discover(ctx context.Context, in EnterpriseDiscoverInput) (enterprise.Job, error) {
	if in.ProjectID <= 0 {
		return enterprise.Job{}, errors.New("project_id 必填")
	}
	extID := strings.TrimSpace(in.ExtID)
	name := strings.TrimSpace(in.Name)
	if extID == "" || len(extID) > 64 || len(name) > 200 {
		return enterprise.Job{}, errors.New("ext_id 必填且不超过 64 字节，企业名不超过 200 字")
	}
	provider, err := EnterpriseCollectInput{
		ProjectID: in.ProjectID, Provider: in.Provider, Keyword: name,
		Cookie: in.Cookie, Username: in.Username, Password: in.Password, ProxyURL: in.ProxyURL,
	}.buildProvider()
	if err != nil {
		return enterprise.Job{}, err
	}
	collector, err := s.collector()
	if err != nil {
		return enterprise.Job{}, err
	}
	return collector.Start(ctx, provider, enterprise.Job{
		ProjectID: strconv.FormatInt(in.ProjectID, 10),
		Owner:     in.Owner,
		Provider:  provider.Name(),
		Keyword:   name,
		Depth:     in.Depth,
		MaxNodes:  in.MaxNodes,
	}, enterprise.CompanyRef{ExtID: extID, Name: name})
}

func (s *EnterpriseService) Jobs(ctx context.Context, projectID int64, limit int) ([]enterprise.Job, error) {
	r := repo.Default()
	if r == nil {
		return nil, errors.New("数据层未初始化")
	}
	return r.ListEnterpriseJobs(ctx, projectID, limit)
}

func (s *EnterpriseService) Job(ctx context.Context, id string) (enterprise.Job, error) {
	r := repo.Default()
	if r == nil {
		return enterprise.Job{}, errors.New("数据层未初始化")
	}
	return r.GetEnterpriseJob(ctx, id)
}

func (s *EnterpriseService) CancelJob(id string) (bool, error) {
	collector, err := s.collector()
	if err != nil {
		return false, err
	}
	return collector.Cancel(id), nil
}

func (s *EnterpriseService) Candidates(ctx context.Context, projectID int64, status string, limit int) ([]enterprise.CandidateAsset, error) {
	r := repo.Default()
	if r == nil {
		return nil, errors.New("数据层未初始化")
	}
	return r.ListEnterpriseCandidates(ctx, projectID, status, limit)
}
