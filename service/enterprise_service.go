package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
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

// PurgeDeadEntities 清理注销/吊销主体及其关联候选（数字候选 + 域名候选）。
// 评估通知风险项「注销主体仍在列」的处置动作；返回各层清理数量。
func (s *EnterpriseService) PurgeDeadEntities(ctx context.Context, projectID int64) (entities, digitalCand, domainCand int64, err error) {
	r := repo.Default()
	if r == nil {
		return 0, 0, 0, errors.New("数据层未初始化")
	}
	rows, err := r.Pool().Query(ctx, `
select name from enterprise_entities
 where project_id = $1 and open_status ~ '注销|吊销|迁出'`, projectID)
	if err != nil {
		return 0, 0, 0, err
	}
	names := []string{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return 0, 0, 0, err
		}
		names = append(names, n)
	}
	rows.Close()
	if len(names) == 0 {
		return 0, 0, 0, nil
	}
	dtag, err := r.Pool().Exec(ctx,
		`delete from digital_candidates where project_id = $1 and entity_name = any($2)`,
		projectID, names)
	if err != nil {
		return 0, 0, 0, err
	}
	etag, err := r.Pool().Exec(ctx,
		`delete from enterprise_candidates where project_id = $1 and entity_name = any($2)`,
		projectID, names)
	if err != nil {
		return 0, 0, 0, err
	}
	digitalCand, domainCand = dtag.RowsAffected(), etag.RowsAffected()
	tag, err := r.Pool().Exec(ctx,
		`delete from enterprise_entities where project_id = $1 and name = any($2)`,
		projectID, names)
	if err != nil {
		return 0, 0, 0, err
	}
	return tag.RowsAffected(), digitalCand, domainCand, nil
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
	return newEnterpriseProvider(in.Provider, in.Cookie, in.Username, in.Password, in.ProxyURL)
}

// newEnterpriseProvider 按会话凭据构造数据源 adapter；数字资产采集与企业采集共用。
// 凭据字段级回落会话存储（请求体非空字段优先）。
func newEnterpriseProvider(provider, cookie, username, password, proxyURL string) (enterprise.Provider, error) {
	cookie, username, password = ResolveDatasourceSession(provider, cookie, username, password)
	cfg := map[string]string{
		"cookie":    strings.TrimSpace(cookie),
		"username":  strings.TrimSpace(username),
		"password":  password,
		"proxy_url": strings.TrimSpace(proxyURL),
	}
	return enterprise.NewProvider(provider, cfg, "")
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
		capWan, _ := enterprise.ParseCapitalWan(detail.RegisteredCapital)
		entity, uerr := r.Upsert(ctx, in.ProjectID, repo.EnterpriseInput{
			Name: name, LegalPerson: detail.LegalPerson, OpenStatus: detail.OpenStatus,
			CreditCode: detail.CreditCode, Address: detail.Address, Industry: detail.Industry,
			RegisteredCapital: detail.RegisteredCapital, RegisteredCapitalWan: capWan,
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
	// enterpriseSettings 持久化深度采集硬上限（data/enterprise/settings.json）。
	// 内存里的 collector 上限随 SetEnterpriseSettings 即时改写（热更新），
	// 文件只保证进程重启后仍是用户配的值。
	enterpriseSettings     *fileSettings
	enterpriseSettingsOnce sync.Once
)

// enterpriseSettingsStore 惰性初始化设置文件句柄。
// 注意：这里绝不能再拿 enterpriseCollectorMu——collector() 的首次初始化
// 在持锁临界区内调用本函数，重入同一把锁会自死锁（Go Mutex 不可重入）。
func enterpriseSettingsStore() *fileSettings {
	enterpriseSettingsOnce.Do(func() {
		root := os.Getenv("ZRE_DATA_DIR")
		if strings.TrimSpace(root) == "" {
			root = "data"
		}
		dir := filepath.Join(root, "enterprise")
		// SetSetting 走临时文件 + rename，目录缺失会让保存直接失败
		_ = os.MkdirAll(dir, 0o750)
		enterpriseSettings = newFileSettings(filepath.Join(dir, "settings.json"))
	})
	return enterpriseSettings
}

// applyEnterpriseLimits 把持久化的上限套到 collector 实例上（collector 创建时与设置更新时）。
func applyEnterpriseLimits(c *enterprise.Collector, fs *fileSettings) {
	maxDepth, maxNodes := 0, 0
	if v, _, err := fs.GetSetting("max_depth"); err == nil {
		if n, perr := strconv.Atoi(v); perr == nil {
			maxDepth = n
		}
	}
	if v, _, err := fs.GetSetting("max_nodes"); err == nil {
		if n, perr := strconv.Atoi(v); perr == nil {
			maxNodes = n
		}
	}
	c.SetLimits(maxDepth, maxNodes)
}

func (s *EnterpriseService) collector() (*enterprise.Collector, error) {
	r := repo.Default()
	if r == nil {
		return nil, errors.New("数据层未初始化")
	}
	enterpriseCollectorMu.Lock()
	defer enterpriseCollectorMu.Unlock()
	if enterpriseCollector == nil {
		enterpriseCollector = enterprise.NewCollector(r, log.Default())
		// 重启后沿用上次保存的层级/节点上限；没保存过就用内建缺省（3 层 / 200 节点）
		applyEnterpriseLimits(enterpriseCollector, enterpriseSettingsStore())
		enterpriseCollector.SetJobDoneHook(func(job enterprise.Job) {
			pid, perr := strconv.ParseInt(job.ProjectID, 10, 64)
			if perr != nil || pid <= 0 {
				return
			}
			SendCollectionAssessmentAsync(pid, "企业深度采集："+job.Keyword, true)
		})
	}
	return enterpriseCollector, nil
}

// EnterpriseSettings 返回深度采集的硬上限（层级/节点），前端配置入口与
// 深度采集弹窗共用这一份，保证表单 max 与后端钳制同一口径。
func (s *EnterpriseService) EnterpriseSettings() (map[string]any, error) {
	collector, err := s.collector()
	if err != nil {
		return nil, err
	}
	maxDepth, maxNodes := collector.Limits()
	return map[string]any{"max_depth": maxDepth, "max_nodes": maxNodes}, nil
}

// SetEnterpriseSettings 更新深度采集硬上限并持久化。热更新：内存即时生效，
// 后续 Discover/巡航启动的任务按新上限钳制，运行中任务不受影响；无需重启进程。
func (s *EnterpriseService) SetEnterpriseSettings(in map[string]any) error {
	collector, err := s.collector()
	if err != nil {
		return err
	}
	fs := enterpriseSettingsStore()
	updates := map[string]string{}
	for k, v := range in {
		switch k {
		case "max_depth", "max_nodes":
			n, ok := intValue(v)
			if !ok {
				return fmt.Errorf("%s 需要整数", k)
			}
			floor := 1
			if k == "max_depth" {
				floor = 1
			}
			if n < floor {
				return fmt.Errorf("%s 至少为 %d", k, floor)
			}
			if n > 10000 {
				return fmt.Errorf("%s 过大（上限 10000）", k)
			}
			updates[k] = strconv.Itoa(n)
		default:
			return fmt.Errorf("不支持的设置项: %s", k)
		}
	}
	// 先落盘再套用：落盘失败则不改内存，两边不会出现不一致
	for k, v := range updates {
		if err := fs.SetSetting(k, v); err != nil {
			return fmt.Errorf("保存设置失败: %w", err)
		}
	}
	maxDepth, maxNodes := collector.Limits()
	if v, ok := updates["max_depth"]; ok {
		maxDepth, _ = strconv.Atoi(v)
	}
	if v, ok := updates["max_nodes"]; ok {
		maxNodes, _ = strconv.Atoi(v)
	}
	collector.SetLimits(maxDepth, maxNodes)
	return nil
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
	// CollectDigital 顺带采集数字资产（APP/小程序/公众号/新媒体）入候选池；
	// nil 视为开启，仅当数据源支持时生效。
	CollectDigital *bool `json:"collect_digital"`
	// CollectGroup 展开集团成员（同集团兄弟公司）；nil 视为开启，仅当数据源支持时生效。
	CollectGroup *bool `json:"collect_group"`
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
	job := enterprise.Job{
		ProjectID:   strconv.FormatInt(in.ProjectID, 10),
		Owner:       in.Owner,
		Provider:    provider.Name(),
		Keyword:     name,
		Depth:       in.Depth,
		MaxNodes:    in.MaxNodes,
		ExpandGroup: in.CollectGroup == nil || *in.CollectGroup,
	}
	root := enterprise.CompanyRef{ExtID: extID, Name: name}
	if dp, ok := provider.(enterprise.DigitalAssetsProvider); ok && (in.CollectDigital == nil || *in.CollectDigital) {
		return collector.StartWithDigitalSink(ctx, provider, job, root, dp)
	}
	return collector.Start(ctx, provider, job, root)
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

// PromoteCandidates 候选域名批量转 domain 种子（人工确认通道）。
func (s *EnterpriseService) PromoteCandidates(ctx context.Context, projectID int64, ids []int64) (int, error) {
	r := repo.Default()
	if r == nil {
		return 0, errors.New("数据层未初始化")
	}
	return r.PromoteDomainCandidates(ctx, projectID, ids)
}

// RejectCandidates 批量忽略候选域名。
func (s *EnterpriseService) RejectCandidates(ctx context.Context, ids []int64) (int, error) {
	r := repo.Default()
	if r == nil {
		return 0, errors.New("数据层未初始化")
	}
	return r.RejectDomainCandidates(ctx, ids)
}
