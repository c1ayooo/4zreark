package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/repo"
)

// AssetService 是资产治理域的读侧与导入入口。
// handler 不再直接碰 repo：分层规矩和 users/tasks 保持一致，越界的 SQL 只能出现在 repo 包里。
type AssetService struct{}

func NewAssetService() *AssetService { return &AssetService{} }

func (s *AssetService) repo() (*repo.AssetRepo, error) {
	if repo.Default() == nil {
		return nil, errors.New("数据层未初始化")
	}
	return repo.NewAssetRepo(), nil
}

// Overview 是首页统计：原始记录与归并站点分开计，口径见 v2 §2.3。
func (s *AssetService) Overview(ctx context.Context) (*repo.Overview, error) {
	a, err := s.repo()
	if err != nil {
		return nil, err
	}
	return a.Overview(ctx)
}

func (s *AssetService) ListProjects(ctx context.Context) ([]*repo.Project, error) {
	a, err := s.repo()
	if err != nil {
		return nil, err
	}
	return a.ListProjects(ctx)
}

func (s *AssetService) GetProject(ctx context.Context, id int64) (*repo.Project, error) {
	a, err := s.repo()
	if err != nil {
		return nil, err
	}
	return a.GetProject(ctx, id)
}

var projectCodePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// normalizeProjectInput 把表单输入收口成可落库的值。code 只在新建时校验。
func normalizeProjectInput(in repo.ProjectInput, creating bool) (repo.ProjectInput, error) {
	in.Code = strings.TrimSpace(in.Code)
	in.Name = strings.TrimSpace(in.Name)
	in.Region = strings.TrimSpace(in.Region)
	in.Description = strings.TrimSpace(in.Description)
	in.HomepageURL = strings.TrimSpace(in.HomepageURL)
	in.Color = strings.TrimSpace(in.Color)

	if creating && !projectCodePattern.MatchString(in.Code) {
		return in, errors.New("项目编码只能包含字母、数字、下划线和短横线，长度 1..64")
	}
	if in.Name == "" || len([]rune(in.Name)) > 120 {
		return in, errors.New("项目名称必填，长度不超过 120")
	}
	if in.Region == "" {
		in.Region = "domestic"
	}
	if len([]rune(in.Region)) > 32 {
		return in, errors.New("地区长度不超过 32")
	}
	if len([]rune(in.Description)) > 4000 {
		return in, errors.New("项目说明不超过 4000 字")
	}
	if in.HomepageURL != "" {
		u, err := url.Parse(in.HomepageURL)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return in, errors.New("主页地址需要是完整的 URL")
		}
	}
	if in.CycleDays == 0 {
		in.CycleDays = 30
	}
	if in.CycleDays < 1 || in.CycleDays > 3650 {
		return in, errors.New("采集周期需在 1..3650 天")
	}
	return in, nil
}

func (s *AssetService) CreateProject(ctx context.Context, in repo.ProjectInput) (*repo.Project, error) {
	a, err := s.repo()
	if err != nil {
		return nil, err
	}
	in, err = normalizeProjectInput(in, true)
	if err != nil {
		return nil, err
	}
	return a.CreateProject(ctx, in)
}

func (s *AssetService) UpdateProject(ctx context.Context, id int64, in repo.ProjectInput) (*repo.Project, error) {
	a, err := s.repo()
	if err != nil {
		return nil, err
	}
	in, err = normalizeProjectInput(in, false)
	if err != nil {
		return nil, err
	}
	return a.UpdateProject(ctx, id, in)
}

func (s *AssetService) SetProjectPaused(ctx context.Context, id int64, paused bool, reason string) (*repo.Project, error) {
	a, err := s.repo()
	if err != nil {
		return nil, err
	}
	reason = strings.TrimSpace(reason)
	if paused && reason == "" {
		reason = "手动暂停"
	}
	if !paused {
		reason = ""
	}
	return a.SetProjectPaused(ctx, id, paused, reason)
}

// GetAssetDetail 是资产详情：站点 + 入口 + 验证历史 + 指纹命中 + 原始记录 + 事件 + 关系证据。
func (s *AssetService) GetAssetDetail(ctx context.Context, id int64) (*repo.AssetDetail, error) {
	a, err := s.repo()
	if err != nil {
		return nil, err
	}
	if id <= 0 {
		return nil, repo.ErrNotFound
	}
	return a.GetAssetDetail(ctx, id)
}

// ListAssets 是资产列表：view × kind × catalog 三层正交维度 + DSL 查询串。
// DSL 语法错误会带上出错位置返回；结构化参数非法则静默回落缺省（v4 §11.4 的容错边界）。
func (s *AssetService) ListAssets(ctx context.Context, q repo.AssetQuery) (*repo.AssetPage, error) {
	a, err := s.repo()
	if err != nil {
		return nil, err
	}
	switch {
	case q.PageSize < 1:
		q.PageSize = 20
	case q.PageSize > 500:
		// 硬上限 500：请求 1000 返回 500 条，而不是回落到 20
		q.PageSize = 500
	}
	return a.ListAssets(ctx, q)
}

// ListTaskSites 是任务详情「本任务资产」页签的数据源：
// 按 raw_records.task_id 找出该任务贡献过证据的站点。
func (s *AssetService) ListTaskSites(ctx context.Context, taskID string, page, pageSize int, q string) ([]repo.TaskSite, int64, error) {
	a, err := s.repo()
	if err != nil {
		return nil, 0, err
	}
	return a.ListTaskSites(ctx, taskID, page, pageSize, q)
}

// CheckQuery 只编译不查库，供前端语法框实时反馈。
func (s *AssetService) CheckQuery(q string) (string, error) {
	expr, _, err := repo.BuildAssetWhere(q)
	if err != nil {
		return "", err
	}
	return expr, nil
}

// Ingest 是治理域的唯一写入口：扫描结果、CSV、API 导入都走这里，
// 内部仍是 ImportRecords（原始记录 + 归并站点 + 入口 + 事件，一个事务）。
func (s *AssetService) Ingest(ctx context.Context, projectID int64, source string, records []repo.RawRecord) (*repo.ImportResult, error) {
	return s.ImportRecords(ctx, projectID, source, records)
}

// ImportRecords 批量导入原始记录并归并。上限 5000 条，超过请分片调用。
func (s *AssetService) ImportRecords(ctx context.Context, projectID int64, source string, records []repo.RawRecord) (*repo.ImportResult, error) {
	a, err := s.repo()
	if err != nil {
		return nil, err
	}
	if projectID <= 0 {
		return nil, errors.New("project_id 必填")
	}
	if len(records) == 0 || len(records) > 5000 {
		return nil, fmt.Errorf("records 数量需在 1..5000，收到 %d", len(records))
	}
	if source == "" {
		source = "api"
	}
	return a.ImportRecords(ctx, projectID, source, records)
}

// VerifySite 是人工判定（不发网络请求）。真实探测走 VerifyService.ProbeSite。
func (s *AssetService) VerifySite(ctx context.Context, siteID int64, reachable bool, code int, reason string) error {
	a, err := s.repo()
	if err != nil {
		return err
	}
	return a.VerifySite(ctx, siteID, reachable, code, reason)
}

func (s *AssetService) RecentEvents(ctx context.Context, limit int) ([]map[string]any, error) {
	return s.RecentEventsByProject(ctx, 0, limit)
}

// RecentEventsByProject 是事件时间线的项目收口版本；projectID=0 表示全部项目。
func (s *AssetService) RecentEventsByProject(ctx context.Context, projectID int64, limit int) ([]map[string]any, error) {
	a, err := s.repo()
	if err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	s.maybePruneEvents(ctx, a)
	return a.RecentEventsByProject(ctx, projectID, limit)
}

var (
	eventPruneMu   sync.Mutex
	lastEventPrune time.Time
)

// maybePruneEvents 事件保留策略（最多 1 万条 / 7 天），每小时最多跑一次。
// 挂在事件读取路径上是刻意的：没有事件被查看时也不需要清理。
func (s *AssetService) maybePruneEvents(ctx context.Context, a *repo.AssetRepo) {
	eventPruneMu.Lock()
	defer eventPruneMu.Unlock()
	if !lastEventPrune.IsZero() && time.Since(lastEventPrune) < time.Hour {
		return
	}
	lastEventPrune = time.Now()
	n, err := a.PruneEvents(ctx, 10000, 7)
	if err != nil {
		log.Printf("[AssetService] 清理资产事件失败: %v", err)
		return
	}
	if n > 0 {
		log.Printf("[AssetService] 清理资产事件 %d 条（保留 10000 条 / 7 天）", n)
	}
}

// IconClusters 按图标聚类（T4 第二步）。
func (s *AssetService) IconClusters(ctx context.Context, projectID int64, q string, page, pageSize int) ([]*repo.IconCluster, int64, error) {
	r := repo.Default()
	if r == nil {
		return nil, 0, errors.New("数据层未初始化")
	}
	return r.Clusters().IconClusters(ctx, projectID, q, page, pageSize)
}

// TechClusters 按技术栈聚类（T4 第二步）。
func (s *AssetService) TechClusters(ctx context.Context, projectID int64, q string, page, pageSize int) ([]*repo.TechCluster, int64, error) {
	r := repo.Default()
	if r == nil {
		return nil, 0, errors.New("数据层未初始化")
	}
	return r.Clusters().TechClusters(ctx, projectID, q, page, pageSize)
}

// IconBytes 读一张图标的原始字节（给 /api/asset-icons/:sha256 用）。
func (s *AssetService) IconBytes(ctx context.Context, sha256 string) ([]byte, string, error) {
	r := repo.Default()
	if r == nil {
		return nil, "", errors.New("数据层未初始化")
	}
	icon, err := r.Clusters().GetIcon(ctx, sha256)
	if err != nil {
		return nil, "", err
	}
	return icon.Data, icon.ContentType, nil
}

// AssetGraph 资产星图：一次取回项目 → 根域名 → 子域名 → IP → 服务 → 端点。
// 与列表接口的区别是不分页，但有站点上限（repo 层控制并在响应里标记 truncated）。
func (s *AssetService) AssetGraph(ctx context.Context, q repo.AssetQuery) (*repo.AssetGraphData, error) {
	a, err := s.repo()
	if err != nil {
		return nil, err
	}
	return a.BuildAssetGraph(ctx, q)
}

// CrawledEndpoint 是爬虫产出的一条 URL。
type CrawledEndpoint struct {
	URL        string `json:"url"`
	Method     string `json:"method"`
	StatusCode int    `json:"status_code"`
}

// SaveCrawledRoutes 把爬虫结果按 host 归到站点，写入 site_routes。
// 匹配不到站点的 URL 直接跳过——路由必须挂在资产上，不凭空建站点。
func (s *AssetService) SaveCrawledRoutes(source string, urls []CrawledEndpoint) (int, int, error) {
	a, err := s.repo()
	if err != nil {
		return 0, 0, err
	}

	// 按 host 分组
	type group struct {
		host   string
		routes []repo.RouteInput
	}
	byHost := map[string]*group{}
	for _, u := range urls {
		raw := u.URL
		path, ok := repo.ParseRouteURL(raw, u.Method)
		if !ok {
			continue
		}
		parsed, err := url.Parse(raw)
		if err != nil {
			continue
		}
		host := parsed.Hostname()
		if host == "" {
			continue
		}
		g := byHost[host]
		if g == nil {
			g = &group{host: host}
			byHost[host] = g
		}
		g.routes = append(g.routes, repo.RouteInput{
			Method:     u.Method,
			Path:       path,
			StatusCode: u.StatusCode,
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sites, routes := 0, 0
	for _, g := range byHost {
		siteID, projectID, err := a.SiteIDByHostAny(ctx, g.host)
		if err != nil {
			continue // 没有对应站点：跳过
		}
		n, err := a.UpsertSiteRoutes(ctx, siteID, projectID, source, g.routes)
		if err != nil {
			return sites, routes, err
		}
		sites++
		routes += n
	}
	return sites, routes, nil
}

// ListSiteRoutes 某站点已采集的路由。limit 由 repo 夹到 1..1000。
func (s *AssetService) ListSiteRoutes(siteID int64, limit int) ([]*repo.SiteRoute, error) {
	a, err := s.repo()
	if err != nil {
		return nil, err
	}
	ctx, cancel := dbCtx()
	defer cancel()
	return a.ListSiteRoutes(ctx, siteID, limit)
}
