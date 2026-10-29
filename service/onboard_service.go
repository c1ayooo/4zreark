package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/internal/enterprise"
	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/repo"
)

// 一键侦察编排 v2：一个输入（公司名称或域名）→ 多平台并行采集 → 归一去重 → 自动建任务。
//
//	公司名模式：每个数据源各自检索根企业并起 BFS（爱企查/天眼查的股权数据互补，
//	实测爱企查对外投资对部分会话返回 -23、天眼查能返回全量），实体/域名/种子的
//	归一去重由库层唯一键保证（enterprise_entities UNIQUE(project_id,name)、
//	enterprise_candidates UNIQUE(project_id,domain)、seeds UNIQUE(project_id,kind,value)）。
//	域名模式：域名先落种子 + 反查主办单位（工信部直查）→ 反查到公司再走公司名模式，
//	全部扫描任务在采集到终态后统一创建一次。
//
// 编排续延用轮询（collector 的 jobDoneHook 是全局单槽，被评估通知占用）。

const (
	onboardWatchInterval = 20 * time.Second
	onboardWatchDeadline = 6 * time.Hour
	onboardTargetCap     = 200
)

// onboardDefaultProviders 未指定数据源时的默认组合：天眼查（股权全量）+ 爱企查（备案/详情）。
var onboardDefaultProviders = []string{"tyc", "aqc"}

type ProjectOnboardInput struct {
	ProjectID int64 `json:"project_id"`
	// Keyword 公司名称或域名（自动识别；域名会先落种子并反查主办单位）
	Keyword string `json:"keyword"`
	// Providers 并行采集的数据源列表；空 = [tyc, aqc]
	Providers []string `json:"providers"`
	Depth     int      `json:"depth"`
	MaxNodes  int      `json:"max_nodes"`
	Cookie    string   `json:"cookie"`
	Username  string   `json:"username"`
	Password  string   `json:"password"`
	ProxyURL  string   `json:"proxy_url"`
	// CollectDigital/CollectGroup nil 视为开启（与 Discover 同语义）
	CollectDigital *bool `json:"collect_digital"`
	CollectGroup   *bool `json:"collect_group"`
}

// OnboardStart 一键侦察启动结果。
type OnboardStart struct {
	Mode         string           `json:"mode"` // company / domain
	Keyword      string           `json:"keyword"`
	Jobs         []enterprise.Job `json:"jobs"`          // 每个数据源一个 BFS 采集任务
	JobErrors    []string         `json:"job_errors"`    // 起采集失败的数据源（其余继续）
	Domain       string           `json:"domain"`        // 域名模式：已落种子的域名
	TasksCreated int              `json:"tasks_created"` // 域名模式降级路径：立即建的任务数
	ICPQueryID   string           `json:"icp_query_id,omitempty"`
}

func looksLikeDomain(s string) bool {
	if strings.ContainsAny(s, " ") || len([]rune(s)) > 80 {
		return false
	}
	if strings.Count(s, ".") < 1 {
		return false
	}
	if net.ParseIP(s) != nil {
		return false
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func normalizeOnboardProviders(in []string) []string {
	cleaned := []string{}
	seen := map[string]bool{}
	for _, p := range in {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		cleaned = append(cleaned, p)
	}
	if len(cleaned) == 0 {
		return append([]string{}, onboardDefaultProviders...)
	}
	return cleaned
}

// Onboard 启动一键侦察。立即返回；扫描任务在全部采集到终态后由后台续延统一创建。
func (s *EnterpriseService) Onboard(ctx context.Context, in ProjectOnboardInput) (*OnboardStart, error) {
	if in.ProjectID <= 0 {
		return nil, errors.New("project_id 必填")
	}
	keyword := strings.TrimSpace(in.Keyword)
	if keyword == "" {
		return nil, errors.New("公司名称或域名必填")
	}
	providers := normalizeOnboardProviders(in.Providers)

	r := repo.Default()
	if r == nil {
		return nil, errors.New("数据层未初始化")
	}

	if looksLikeDomain(strings.ToLower(keyword)) {
		return s.onboardByDomain(ctx, r, in, providers, strings.ToLower(keyword))
	}
	return s.onboardByCompany(ctx, r, in, providers, keyword)
}

// onboardByCompany 公司名模式：每个数据源检索根企业并起 BFS。
func (s *EnterpriseService) onboardByCompany(ctx context.Context, r *repo.Repo, in ProjectOnboardInput,
	providers []string, keyword string) (*OnboardStart, error) {

	out := &OnboardStart{Mode: "company", Keyword: keyword}
	search := EnterpriseCollectInput{
		ProjectID: in.ProjectID, Keyword: keyword,
		Cookie: in.Cookie, Username: in.Username, Password: in.Password, ProxyURL: in.ProxyURL,
		Limit: 1,
	}
	for _, provider := range providers {
		refs, err := s.SearchProvider(ctx, withProvider(search, provider))
		if err != nil {
			out.JobErrors = append(out.JobErrors, fmt.Sprintf("%s 检索失败: %v", provider, err))
			continue
		}
		if len(refs) == 0 {
			out.JobErrors = append(out.JobErrors, fmt.Sprintf("%s 未检索到「%s」", provider, keyword))
			continue
		}
		job, err := s.Discover(ctx, EnterpriseDiscoverInput{
			ProjectID: in.ProjectID, Provider: provider,
			ExtID: refs[0].ExtID, Name: firstNonEmptyStr(refs[0].Name, keyword),
			Depth: in.Depth, MaxNodes: in.MaxNodes,
			Cookie: in.Cookie, Username: in.Username, Password: in.Password, ProxyURL: in.ProxyURL,
			CollectDigital: in.CollectDigital, CollectGroup: in.CollectGroup,
		})
		if err != nil {
			out.JobErrors = append(out.JobErrors, fmt.Sprintf("%s 采集启动失败: %v", provider, err))
			continue
		}
		out.Jobs = append(out.Jobs, job)
	}
	if len(out.Jobs) == 0 {
		return nil, fmt.Errorf("所有数据源启动失败：%s", strings.Join(out.JobErrors, "；"))
	}
	go watchOnboardJobs(out.Jobs, in.ProjectID, keyword)
	return out, nil
}

// onboardByDomain 域名模式：域名落种子 → 工信部反查主办单位 → 反查到公司走多平台
// BFS；反查失败则降级为立即按现有种子建任务（输入不丢失）。
func (s *EnterpriseService) onboardByDomain(ctx context.Context, r *repo.Repo, in ProjectOnboardInput,
	providers []string, domain string) (*OnboardStart, error) {

	out := &OnboardStart{Mode: "domain", Keyword: domain, Domain: domain}

	// 域名先落种子（唯一键兜底重复）
	if err := r.Seeds().CreateSeed(ctx, &repo.Seed{ProjectID: in.ProjectID, Kind: "domain", Value: domain, Enabled: true}); err != nil {
		// 已存在等唯一键冲突不致命：目标里带上即可
		log.Printf("[onboard] 种子 %s 已存在或写入失败: %v", domain, err)
	}

	// 工信部反查主办单位（同步直查，限两页；失败不阻塞主流程）
	company := ""
	icp := NewICPService()
	filings, _, err := icp.QueryDirect(ctx, domain, 1, 40, 2)
	if err != nil {
		log.Printf("[onboard] 工信部反查 %s 失败: %v", domain, err)
		out.JobErrors = append(out.JobErrors, fmt.Sprintf("工信部反查失败: %v", err))
	} else {
		for _, f := range filings {
			if strings.TrimSpace(f.UnitName) != "" {
				company = strings.TrimSpace(f.UnitName)
				break
			}
		}
	}

	if company == "" {
		// 降级：没反查到公司 → 立即按现有种子建扫描任务（至少域名本身被扫到）
		created, errs := createOnboardFollowupTasks(ctx, in.ProjectID, domain)
		out.TasksCreated = created
		for _, e := range errs {
			out.JobErrors = append(out.JobErrors, e.Error())
		}
		log.Printf("[onboard] 域名 %s 未反查到主办单位，已直接创建 %d 个扫描任务", domain, created)
		return out, nil
	}

	// 反查到公司：走多平台公司名模式（域名的种子已在，扫描任务在采集终态后统一创建）
	out.Keyword = company
	companyIn := in
	companyIn.Keyword = company
	start, err := s.onboardByCompany(ctx, r, companyIn, providers, company)
	if err != nil {
		// 多平台全挂 → 降级立即建任务
		created, errs := createOnboardFollowupTasks(ctx, in.ProjectID, domain)
		out.TasksCreated = created
		for _, e := range errs {
			out.JobErrors = append(out.JobErrors, e.Error())
		}
		out.JobErrors = append(out.JobErrors, err.Error())
		return out, nil
	}
	out.Jobs = start.Jobs
	out.JobErrors = append(out.JobErrors, start.JobErrors...)
	return out, nil
}

// watchOnboardJobs 等全部采集任务到终态后创建一轮扫描任务（只建一次）。
// 部分取消/部分失败不影响其余成果：按已有种子建，宁可少扫不漏建。
func watchOnboardJobs(jobs []enterprise.Job, projectID int64, keyword string) {
	r := repo.Default()
	if r == nil {
		return
	}
	deadline := time.Now().Add(onboardWatchDeadline)
	ctx := context.Background()
	pending := map[string]bool{}
	for _, j := range jobs {
		pending[j.ID] = true
	}
	var lastErrs []string
	for len(pending) > 0 && time.Now().Before(deadline) {
		time.Sleep(onboardWatchInterval)
		for id := range pending {
			job, err := r.GetEnterpriseJob(ctx, id)
			if err != nil {
				continue
			}
			if job.Status != "running" {
				if job.Status == "error" && job.Error != "" {
					lastErrs = append(lastErrs, fmt.Sprintf("%s(%s)：%s", job.Provider, job.Keyword, job.Error))
				}
				delete(pending, id)
			}
		}
	}
	if len(pending) > 0 {
		log.Printf("[onboard] 采集任务 %v 超过 %s 未到终态，放弃续延", pendingKeys(pending), onboardWatchDeadline)
		return
	}

	allCanceled := true
	for _, j := range jobs {
		if j.Status == "canceled" {
			continue
		}
		// jobs 快照里的 Status 是启动态；重新读终态判断
		job, err := r.GetEnterpriseJob(ctx, j.ID)
		if err == nil && job.Status != "canceled" {
			allCanceled = false
		}
	}
	if allCanceled {
		log.Printf("[onboard] 全部采集任务被取消，不创建扫描任务")
		return
	}

	created, _ := createOnboardFollowupTasks(ctx, projectID, keyword)
	errs := lastErrs
	summary := fmt.Sprintf("一键侦察（%s）：多平台采集完成，自动创建 %d 个扫描任务", keyword, created)
	if len(lastErrs) > 0 {
		summary += fmt.Sprintf("；采集异常 %d 条", len(lastErrs))
	}
	if len(errs) > 0 {
		summary += fmt.Sprintf("；%d 条任务创建失败", len(errs))
	}
	for _, e := range errs {
		log.Printf("[onboard] %v", e)
	}
	SendCollectionAssessmentAsync(projectID, summary, false)
	log.Printf("[onboard] %s", summary)
}

func pendingKeys(pending map[string]bool) []string {
	keys := make([]string, 0, len(pending))
	for k := range pending {
		keys = append(keys, k)
	}
	return keys
}

func withProvider(in EnterpriseCollectInput, provider string) EnterpriseCollectInput {
	in.Provider = provider
	return in
}


// createOnboardFollowupTasks 按项目 domain 种子批量创建后续扫描任务。
// 种子为空（公司没有可解析的备案域名等）返回 (0, nil)，不报错。
func createOnboardFollowupTasks(ctx context.Context, projectID int64, keyword string) (int, []error) {
	r := repo.Default()
	if r == nil {
		return 0, []error{errors.New("数据层未初始化")}
	}
	seeds, err := r.Seeds().ListSeeds(ctx, projectID)
	if err != nil {
		return 0, []error{fmt.Errorf("读取种子失败: %w", err)}
	}
	targets := make([]string, 0, len(seeds))
	seen := map[string]bool{}
	for _, sd := range seeds {
		if sd.Kind != "domain" || !sd.Enabled || seen[sd.Value] {
			continue
		}
		seen[sd.Value] = true
		targets = append(targets, sd.Value)
		if len(targets) >= onboardTargetCap {
			break
		}
	}
	if len(targets) == 0 {
		log.Printf("[onboard] 项目 %d 没有可用 domain 种子，跳过后续任务创建", projectID)
		return 0, nil
	}

	svc := NewTaskService()
	base := "一键侦察·" + keyword
	specs := []struct {
		name string
		typ  models.TaskType
		conf models.TaskConfig
	}{
		{
			name: base + "·全流水线", typ: models.TaskTypeCustom,
			conf: models.TaskConfig{
				ScanTypes:     []string{"subdomain", "port_scan", "fingerprint", "crawler", "dir_scan", "vuln_scan"},
				PortScanMode:  "top2000",
				TargetDelayMs: 200,
				RatePerSec:    20,
			},
		},
		{name: base + "·服务识别", typ: models.TaskTypeServiceID},
		{name: base + "·暴露面探测", typ: models.TaskTypeExposure},
		{name: base + "·存量线索", typ: models.TaskTypeClueHunt},
	}

	created, errs := 0, []error{}
	for _, spec := range specs {
		task := &models.Task{
			ProjectID:   projectID,
			Name:        spec.name,
			Description: "一键侦察自动创建：多平台企业采集（" + keyword + "）完成后按项目种子生成",
			Type:        spec.typ,
			Targets:     targets,
			TargetType:  "domain",
			Config:      spec.conf,
		}
		if err := svc.CreateTask(task); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", spec.name, err))
			continue
		}
		created++
	}
	return created, errs
}
