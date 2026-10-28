package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/internal/enterprise"
	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/repo"
)

// 一键侦察编排（项目冷启动）：公司名 → 企业 BFS 采集（子公司/分支域名
// 备案确认后自动转种子）→ 采集到终态后自动创建后续扫描任务：
//   1) custom 全流水线（子域/端口/指纹/爬虫/目录/漏洞），目标 = 项目 domain 种子；
//   2) service_identify / exposure_scan / clue_hunt 三个独立执行器任务（同目标）。
//
// 为什么用轮询而不是 collector 的 jobDoneHook：钩子是全局单槽（评估通知占用），
// 编排的续延挂轮询上互不影响；上下文用 Background，请求结束后继续生效。

// onboardWatchInterval / onboardWatchDeadline 采集续延的轮询节奏与总时限
//（BFS 3 层 200 节点 800ms 节流，实测十分钟级；6 小时是极端兜底）。
const (
	onboardWatchInterval = 20 * time.Second
	onboardWatchDeadline = 6 * time.Hour
	// onboardTargetCap 单任务目标数上限：种子异常膨胀时不放大扫描面。
	onboardTargetCap = 200
)

type ProjectOnboardInput struct {
	ProjectID int64  `json:"project_id"`
	Provider  string `json:"provider"`
	// Keyword 公司名称；同时是根企业搜索关键词
	Keyword string `json:"keyword"`
	// ExtID/Name 已在候选列表选定时直接传入，跳过搜索
	ExtID string `json:"ext_id"`
	Name  string `json:"name"`
	Depth int    `json:"depth"`
	MaxNodes int `json:"max_nodes"`
	Cookie   string `json:"cookie"`
	Username string `json:"username"`
	Password string `json:"password"`
	ProxyURL string `json:"proxy_url"`
	// CollectDigital/CollectGroup nil 视为开启（与 Discover 同语义）
	CollectDigital *bool `json:"collect_digital"`
	CollectGroup   *bool `json:"collect_group"`
}

// Onboard 启动企业采集并挂上「采集完成 → 自动建后续任务」的续延。
// 立即返回采集 job（status=running）；后续任务的创建进度看任务列表与通知。
func (s *EnterpriseService) Onboard(ctx context.Context, in ProjectOnboardInput) (enterprise.Job, error) {
	if in.ProjectID <= 0 {
		return enterprise.Job{}, errors.New("project_id 必填")
	}
	keyword := strings.TrimSpace(in.Keyword)
	if keyword == "" {
		return enterprise.Job{}, errors.New("公司名称必填")
	}

	ref := enterprise.CompanyRef{ExtID: strings.TrimSpace(in.ExtID), Name: strings.TrimSpace(in.Name)}
	if ref.ExtID == "" {
		// 没选定具体企业：按公司名搜索取第一条命中
		refs, err := s.SearchProvider(ctx, EnterpriseCollectInput{
			ProjectID: in.ProjectID, Provider: in.Provider, Keyword: keyword,
			Cookie: in.Cookie, Username: in.Username, Password: in.Password, ProxyURL: in.ProxyURL,
			Limit: 1,
		})
		if err != nil {
			return enterprise.Job{}, fmt.Errorf("企业检索失败: %w", err)
		}
		if len(refs) == 0 {
			return enterprise.Job{}, errors.New("没有检索到该公司：换个关键词，或先在企业身份页搜索选定")
		}
		ref = refs[0]
	}
	if ref.Name == "" {
		ref.Name = keyword
	}

	job, err := s.Discover(ctx, EnterpriseDiscoverInput{
		ProjectID: in.ProjectID, Provider: in.Provider,
		ExtID: ref.ExtID, Name: ref.Name,
		Depth: in.Depth, MaxNodes: in.MaxNodes,
		Cookie: in.Cookie, Username: in.Username, Password: in.Password, ProxyURL: in.ProxyURL,
		CollectDigital: in.CollectDigital, CollectGroup: in.CollectGroup,
	})
	if err != nil {
		return enterprise.Job{}, err
	}

	go watchOnboardJob(job.ID, in.ProjectID, ref.Name, keyword)
	return job, nil
}

// watchOnboardJob 等采集到终态后自动创建后续扫描任务。
// done/error 都尝试建（error 常见于「达到节点上限中止」，此时种子已落了大部分）；
// canceled 视为用户主动放弃，不建任务。
func watchOnboardJob(jobID string, projectID int64, companyName, keyword string) {
	r := repo.Default()
	if r == nil {
		return
	}
	deadline := time.Now().Add(onboardWatchDeadline)
	ctx := context.Background()
	var last enterprise.Job
	for time.Now().Before(deadline) {
		time.Sleep(onboardWatchInterval)
		job, err := r.GetEnterpriseJob(ctx, jobID)
		if err != nil {
			log.Printf("[onboard] 采集任务 %s 状态查询失败: %v", jobID, err)
			continue
		}
		last = job
		if job.Status == "running" {
			continue
		}
		break
	}
	if last.Status == "" || last.Status == "running" {
		log.Printf("[onboard] 采集任务 %s 超过 %s 未到终态，放弃续延", jobID, onboardWatchDeadline)
		return
	}
	if last.Status == "canceled" {
		log.Printf("[onboard] 采集任务 %s 已取消，不创建后续任务", jobID)
		return
	}

	created, errs := createOnboardFollowupTasks(ctx, projectID, keyword)
	summary := fmt.Sprintf("一键侦察：%s采集%s，自动创建 %d 个扫描任务",
		companyName, map[string]string{"done": "完成", "error": "中止"}[last.Status], created)
	if last.Status == "error" && last.Error != "" {
		summary += fmt.Sprintf("（采集中止原因：%s）", last.Error)
	}
	if len(errs) > 0 {
		summary += fmt.Sprintf("；%d 个创建失败", len(errs))
	}
	for _, e := range errs {
		log.Printf("[onboard] 后续任务创建失败: %v", e)
	}
	SendCollectionAssessmentAsync(projectID, summary, false)
	log.Printf("[onboard] %s", summary)
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
				PortScanMode:  "top1000",
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
			Description: "一键侦察自动创建：企业采集（" + keyword + "）完成后按项目种子生成",
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
