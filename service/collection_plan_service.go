package service

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/oid"
	"github.com/c1ayooo/4zreark/repo"
)

// 信息收集阶段。S1 只收集域名（不主动访问目标）；S2 探活（当前用端口+指纹
// 实现 HTTP 可达性判断，待 HttpProbe 模块接入后替换）；S3 爬虫/端口；
// S4 尾部刻画；S5 只做综合评估，不创建扫描任务。
const (
	CollectionStagePlan    = "plan"
	CollectionStageDomains = "s1_domains"
	CollectionStageProbe   = "s2_probe"
	CollectionStageCrawl   = "s3a_crawl"
	CollectionStagePorts   = "s3b_ports"
	CollectionStageEnrich  = "s4_enrich"
)

type collectionStageSpec struct {
	name      string
	scanTypes []string
	portMode  string
}

var collectionStageOrder = []collectionStageSpec{
	{name: CollectionStageDomains, scanTypes: []string{"subdomain", "domain_only"}},
	// S2 独立探活：httpx 优先，缺失时 HttpProbe 模块回退纯 Go。
	{name: CollectionStageProbe, scanTypes: []string{"http_probe"}},
	{name: CollectionStageCrawl, scanTypes: []string{"crawler"}},
	{name: CollectionStagePorts, scanTypes: []string{"port_scan", "fingerprint"}, portMode: "top1000"},
	{name: CollectionStageEnrich, scanTypes: []string{"fingerprint", "js_audit", "api_probe", "dir_scan", "sensitive"}, portMode: "quick"},
}

// CollectionPlanService 负责计划创建、阶段推进与兜底对账。
// 所有推进都走 (plan_id, stage) 唯一键，重复调用不会重复建任务。
type CollectionPlanService struct {
	store    *repo.CollectionRepo
	stopCh   chan struct{}
	stopOnce sync.Once
}

var (
	collectionPlanOnce sync.Once
	collectionPlanSvc  *CollectionPlanService
)

func GetCollectionPlanService() *CollectionPlanService {
	collectionPlanOnce.Do(func() {
		collectionPlanSvc = &CollectionPlanService{
			store:  repo.NewCollectionRepo(),
			stopCh: make(chan struct{}),
		}
	})
	return collectionPlanSvc
}

// CreatePlan 创建父计划、S1 子任务并启动编排。
// 父任务只承载计划状态，不进入 River 队列。
func (s *CollectionPlanService) CreatePlan(ctx context.Context, task *models.Task) error {
	if s == nil || s.store == nil {
		return fmt.Errorf("数据层未初始化，无法创建信息收集计划")
	}
	if task == nil || len(task.Targets) == 0 {
		return fmt.Errorf("信息收集计划缺少目标")
	}

	mode := config.GetConfig().Collection.Mode
	if mode == "" {
		mode = "auto"
	}
	planID := oid.NewObjectID().Hex()
	parentID := oid.NewObjectID()
	if task.ID.IsZero() {
		task.ID = parentID
	}
	parentID = task.ID

	parent := *task
	parent.Stage = CollectionStagePlan
	parent.PlanID = planID
	parent.CollectionMode = mode
	parent.Status = models.TaskStatusRunning
	parent.Progress = 0
	parent.StartedAt = time.Now()
	parent.UpdatedAt = time.Now()
	if parent.CreatedAt.IsZero() {
		parent.CreatedAt = time.Now()
	}
	if err := repo.Default().Tasks().Create(ctx, &parent); err != nil {
		return fmt.Errorf("创建计划父任务失败: %w", err)
	}

	plan := &repo.CollectionPlan{
		ID:           planID,
		ProjectID:    task.ProjectID,
		Mode:         mode,
		Status:       "running",
		CurrentStage: CollectionStageDomains,
		Seed:         task.Config.UASeed,
	}
	if err := s.store.CreatePlan(ctx, plan); err != nil {
		return fmt.Errorf("创建计划失败: %w", err)
	}

	if err := s.startStage(ctx, &parent, collectionStageOrder[0], task.Targets); err != nil {
		_ = s.store.UpdatePlanProgress(ctx, planID, "failed", CollectionStageDomains)
		return err
	}
	return s.store.UpdatePlanProgress(ctx, planID, "running", CollectionStageDomains)
}

// OnStageDone 是阶段完成钩子：快路径由执行器调用，reconciler 兜底。
func (s *CollectionPlanService) OnStageDone(task *models.Task, status string) {
	if s == nil || s.store == nil || task == nil {
		return
	}
	if task.PlanID == "" || task.Stage == "" || task.Stage == CollectionStagePlan {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	stage, err := s.store.GetStage(ctx, task.PlanID, task.Stage)
	if err != nil || stage == nil {
		log.Printf("[Collection] 阶段账本不存在 plan=%s stage=%s: %v", task.PlanID, task.Stage, err)
		return
	}
	// 幂等：终态阶段不再推进（钩子与 reconciler 可能同时命中）。
	switch stage.Status {
	case "completed", "failed", "skipped":
		return
	}
	terminal := "completed"
	if status == string(models.TaskStatusFailed) || status == string(models.TaskStatusCancelled) {
		// 部分失败继续：当前阶段记 failed，但仍尝试下一阶段。
		terminal = "failed"
	}
	if err := s.store.MarkStageTerminal(ctx, stage.ID, terminal, ""); err != nil {
		log.Printf("[Collection] 更新阶段终态失败 plan=%s stage=%s: %v", task.PlanID, task.Stage, err)
		return
	}

	plan, err := s.store.GetPlan(ctx, task.PlanID)
	if err != nil || plan == nil {
		return
	}
	index := stageIndex(task.Stage)
	if index < 0 || index+1 >= len(collectionStageOrder) {
		s.finishPlan(ctx, plan)
		return
	}

	// 下一阶段的输入 = 当前阶段窗口内落库的资产。
	since := time.Now().Add(-time.Hour)
	if stage.StartedAt != nil {
		since = *stage.StartedAt
	} else if !task.StartedAt.IsZero() {
		since = task.StartedAt
	}
	targets, err := s.store.StageTargets(ctx, plan.ProjectID, since, 1000)
	if err != nil {
		log.Printf("[Collection] 查询阶段产出失败 plan=%s stage=%s: %v", plan.ID, task.Stage, err)
	}
	s.advance(ctx, plan, index+1, targets)
}

func (s *CollectionPlanService) advance(ctx context.Context, plan *repo.CollectionPlan, index int, targets []string) {
	if index >= len(collectionStageOrder) {
		s.finishPlan(ctx, plan)
		return
	}
	spec, skipReason := filterStageByTools(collectionStageOrder[index])
	if len(targets) == 0 {
		// 没有输入就跳过，并留下原因；继续看下一阶段。
		id, err := s.store.UpsertStage(ctx, plan.ID, spec.name)
		if err == nil {
			_ = s.store.MarkStageTerminal(ctx, id, "skipped", "上一阶段没有产出可用的目标")
		}
		log.Printf("[Collection] 跳过阶段 %s：无可用输入 plan=%s", spec.name, plan.ID)
		s.advance(ctx, plan, index+1, targets)
		return
	}
	if len(spec.scanTypes) == 0 {
		// 工具全部缺失：阶段整体跳过，不创建空任务。
		id, err := s.store.UpsertStage(ctx, plan.ID, spec.name)
		if err == nil {
			_ = s.store.MarkStageTerminal(ctx, id, "skipped", skipReason)
		}
		log.Printf("[Collection] 跳过阶段 %s：%s plan=%s", spec.name, skipReason, plan.ID)
		s.advance(ctx, plan, index+1, targets)
		return
	}
	parent, err := repo.Default().Tasks().GetByID(ctx, planTaskID(ctx, plan.ID))
	if err != nil || parent == nil {
		// 父任务查不到时用计划自身字段兜底：至少保证 project/targets 不丢。
		parent = &models.Task{
			ID:             oid.ObjectID{},
			ProjectID:      plan.ProjectID,
			Type:           models.TaskTypeCollection,
			PlanID:         plan.ID,
			Stage:          CollectionStagePlan,
			Targets:        targets,
			TargetType:     "domain",
			Status:         models.TaskStatusRunning,
			CollectionMode: plan.Mode,
		}
	}
	if err := s.startStage(ctx, parent, spec, targets); err != nil {
		log.Printf("[Collection] 启动阶段 %s 失败 plan=%s: %v", spec.name, plan.ID, err)
		_ = s.store.UpdatePlanProgress(ctx, plan.ID, "failed", spec.name)
		return
	}
	_ = s.store.UpdatePlanProgress(ctx, plan.ID, "running", spec.name)
}

func (s *CollectionPlanService) startStage(ctx context.Context, parent *models.Task, spec collectionStageSpec, targets []string) error {
	if spec.name == "" {
		return fmt.Errorf("无效阶段")
	}
	stageID, err := s.store.UpsertStage(ctx, parent.PlanID, spec.name)
	if err != nil {
		return fmt.Errorf("创建阶段账本失败: %w", err)
	}

	child := &models.Task{
		WorkspaceID:    parent.WorkspaceID,
		ProjectID:      parent.ProjectID,
		Name:           parent.Name + " / " + spec.name,
		Description:    "信息收集阶段子任务（由计划 " + parent.PlanID + " 自动创建）",
		Type:           models.TaskTypeCollection,
		Status:         models.TaskStatusPending,
		Targets:        targets,
		TargetType:     parent.TargetType,
		Config:         parent.Config,
		PlanID:         parent.PlanID,
		ParentID:       parent.ID.Hex(),
		Stage:          spec.name,
		CollectionMode: parent.CollectionMode,
		CreatedBy:      parent.CreatedBy,
		Tags:           append(append([]string{}, parent.Tags...), "collection", spec.name),
	}
	if child.TargetType == "" {
		child.TargetType = "domain"
	}
	// 阶段只描述「这一阶段扫什么」；用户父任务里的 scan_types 不应覆盖阶段编排。
	child.Config.ScanTypes = append([]string{}, spec.scanTypes...)
	child.Config.PortScanMode = spec.portMode
	child.Config.PortRange = ""
	child.Config.WatchCrawl = false

	if err := NewTaskService().CreateTask(child); err != nil {
		return fmt.Errorf("创建阶段任务失败: %w", err)
	}
	if err := s.store.MarkStageRunning(ctx, stageID, child.ID.Hex()); err != nil {
		return fmt.Errorf("标记阶段 running 失败: %w", err)
	}
	return nil
}

func (s *CollectionPlanService) finishPlan(ctx context.Context, plan *repo.CollectionPlan) {
	_ = s.store.UpdatePlanProgress(ctx, plan.ID, "completed", "")
	// 综合评估：采集链路的收尾通知；失败不影响计划终态。
	SendCollectionAssessmentAsync(plan.ProjectID, "collection_plan:"+plan.ID, false)
	log.Printf("[Collection] 计划完成 plan=%s project=%d", plan.ID, plan.ProjectID)
}

// StartReconciler 启动 30s 兜底推进：worker 执行完成时 master 的钩子可能丢失。
func (s *CollectionPlanService) StartReconciler(ctx context.Context) {
	if s == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-s.stopCh:
				return
			case <-ticker.C:
				s.reconcileOnce(ctx)
			}
		}
	}()
}

func (s *CollectionPlanService) reconcileOnce(ctx context.Context) {
	plans, err := s.store.ListRunningPlans(ctx, 50)
	if err != nil {
		return
	}
	for _, plan := range plans {
		stage, err := s.store.GetStage(ctx, plan.ID, plan.CurrentStage)
		if err != nil || stage == nil || stage.Status != "running" || stage.TaskID == "" {
			continue
		}
		task, err := repo.Default().Tasks().GetByID(ctx, stage.TaskID)
		if err != nil || task == nil {
			continue
		}
		switch task.Status {
		case models.TaskStatusCompleted:
			s.OnStageDone(task, string(models.TaskStatusCompleted))
		case models.TaskStatusFailed, models.TaskStatusCancelled:
			s.OnStageDone(task, string(task.Status))
		}
	}
}

func (s *CollectionPlanService) Stop() {
	if s == nil {
		return
	}
	s.stopOnce.Do(func() { close(s.stopCh) })
}

func stageIndex(stage string) int {
	for i, spec := range collectionStageOrder {
		if spec.name == stage {
			return i
		}
	}
	return -1
}

// planTaskID 取计划的父任务：plan_id 下 stage='plan' 的那条。
func planTaskID(ctx context.Context, planID string) string {
	tasks, _, err := repo.Default().Tasks().List(ctx, "", string(models.TaskTypeCollection), "", 0, 1, 200)
	if err != nil {
		return ""
	}
	for _, t := range tasks {
		if t.PlanID == planID && strings.EqualFold(t.Stage, CollectionStagePlan) {
			return t.ID.Hex()
		}
	}
	return ""
}
