package service

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/internal/toolruntime"
	"github.com/c1ayooo/4zreark/repo"
)

// ToolRuntimeService 是 toolruntime 的服务层包装：注入 PG 仓储、
// 跑定时检查循环，并把 nuclei 运行时状态并进统一面板。
type ToolRuntimeService struct {
	mgr   *toolruntime.Manager
	repos func() (*repo.Repo, error)

	stopOnce sync.Once
	stopCh   chan struct{}
}

var (
	toolRuntimeOnce sync.Once
	toolRuntimeSvc  *ToolRuntimeService
)

// GetToolRuntimeService 进程级单例。首次调用即注入仓储并启动低频循环
// （每小时 tick，按每个工具的 check_interval_hours 判断是否到期）。
func GetToolRuntimeService() *ToolRuntimeService {
	toolRuntimeOnce.Do(func() {
		mgr := toolruntime.Default()
		svc := &ToolRuntimeService{
			mgr:    mgr,
			repos:  func() (*repo.Repo, error) { return repo.Default(), nil },
			stopCh: make(chan struct{}),
		}
		if r, err := svc.repos(); err == nil && r != nil {
			mgr.SetStore(r.ToolRuntime())
		} else {
			log.Printf("[toolruntime] 未接仓储（worker/无库模式），状态只看本地磁盘")
		}
		svc.Start()
		toolRuntimeSvc = svc
	})
	return toolRuntimeSvc
}

// Start 启动定时循环；工具不存在且 auto_update 开启时顺带补装。
func (s *ToolRuntimeService) Start() {
	go func() {
		// 启动后延迟 2 分钟再动手，避开启动高峰；先补装缺失工具。
		select {
		case <-time.After(2 * time.Minute):
		case <-s.stopCh:
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		for _, name := range toolruntime.SpecNames() {
			if _, err := s.mgr.EnsureInstalled(ctx, name); err != nil {
				log.Printf("[toolruntime] 补装 %s 失败: %v", name, err)
			}
		}
		cancel()

		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-s.stopCh:
				return
			case <-ticker.C:
				cctx, ccancel := context.WithTimeout(context.Background(), 15*time.Minute)
				s.mgr.CheckDue(cctx, true)
				ccancel()
			}
		}
	}()
}

func (s *ToolRuntimeService) Stop() {
	s.stopOnce.Do(func() { close(s.stopCh) })
}

// Status 全部受管工具状态 + nuclei 运行时摘要。
func (s *ToolRuntimeService) Status(ctx context.Context) map[string]any {
	tools := s.mgr.Status(ctx)
	out := map[string]any{"tools": tools}
	if st, err := GetNucleiRuntimeService().Status(ctx); err == nil {
		out["nuclei"] = st
	}
	return out
}

// Check 查询单个工具的上游最新版本。
func (s *ToolRuntimeService) Check(ctx context.Context, name string) (*toolruntime.ToolStatus, error) {
	return s.mgr.Check(ctx, name)
}

// Update 安装/更新单个工具。
func (s *ToolRuntimeService) Update(ctx context.Context, name string, force bool) (*toolruntime.ToolStatus, error) {
	return s.mgr.Update(ctx, name, force)
}

// Rollback 回滚单个工具。
func (s *ToolRuntimeService) Rollback(ctx context.Context, name string) (*toolruntime.ToolStatus, error) {
	return s.mgr.Rollback(ctx, name)
}

// History 单个工具的更新历史。
func (s *ToolRuntimeService) History(ctx context.Context, name string) ([]toolruntime.UpdateRecord, error) {
	r, err := s.repos()
	if err != nil || r == nil {
		return nil, errors.New("仓储不可用")
	}
	return r.ToolRuntime().ListRecords(ctx, name, 20)
}

// ApplySettings 更新单个工具设置（pinned_version / auto_update / 间隔）。
func (s *ToolRuntimeService) ApplySettings(ctx context.Context, name string, mutate func(*toolruntime.ToolState)) (*toolruntime.ToolStatus, error) {
	return s.mgr.ApplySettings(ctx, name, mutate)
}

// Manager 暴露底层管理器（供部署流等取路径）。
func (s *ToolRuntimeService) Manager() *toolruntime.Manager { return s.mgr }
