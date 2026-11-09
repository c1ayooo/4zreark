package service

import (
	"context"
	"errors"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/internal/browser"
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

// Start 启动定时循环：启动 2 分钟后、之后每小时巡检项目内部，缺工具即补装；
// 系统 PATH 上有同名工具也不会跳过（由 EnsureInstalled 的项目内检测保证）。
func (s *ToolRuntimeService) Start() {
	go func() {
		// 启动后延迟 2 分钟再动手，避开启动高峰。
		select {
		case <-time.After(2 * time.Minute):
		case <-s.stopCh:
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		s.EnsureMissing(ctx)
		cancel()

		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-s.stopCh:
				return
			case <-ticker.C:
				ictx, icancel := context.WithTimeout(context.Background(), 10*time.Minute)
				s.EnsureMissing(ictx)
				icancel()
				cctx, ccancel := context.WithTimeout(context.Background(), 15*time.Minute)
				s.mgr.CheckDue(cctx, true)
				ccancel()
			}
		}
	}()
}

// EnsureMissing 立即巡检并补装项目内缺失的受管工具，返回每个工具的结果。
func (s *ToolRuntimeService) EnsureMissing(ctx context.Context) map[string]string {
	out := make(map[string]string, len(toolruntime.SpecNames()))
	for _, name := range toolruntime.SpecNames() {
		p, err := s.mgr.EnsureInstalled(ctx, name)
		if err != nil {
			out[name] = "error: " + err.Error()
			log.Printf("[toolruntime] 补装 %s 到项目目录失败: %v", name, err)
			continue
		}
		out[name] = "ok: " + p
	}
	return out
}

func (s *ToolRuntimeService) Stop() {
	s.stopOnce.Do(func() { close(s.stopCh) })
}

// Status 全部受管工具状态 + nuclei 运行时摘要 + 自带浏览器状态。
func (s *ToolRuntimeService) Status(ctx context.Context) map[string]any {
	tools := s.mgr.Status(ctx)
	out := map[string]any{"tools": tools}
	if st, err := GetNucleiRuntimeService().Status(ctx); err == nil {
		out["nuclei"] = st
	}
	out["browser"] = browser.Status()
	return out
}

// InstalledToolsResult 是「平台已安装工具」的统一检索结果。
// Items 默认只含项目内部安装；External 是环境里发现、但不属于平台自身的工具。
type InstalledToolsResult struct {
	Items         []toolruntime.InstalledTool `json:"items"`
	Total         int                         `json:"total"`
	Roots         []string                    `json:"roots"`
	External      []toolruntime.InstalledTool `json:"external"`
	ExternalCount int                         `json:"external_count"`
}

// InstalledTools 检索平台自身（项目内部）已安装的工具，覆盖受管工具、
// nuclei 独立运行时与自带浏览器；系统 PATH 上的工具只作为外部候选单列。
func (s *ToolRuntimeService) InstalledTools(ctx context.Context, f toolruntime.InstalledFilter, includeExternal bool) *InstalledToolsResult {
	opts := toolruntime.DefaultDiscoverOptions()
	external := make([]toolruntime.InstalledTool, 0)

	var nucleiVersion string
	if nst, err := GetNucleiRuntimeService().Status(ctx); err == nil && nst != nil {
		nucleiVersion = nst.BinaryVersion
		if nst.BinaryExists && nst.BinaryPath != "" {
			if pathWithin(nst.BinaryPath, nst.Root) {
				opts.NucleiBin = nst.BinaryPath
			} else {
				external = append(external, externalTool("nuclei", nst.BinaryPath,
					toolruntime.SourceOverride, "nuclei.binary_path 指向项目外部，不算平台安装"))
			}
		} else if p, lookErr := exec.LookPath("nuclei"); lookErr == nil && !pathWithin(p, nst.Root) {
			external = append(external, externalTool("nuclei", p,
				toolruntime.SourceSystem, "系统 PATH 上的 nuclei 不算平台安装；独立运行时会自动下载到项目内 data/bin/nuclei/bin"))
		}
	}

	var browserVersion string
	if bs := browser.Status(); bs != nil {
		browserVersion, _ = bs["version"].(string)
		if p, _ := bs["path"].(string); p != "" {
			if src, _ := bs["source"].(string); src == "bundled" {
				opts.BrowserBin = p
			} else {
				external = append(external, externalTool("browser", p,
					toolruntime.SourceSystem, "系统安装的浏览器，不算平台自带工具"))
			}
		}
	}

	// 项目内没有、但环境（PATH/覆盖）能解析到的受管工具：不算平台安装。
	for _, name := range toolruntime.SpecNames() {
		if s.mgr.ProjectToolPath(name) != "" {
			continue
		}
		if p := s.mgr.ResolveToolPath(name); p != "" {
			src := s.mgr.ToolSource(name, p)
			note := "系统 PATH 上的同名工具不算平台安装；自动补装会装到项目目录"
			if src == toolruntime.SourceOverride {
				note = "环境变量覆盖到项目外部；自动补装仍会装到项目目录"
			}
			external = append(external, externalTool(name, p, src, note))
		}
	}

	res := toolruntime.DiscoverInstalled(opts)
	managedVersions := make(map[string]string, len(toolruntime.SpecNames()))
	for _, st := range s.mgr.Status(ctx) {
		v := st.InstalledVersion
		if v == "" {
			v = st.DiskVersion
		}
		if v != "" {
			managedVersions[st.Name] = v
		}
	}
	fillVersion := func(it *toolruntime.InstalledTool) {
		switch it.Name {
		case "nuclei":
			it.Version = nucleiVersion
			it.Description = "漏洞模板执行 / 自动验证（独立运行时）"
		case "browser":
			it.Version = browserVersion
			it.Description = "Chromium（报告渲染 / SPA 爬虫）"
		default:
			it.Version = managedVersions[it.Name]
		}
	}
	for i := range res.Items {
		fillVersion(&res.Items[i])
	}
	for i := range external {
		fillVersion(&external[i])
	}

	items := res.Items
	if includeExternal {
		items = append(items, external...)
	}
	items = toolruntime.FilterInstalled(items, f)
	return &InstalledToolsResult{
		Items: items, Total: len(items), Roots: res.Roots,
		External: external, ExternalCount: len(external),
	}
}

// externalTool 把环境里发现的工具转成统一条目（明确标为项目外部）。
func externalTool(name, path, source, note string) toolruntime.InstalledTool {
	it := toolruntime.InstalledTool{
		Name: name, Path: path, Source: source, InProject: false, Note: note,
	}
	if spec, ok := toolruntime.Spec(name); ok {
		it.Managed = true
		it.Description = spec.Description
	}
	if fi, err := os.Stat(path); err == nil {
		it.SizeBytes = fi.Size()
		it.ModTime = fi.ModTime()
		it.Executable = fi.Mode().Perm()&0o111 != 0 || strings.HasSuffix(strings.ToLower(path), ".exe")
	}
	return it
}

func pathWithin(path, root string) bool {
	if path == "" || root == "" {
		return false
	}
	p, err1 := filepath.Abs(path)
	r, err2 := filepath.Abs(root)
	if err1 != nil || err2 != nil {
		return false
	}
	rel, err := filepath.Rel(r, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

// Check 查询单个工具的上游最新版本。browser 非 GitHub release 工具：
// revision 期望值随平台版本（rod 依赖）走，状态里的 update_available 即
// 检测结果，无需上游查询。
func (s *ToolRuntimeService) Check(ctx context.Context, name string) (*toolruntime.ToolStatus, error) {
	if name == "browser" {
		return nil, errors.New("browser 非 GitHub release 工具：更新检测已内置于 browser 条目（update_available），无需上游查询")
	}
	return s.mgr.Check(ctx, name)
}

// Update 安装/更新单个工具。（browser 的更新走 UpdateBrowser，返回类型不同）
func (s *ToolRuntimeService) Update(ctx context.Context, name string, force bool) (*toolruntime.ToolStatus, error) {
	return s.mgr.Update(ctx, name, force)
}

// BrowserStatus 自带浏览器状态（工具运行时面板 browser 条目）。
func (s *ToolRuntimeService) BrowserStatus() map[string]any { return browser.Status() }

// UpdateBrowser 自带浏览器重新自举：下载当前平台期望的 revision 并探活。
func (s *ToolRuntimeService) UpdateBrowser(ctx context.Context) (map[string]any, error) {
	return browser.Update(ctx)
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
