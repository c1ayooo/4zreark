package pipeline

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// ProgressTracker 进度追踪器
// 用于追踪流水线各模块的处理进度
type ProgressTracker struct {
	mu sync.RWMutex

	// 总体进度
	totalTargets int       // 总目标数
	startTime    time.Time // 开始时间

	// 各模块进度
	moduleProgress map[string]*ModuleProgress

	// 模块权重配置（用于计算总体进度）
	moduleWeights map[string]float64

	// 进度回调
	callback ProgressCallback
	// callbackInFlight 合并在飞回调：逐条结果都起 goroutine 写库会在大任务下
	// 产生数万个并发 UPDATE，丢中间帧没有信息损失（下一帧总是更新）。
	callbackInFlight atomic.Bool
}

// ModuleProgress 模块进度
type ModuleProgress struct {
	Name           string    `json:"name"`            // 模块名称
	Status         string    `json:"status"`          // pending, running, completed
	TotalItems     int       `json:"total_items"`     // 总项目数
	ProcessedItems int       `json:"processed_items"` // 已处理项目数
	OutputItems    int       `json:"output_items"`    // 输出项目数
	StartTime      time.Time `json:"start_time"`      // 开始时间
	EndTime        time.Time `json:"end_time"`        // 结束时间
	Progress       float64   `json:"progress"`        // 进度百分比 0-100
}

// ProgressCallback 进度回调函数
type ProgressCallback func(progress *ProgressReport)

// ProgressReport 进度报告
type ProgressReport struct {
	OverallProgress   int                        `json:"overall_progress"`    // 总体进度 0-100
	CurrentModule     string                     `json:"current_module"`      // 当前执行的模块
	ModuleProgresses  map[string]*ModuleProgress `json:"module_progresses"`   // 各模块进度
	TotalTargets      int                        `json:"total_targets"`       // 总目标数
	TotalResults      int                        `json:"total_results"`       // 总结果数
	ElapsedTime       string                     `json:"elapsed_time"`        // 已用时间
	EstimatedTimeLeft string                     `json:"estimated_time_left"` // 预计剩余时间
}

// DefaultModuleWeights 默认模块权重
// 权重决定每个模块在总体进度中所占的比例
var DefaultModuleWeights = map[string]float64{
	"SubdomainScan":   20, // 子域名扫描 20%
	"DomainVerify":    5,  // 域名验证 5%
	"PortPreparation": 5,  // 端口预处理 5%
	"PortScan":        25, // 端口扫描 25%
	"Fingerprint":     15, // 指纹识别 15%
	"VulnScan":        15, // 漏洞扫描 15%
	"Crawler":         5,  // 爬虫 5%
	"DirScan":         5,  // 目录扫描 5%
	"Sensitive":       5,  // 敏感信息 5%
}

// NewProgressTracker 创建进度追踪器
func NewProgressTracker(totalTargets int, callback ProgressCallback) *ProgressTracker {
	return &ProgressTracker{
		totalTargets:   totalTargets,
		startTime:      time.Now(),
		moduleProgress: make(map[string]*ModuleProgress),
		moduleWeights:  DefaultModuleWeights,
		callback:       callback,
	}
}

// SetModuleWeights 根据启用的模块重新计算权重
func (pt *ProgressTracker) SetModuleWeights(enabledModules []string) {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	// 计算启用模块的总权重
	var totalWeight float64
	for _, module := range enabledModules {
		if w, ok := DefaultModuleWeights[module]; ok {
			totalWeight += w
		}
	}

	// 重新标准化权重到100%
	pt.moduleWeights = make(map[string]float64)
	for _, module := range enabledModules {
		if w, ok := DefaultModuleWeights[module]; ok {
			pt.moduleWeights[module] = (w / totalWeight) * 100
		}
	}
}

// StartModule 模块开始
func (pt *ProgressTracker) StartModule(moduleName string, totalItems int) {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	pt.moduleProgress[moduleName] = &ModuleProgress{
		Name:       moduleName,
		Status:     "running",
		TotalItems: totalItems,
		StartTime:  time.Now(),
	}

	pt.notifyProgress()
}

// UpdateModuleTotal 更新模块总数（用于动态发现的情况）
func (pt *ProgressTracker) UpdateModuleTotal(moduleName string, totalItems int) {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	if mp, ok := pt.moduleProgress[moduleName]; ok {
		mp.TotalItems = totalItems
	}

	pt.notifyProgress()
}

// IncrementModuleProcessed 增加模块处理计数
func (pt *ProgressTracker) IncrementModuleProcessed(moduleName string, count int) {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	if mp, ok := pt.moduleProgress[moduleName]; ok {
		mp.ProcessedItems += count
		if mp.TotalItems > 0 {
			mp.Progress = float64(mp.ProcessedItems) / float64(mp.TotalItems) * 100
			if mp.Progress > 100 {
				mp.Progress = 100
			}
		}
	}

	pt.notifyProgress()
}

// IncrementModuleOutput 增加模块输出计数
func (pt *ProgressTracker) IncrementModuleOutput(moduleName string, count int) {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	if mp, ok := pt.moduleProgress[moduleName]; ok {
		mp.OutputItems += count
	}
}

// CompleteModule 模块完成
func (pt *ProgressTracker) CompleteModule(moduleName string) {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	if mp, ok := pt.moduleProgress[moduleName]; ok {
		mp.Status = "completed"
		mp.EndTime = time.Now()
		mp.Progress = 100
	}

	pt.notifyProgress()
}

// GetOverallProgress 获取总体进度
func (pt *ProgressTracker) GetOverallProgress() int {
	pt.mu.RLock()
	defer pt.mu.RUnlock()

	return pt.calculateOverallProgress()
}

// calculateOverallProgress 计算总体进度（内部方法，需要持有锁）
func (pt *ProgressTracker) calculateOverallProgress() int {
	var totalProgress float64
	var activeWeight float64

	for moduleName, mp := range pt.moduleProgress {
		weight, ok := pt.moduleWeights[moduleName]
		if !ok {
			weight = 10 // 默认权重
		}
		activeWeight += weight
		totalProgress += (mp.Progress / 100) * weight
	}

	if activeWeight == 0 {
		return 0
	}

	// 归一化到已激活模块的权重比例
	progress := int(totalProgress / activeWeight * 100)
	if progress > 100 {
		progress = 100
	}

	return progress
}

// GetReport 获取进度报告
func (pt *ProgressTracker) GetReport() *ProgressReport {
	pt.mu.RLock()
	defer pt.mu.RUnlock()

	elapsed := time.Since(pt.startTime)
	overallProgress := pt.calculateOverallProgress()

	// 计算预计剩余时间
	var estimatedLeft string
	if overallProgress > 0 && overallProgress < 100 {
		totalTime := elapsed.Seconds() / (float64(overallProgress) / 100)
		leftTime := time.Duration((totalTime - elapsed.Seconds()) * float64(time.Second))
		estimatedLeft = formatDuration(leftTime)
	} else if overallProgress >= 100 {
		estimatedLeft = "已完成"
	} else {
		estimatedLeft = "计算中..."
	}

	// 找到当前运行的模块
	var currentModule string
	for name, mp := range pt.moduleProgress {
		if mp.Status == "running" {
			currentModule = name
			break
		}
	}

	// 计算总结果数
	var totalResults int
	for _, mp := range pt.moduleProgress {
		totalResults += mp.OutputItems
	}

	// 复制模块进度
	progresses := make(map[string]*ModuleProgress)
	for k, v := range pt.moduleProgress {
		cp := *v
		progresses[k] = &cp
	}

	return &ProgressReport{
		OverallProgress:   overallProgress,
		CurrentModule:     currentModule,
		ModuleProgresses:  progresses,
		TotalTargets:      pt.totalTargets,
		TotalResults:      totalResults,
		ElapsedTime:       formatDuration(elapsed),
		EstimatedTimeLeft: estimatedLeft,
	}
}

// notifyProgress 通知进度更新（内部方法，需要持有锁）
func (pt *ProgressTracker) notifyProgress() {
	if pt.callback == nil {
		return
	}
	if !pt.callbackInFlight.CompareAndSwap(false, true) {
		return
	}

	// 创建报告（注意：此时已持有锁，需要释放后再调用回调）
	report := pt.getReportUnsafe()

	go func() {
		defer pt.callbackInFlight.Store(false)
		pt.callback(report)
	}()
}

// getReportUnsafe 获取进度报告（不加锁版本，内部使用）
func (pt *ProgressTracker) getReportUnsafe() *ProgressReport {
	elapsed := time.Since(pt.startTime)
	overallProgress := pt.calculateOverallProgress()

	var estimatedLeft string
	if overallProgress > 0 && overallProgress < 100 {
		totalTime := elapsed.Seconds() / (float64(overallProgress) / 100)
		leftTime := time.Duration((totalTime - elapsed.Seconds()) * float64(time.Second))
		estimatedLeft = formatDuration(leftTime)
	} else if overallProgress >= 100 {
		estimatedLeft = "已完成"
	} else {
		estimatedLeft = "计算中..."
	}

	var currentModule string
	for name, mp := range pt.moduleProgress {
		if mp.Status == "running" {
			currentModule = name
			break
		}
	}

	var totalResults int
	for _, mp := range pt.moduleProgress {
		totalResults += mp.OutputItems
	}

	progresses := make(map[string]*ModuleProgress)
	for k, v := range pt.moduleProgress {
		cp := *v
		progresses[k] = &cp
	}

	return &ProgressReport{
		OverallProgress:   overallProgress,
		CurrentModule:     currentModule,
		ModuleProgresses:  progresses,
		TotalTargets:      pt.totalTargets,
		TotalResults:      totalResults,
		ElapsedTime:       formatDuration(elapsed),
		EstimatedTimeLeft: estimatedLeft,
	}
}

// formatDuration 格式化时间
func formatDuration(d time.Duration) string {
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	if hours > 0 {
		return fmt.Sprintf("%d小时%d分%d秒", hours, minutes, seconds)
	} else if minutes > 0 {
		return fmt.Sprintf("%d分%d秒", minutes, seconds)
	}
	return fmt.Sprintf("%d秒", seconds)
}
