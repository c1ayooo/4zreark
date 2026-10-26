package service

import (
	"context"
	"encoding/json"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/repo"
)

// EngineBudgetService 是测绘引擎查询额度的按天记账：
//
//   - 限额存 app_settings（key=engine_daily_limits，JSON {engine: 次数}），
//     <=0 或缺省表示不限；默认每个引擎 60 次/天（保守起步，可调）。
//   - master 侧调用点（seed_expand 的公司反查 / 证书反查）查询前查余额、
//     查询后落账；worker 侧实际消耗随 scan_done 上报后落账。
//   - worker 崩溃会少记（保护性记账，不追求审计级精确），如实写在文档里。
//
// worker 无库：GetEngineBudgetService 在 worker 上不可用（repo 未初始化），
// 相关入口必须先判 CanAccount()。
type EngineBudgetService struct {
	mu sync.Mutex
}

var (
	engineBudgetOnce sync.Once
	engineBudgetSvc  *EngineBudgetService
)

const engineLimitsSettingKey = "engine_daily_limits"

// 引擎白名单：只有这些名字进限额/统计。
var budgetEngines = []string{"fofa", "hunter", "quake", "zoomeye", "shodan"}

func GetEngineBudgetService() *EngineBudgetService {
	engineBudgetOnce.Do(func() { engineBudgetSvc = &EngineBudgetService{} })
	return engineBudgetSvc
}

// CanAccount 当前进程能否记账（需要 PG 仓储；worker 返回 false）。
func (s *EngineBudgetService) CanAccount() bool {
	return repo.Default() != nil
}

func (s *EngineBudgetService) repo() repo.EngineUsageRepo {
	return repo.Default().EngineUsage()
}

func (s *EngineBudgetService) settings() repo.SettingsRepo {
	return repo.Default().Settings()
}

// limits 读取并归一化限额表；无法读取时返回默认。
func (s *EngineBudgetService) limits(ctx context.Context) map[string]int {
	out := map[string]int{}
	found, err := s.settings().Get(ctx, engineLimitsSettingKey, &out)
	if err != nil || !found || len(out) == 0 {
		for _, e := range budgetEngines {
			out[e] = 60
		}
		return out
	}
	for _, e := range budgetEngines {
		if _, ok := out[e]; !ok {
			out[e] = 60
		}
	}
	return out
}

// RemainingToday 返回引擎今日剩余额度；limit<=0 表示不限（返回 -1）。
// 仓储不可用（worker）返回 -1, false。
func (s *EngineBudgetService) RemainingToday(ctx context.Context, engine string) (int, bool) {
	if !s.CanAccount() {
		return -1, false
	}
	limit := s.limits(ctx)[engine]
	if limit <= 0 {
		return -1, true
	}
	used, err := s.repo().GetEngineUsageSince(ctx, beginningOfToday())
	if err != nil {
		return -1, true // 记账读失败时不阻断业务，交给任务级闸门兜底
	}
	for _, row := range used {
		if row.Engine == engine && sameDay(row.Day, time.Now()) {
			return limit - row.Queries, true
		}
	}
	return limit, true
}

// Consume 落账 n 次查询。
func (s *EngineBudgetService) Consume(ctx context.Context, engine string, n int) {
	if !s.CanAccount() || n <= 0 {
		return
	}
	if err := s.repo().IncrEngineUsage(ctx, engine, n); err != nil {
		log.Printf("[EngineBudget] 记账失败 %s+%d: %v", engine, n, err)
	}
}

// ConsumeMany 批量落账（worker 上报的 map 形态）。
func (s *EngineBudgetService) ConsumeMany(ctx context.Context, usage map[string]int) {
	if !s.CanAccount() {
		return
	}
	engines := make([]string, 0, len(usage))
	for e := range usage {
		engines = append(engines, e)
	}
	sort.Strings(engines)
	for _, e := range engines {
		if usage[e] > 0 {
			s.Consume(ctx, e, usage[e])
		}
	}
}

// AllowMasterQuery master 侧调用点的余额闸门：额度耗尽返回 false。
// 不限额或读不到账时一律放行（业务连续性优先，任务级闸门兜底）。
func (s *EngineBudgetService) AllowMasterQuery(ctx context.Context, engine string) bool {
	remaining, tracked := s.RemainingToday(ctx, engine)
	if !tracked || remaining < 0 {
		return true
	}
	return remaining > 0
}

// Status 供治理面板：今日用量 + 近 7 天 + 限额。
func (s *EngineBudgetService) Status(ctx context.Context) map[string]any {
	if !s.CanAccount() {
		return map[string]any{"available": false}
	}
	limits := s.limits(ctx)
	rows, err := s.repo().GetEngineUsageSince(ctx, time.Now().AddDate(0, 0, -6))
	if err != nil {
		return map[string]any{"available": false, "error": err.Error()}
	}
	today := map[string]int{}
	history := make([]repo.EngineUsageRow, 0, len(rows))
	for _, r := range rows {
		if sameDay(r.Day, time.Now()) {
			today[r.Engine] = r.Queries
		}
		history = append(history, r)
	}
	return map[string]any{
		"available": true,
		"limits":    limits,
		"today":     today,
		"history":   history,
	}
}

// SetLimits 更新限额表（治理 API）。
func (s *EngineBudgetService) SetLimits(ctx context.Context, limits map[string]int) error {
	normalized := map[string]int{}
	known := map[string]bool{}
	for _, e := range budgetEngines {
		known[e] = true
	}
	for e, v := range limits {
		if !known[e] {
			continue
		}
		if v < 0 {
			v = 0
		}
		normalized[e] = v
	}
	return s.settings().Set(ctx, engineLimitsSettingKey, normalized)
}

func beginningOfToday() time.Time {
	now := time.Now()
	return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
}

func sameDay(a, b time.Time) bool {
	ay, am, ad := a.Date()
	by, bm, bd := b.Date()
	return ay == by && am == bm && ad == bd
}

// engineUsageSink 由 main 注入（master 进程内执行路径直接落账，不经 scan_done）。
var engineUsageSink func(map[string]int)

// ReportLocalEngineUsage master 本地执行（role=all / master 直跑）时，
// 由任务执行器调用：把 worker 侧收集的引擎用量直接落账。
// worker 进程 sink 为 nil，量留给 scan_done 上报。
func ReportLocalEngineUsage(usage map[string]int) {
	if engineUsageSink != nil && len(usage) > 0 {
		engineUsageSink(usage)
	}
}

// SetEngineUsageSink 注入本地落账函数（main 启动时）。
func SetEngineUsageSink(fn func(map[string]int)) { engineUsageSink = fn }

// marshalEngineLimits 便于调试/测试的限额序列化。
func marshalEngineLimits(m map[string]int) string {
	b, _ := json.Marshal(m)
	return string(b)
}
