package service

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/internal/githubleak"
	"github.com/c1ayooo/4zreark/internal/lz"
	"github.com/c1ayooo/4zreark/repo"

	"github.com/jackc/pgx/v5/stdlib"
)

// GitHub 泄露监控（迁移自 4zreco/internal/githubleak）：
// 全局单例 Service，规则来自全部项目的启用规则（规则名带项目名前缀）。
// 每轮周期从 DB 重拉规则，变更即 UpdateSettings 热更；token 取任一项目配置值。

type GitHubMonitorService struct {
	mu    sync.Mutex
	svc   *githubleak.Service
	store *githubleak.Store
	repo  repo.GitHubMonitorRepo
	// lastRulesKey 上轮规则指纹（项目:名:关键词 串接哈希的替身——直接拼串比较）
	lastRules string
}

var (
	githubMonitorOnce sync.Once
	githubMonitorSvc  *GitHubMonitorService
	githubMonitorErr  error
)

// GetGitHubMonitor 构造全局监控服务；DB 不可用时不阻塞启动，返回错误供调用方记日志。
func GetGitHubMonitor() (*GitHubMonitorService, error) {
	githubMonitorOnce.Do(func() {
		r := repo.Default()
		if r == nil {
			githubMonitorErr = fmt.Errorf("数据层未初始化")
			return
		}
		sqldb := stdlib.OpenDBFromPool(r.Pool())
		store, err := githubleak.NewStore(context.Background(), sqldb)
		if err != nil {
			githubMonitorErr = err
			return
		}
		githubMonitorSvc = &GitHubMonitorService{
			store: store,
			repo:  r.GitHubMonitor(),
		}
		// 首次以空设置建 Service（启用规则同步后再热更）；token 未配置时
		// GitHub 匿名搜索配额极低，客户端仍可构造，跑起来只会拿不到结果。
		settings := githubleak.Settings{Enabled: false}
		svc, err := githubleak.NewService(store, settings, lz.New("GitHubLeak"))
		if err != nil {
			githubMonitorErr = err
			githubMonitorSvc = nil
			return
		}
		// 通知出口：迁移自 4zreco 的 IM notifier；4zreark 先落日志，
		// 要接机器人广播时只改这一处。
		svc.SetNotify(func(e githubleak.Event) {
			log.Printf("[GitHubLeak] %s (%s) %s: %s", e.Title, e.Level, e.Kind, e.Summary)
		})
		githubMonitorSvc.svc = svc
	})
	return githubMonitorSvc, githubMonitorErr
}

// GitHubMonitorStore findings 存储访问（handler 列表/处置用）；未就绪返回 nil。
func GitHubMonitorStore() *githubleak.Store {
	if githubMonitorSvc == nil {
		return nil
	}
	return githubMonitorSvc.store
}

// Start 启动规则同步循环与监控循环（master 进程入口调用一次）。
func (g *GitHubMonitorService) Start(ctx context.Context) {
	g.svc.Start(ctx)
	go g.syncRulesLoop(ctx)
}

// syncRulesLoop 每 2 分钟从 DB 重拉启用规则，拼装 Settings 热更监控。
func (g *GitHubMonitorService) syncRulesLoop(ctx context.Context) {
	// 起手先同步一次，成功即启动监控
	for {
		changed, err := g.syncOnce(ctx)
		if err != nil {
			log.Printf("[GitHubLeak] 规则同步失败: %v", err)
		} else if changed {
			log.Printf("[GitHubLeak] 规则已更新并热更监控")
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Minute):
		}
	}
}

// syncOnce 拉规则拼 Settings；返回是否发生了热更。
func (g *GitHubMonitorService) syncOnce(ctx context.Context) (bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	rules, err := g.repo.ListAllEnabledRules(ctx)
	if err != nil {
		return false, err
	}
	token, err := g.repo.FirstToken(ctx)
	if err != nil {
		return false, err
	}

	// 规则指纹：名字+关键词串接（项目名已带前缀）
	key := make([]string, 0, len(rules))
	keywords := make([]string, 0, 64)
	glRules := make([]githubleak.Rule, 0, len(rules))
	for _, r := range rules {
		key = append(key, fmt.Sprintf("%d:%s:%s", r.ID, r.Name, strings.Join(r.Keywords, ",")))
		keywords = append(keywords, r.Keywords...)
		glRules = append(glRules, githubleak.Rule{
			Enabled:  true,
			Name:     r.Name,
			Keywords: r.Keywords,
		})
	}
	newKey := strings.Join(key, "|")
	if newKey == g.lastRules {
		// 规则没变，但 token 可能变了：交给 UpdateSettings 幂等处理
		if token == "" {
			return false, nil
		}
	}

	settings := githubleak.Settings{
		Enabled:         len(rules) > 0 && token != "",
		Token:           token,
		Keywords:        keywords,
		Rules:           glRules,
		IntervalSeconds: githubleak.DefaultIntervalSeconds,
	}
	if err := g.svc.UpdateSettings(settings); err != nil {
		return false, fmt.Errorf("热更设置失败: %w", err)
	}
	// Start 幂等（内部 running/queued 标记，重复调用直接返回）
	g.svc.Start(ctx)
	g.lastRules = newKey
	return true, nil
}
