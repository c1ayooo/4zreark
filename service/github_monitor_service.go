package service

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/internal/githubleak"
	"github.com/c1ayooo/4zreark/internal/githubtokens"
	"github.com/c1ayooo/4zreark/internal/lz"
	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service/notify"

	"github.com/jackc/pgx/v5/stdlib"
)

// defaultExtraRulesPath gitleaks 社区规则导入产物的缺省位置（相对 master 工作目录）。
// 项目设置里显式配置 extra_rules_path 时覆盖此值。
const defaultExtraRulesPath = "configs/gitleaks_extra_rules.json"

// GitHubMonitorService 全局 GitHub 泄露监控编排：
//   - 规则来自全部项目的启用规则（规则名带项目名前缀），每轮周期从 DB 重拉热更；
//   - token 优先从 Token 池按剩余配额轮换（Pool.Pick），池空回退项目级单 token；
//   - search 桶 30 次/分钟限速器三方共享（监控轮询 / dork 扫描 / 其它消费方）。

type GitHubMonitorService struct {
	mu    sync.Mutex
	svc   *githubleak.Service
	store *githubleak.Store
	repo  repo.GitHubMonitorRepo
	// token 池与配额（与 githubleak.Store 共用同一个 database/sql 适配层连接）
	tokens *githubtokens.Store
	pool   *githubtokens.Pool
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
		// Token 池：与 githubleak.Store 共用同一 database/sql 连接；池表由包自建。
		// 池为空时 Pick 返回 ""，监控自动回退项目级单 token，向后兼容。
		tokens, terr := githubtokens.NewStore(sqldb)
		if terr != nil {
			log.Printf("[GitHubLeak] Token 池初始化失败（监控将退回单 token 模式）: %v", terr)
		} else {
			pool := githubtokens.NewPool(tokens)
			svc.SetTokenPool(pool)
			svc.SetSearchLimiter(githubtokens.NewSearchLimiter(0))
			githubMonitorSvc.tokens = tokens
			githubMonitorSvc.pool = pool
		}
		// 通知出口：接 4zreark 通知设施（飞书/钉钉/企业微信/Telegram/邮件/自定义 webhook，
		// 渠道与级别门槛由 notify 配置决定；未配置任何渠道时 Manager 静默跳过）。
		// 事件本身已按「仓库×密钥值」聚合（githubleak/service_notify.go），这里只做映射。
		svc.SetNotify(func(e githubleak.Event) {
			msg := &notify.NotifyMessage{
				Level:     notifyLevelOf(e.Level),
				Title:     e.Title,
				Content:   renderLeakEvent(e),
				Timestamp: time.Now(),
				Source:    "github-leak",
				Extra: map[string]interface{}{
					"kind":       e.Kind,
					"dedup_key":  e.DedupKey,
					"item_count": len(e.Items),
				},
			}
			notify.GetGlobalManager().SendAsync(msg)
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

// GitHubTokenStore Token 池存储访问（handler 管理/配额展示用）；未就绪返回 nil。
func GitHubTokenStore() *githubtokens.Store {
	if githubMonitorSvc == nil {
		return nil
	}
	return githubMonitorSvc.tokens
}

// GitHubTokenPool Token 池轮换器访问（handler 手动刷新配额用）；未就绪返回 nil。
func GitHubTokenPool() *githubtokens.Pool {
	if githubMonitorSvc == nil {
		return nil
	}
	return githubMonitorSvc.pool
}

// GitHubLeakService 泄露监控内核访问（管理端点 Run/Backfill/Suppressions 等）；
// 未就绪返回 nil。
func GitHubLeakService() *githubleak.Service {
	if githubMonitorSvc == nil {
		return nil
	}
	return githubMonitorSvc.svc
}

// notifyLevelOf 把 githubleak 事件级别映射为通知级别；未知值保守取 medium。
func notifyLevelOf(level string) notify.NotifyLevel {
	switch level {
	case "critical", "high", "medium", "low", "info":
		return notify.NotifyLevel(level)
	default:
		return notify.NotifyLevelMedium
	}
}

// renderLeakEvent 把聚合事件渲染成纯文本正文：摘要 + 命中条目（仓库 · 类型 · 明文键值）+ 脚注。
// 明文键值直接进正文——通知即告警，值守不需要再跳平台才能看到泄露值。
func renderLeakEvent(e githubleak.Event) string {
	var b strings.Builder
	if e.Summary != "" {
		b.WriteString(e.Summary)
	}
	for _, it := range e.Items {
		b.WriteString("\n")
		switch {
		case it.Tag != "":
			fmt.Fprintf(&b, "• %s", it.Tag)
			if it.Text != "" {
				fmt.Fprintf(&b, "：%s", it.Text)
			}
		case it.Text != "":
			fmt.Fprintf(&b, "• %s", it.Text)
		}
		if it.Sub != "" {
			fmt.Fprintf(&b, "\n  %s", it.Sub)
		}
		if it.Link != "" {
			fmt.Fprintf(&b, "\n  %s", it.Link)
		}
	}
	if e.Footer != "" {
		fmt.Fprintf(&b, "\n%s", e.Footer)
	}
	return b.String()
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
	// 出网设置：token（已解密）+ 项目配置的轮询间隔。
	active, err := g.repo.FirstActiveSettings(ctx)
	if err != nil {
		return false, err
	}
	// Token 池优先：按剩余配额轮换多账号；池空/未初始化回退项目级单 token。
	// 顺带刷新全池配额（rate_limit 端点不计配额；同步周期 2 分钟，调用方节流足够）。
	token := active.Token
	if g.pool != nil {
		if errs := g.pool.RefreshRates(ctx); len(errs) > 0 {
			for _, e := range errs {
				log.Printf("[GitHubLeak] Token 配额刷新失败: %v", e)
			}
		}
		if picked := g.pool.Pick(ctx); picked != "" {
			token = picked
		}
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
	// 项目里配的 interval_seconds 语义是「多久搜一轮」，映射到 poll 间隔；
	// 请求间隔仍固定 60s，由 githubleak 的 31s 下限兜底，避免打爆 search 配额。
	if active.IntervalSeconds > 0 {
		settings.PollIntervalSeconds = active.IntervalSeconds
	}
	// 高级误报治理与动态规则（gitleaks 社区规则导入产物）。
	// ExtraRulesPath 缺省指向仓库内规则文件，存在才生效，缺失只记日志不报错。
	settings.RepoMaxAgeDays = active.RepoMaxAgeDays
	settings.LookbackDays = active.LookbackDays
	settings.BoilerplateRepos = active.BoilerplateRepos
	settings.MaxBlobRescansPerRule = active.MaxBlobRescansPerRule
	settings.BlobRescan = &active.BlobRescan
	settings.NotifyEnabled = &active.NotifyEnabled
	settings.ExtraRulesPath = active.ExtraRulesPath
	if settings.ExtraRulesPath == "" {
		settings.ExtraRulesPath = defaultExtraRulesPath
	}
	if _, statErr := os.Stat(settings.ExtraRulesPath); statErr != nil {
		log.Printf("[GitHubLeak] 动态规则文件不可用（跳过加载）: %s", settings.ExtraRulesPath)
		settings.ExtraRulesPath = ""
	}
	if err := g.svc.UpdateSettings(settings); err != nil {
		return false, fmt.Errorf("热更设置失败: %w", err)
	}
	// Start 幂等（内部 running/queued 标记，重复调用直接返回）
	g.svc.Start(ctx)
	g.lastRules = newKey
	return true, nil
}
