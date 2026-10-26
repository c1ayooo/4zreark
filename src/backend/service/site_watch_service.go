package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"math/rand"
	"os"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/internal/httpprobe"
	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service/notify"
)

// SiteWatchService 是资产监控的「站点内容慢速巡检」层：
//
//   - 队列：全局限速令牌桶（默认 4 次/分钟）+ 每日预算 + 随机抖动，
//     按 content_checked_at 最旧优先逐站发一次 GET（同 ProbeSite 的单请求口径）；
//   - 判定：两级 hash——raw(整个响应体) 变而 text(剥 script/style/标签) 同
//     视为动态噪声静默放过；text 变才是真变更 → asset_events + 通知 + 慢爬；
//   - 慢爬：不走重流水线，创建纯爬虫轻任务（无端口扫描/指纹，2 rps、
//     深度 2、30 页上限），全局同时至多 1 个、同站 24h 冷却——
//     「慢速且漫长，不能影响人家网站」。
type SiteWatchService struct {
	notify *notify.NotifyManager

	crawlMu sync.Mutex

	stopOnce sync.Once
	stopCh   chan struct{}
}

var (
	siteWatchOnce sync.Once
	siteWatchSvc  *SiteWatchService
)

func GetSiteWatchService() *SiteWatchService {
	siteWatchOnce.Do(func() {
		siteWatchSvc = &SiteWatchService{
			notify: notify.GetGlobalManager(),
			stopCh: make(chan struct{}),
		}
	})
	return siteWatchSvc
}

// Start 启动巡检循环：启动延迟 7 分钟（错开 discovery 的 5 分钟），
// 每轮取一批（默认 5 个），批间随机歇 45-75s。实测吞吐 ≈ 每分钟 4-6 站。
func (s *SiteWatchService) Start() {
	go func() {
		select {
		case <-time.After(7 * time.Minute):
		case <-s.stopCh:
			return
		}
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			batch, err := s.RunBatch(ctx)
			cancel()
			if err != nil {
				log.Printf("[SiteWatch] 巡检批次失败: %v", err)
			} else if batch.Checked > 0 {
				log.Printf("[SiteWatch] 批次完成: 检查 %d, 变更 %d, 慢爬下发 %d",
					batch.Checked, batch.Changed, batch.Crawls)
			}
			pause := time.Duration(45+rand.Intn(30)) * time.Second
			select {
			case <-s.stopCh:
				return
			case <-time.After(pause):
			}
		}
	}()
}

func (s *SiteWatchService) Stop() {
	s.stopOnce.Do(func() { close(s.stopCh) })
}

// WatchBatchSummary 一批巡检的回执。
type WatchBatchSummary struct {
	Checked int `json:"checked"`
	Changed int `json:"changed"`
	Crawls  int `json:"crawls"`
	Skipped int `json:"skipped"`
}

// RunBatch 执行一批巡检。
func (s *SiteWatchService) RunBatch(ctx context.Context) (*WatchBatchSummary, error) {
	assets := repo.NewAssetRepo()
	sites, err := assets.SelectWatchSites(ctx, watchIntervalHours(), watchBatchSize())
	if err != nil {
		return nil, err
	}
	summary := &WatchBatchSummary{}
	for _, w := range sites {
		select {
		case <-ctx.Done():
			return summary, ctx.Err()
		default:
		}
		changed, crawl, err := s.CheckOne(ctx, w)
		if err != nil {
			log.Printf("[SiteWatch] %s:%d 巡检失败: %v", w.Host, w.Port, err)
			summary.Skipped++
			continue
		}
		summary.Checked++
		if changed {
			summary.Changed++
		}
		if crawl {
			summary.Crawls++
		}
		// 站与站之间 1-3s 抖动：全局压力再降一档
		select {
		case <-ctx.Done():
			return summary, ctx.Err()
		case <-time.After(time.Duration(1000+rand.Intn(2000)) * time.Millisecond):
		}
	}
	return summary, nil
}

// CheckOne 巡检单个站点：一次 GET → 两级 hash → 判定 → 记账/通知/慢爬。
func (s *SiteWatchService) CheckOne(ctx context.Context, w repo.WatchSite) (changed, crawled bool, err error) {
	port := w.Port
	if port == 0 {
		if w.Scheme == "https" {
			port = 443
		} else {
			port = 80
		}
	}
	url := fmt.Sprintf("%s://%s", w.Scheme, net_JoinHostPort(w.Host, port))

	pctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	snap, err := httpprobe.DoRequest(pctx, httpprobe.Request{
		URL:            url,
		TimeoutSeconds: 15,
	})
	if err != nil {
		// 站点可能已失联：不记 hash（存活状态归 autoverify 退避阶梯管），
		// 但要推进巡检时间戳——否则最旧优先会把队头永远让给失败站点
		_ = repo.NewAssetRepo().TouchSiteWatchChecked(ctx, w.SiteID)
		return false, false, fmt.Errorf("请求失败: %w", err)
	}

	rawHash := sha256Hex(snap.RespBody)
	textHash := sha256Hex(extractVisibleText(snap.RespBody))

	assets := repo.NewAssetRepo()
	firstSeen := w.ContentHash == "" && w.TextHash == ""
	// 判定：raw 同 → 无操作；raw 变 text 同 → 动态噪声（更新 raw）；text 变 → 真变更
	isChange := !firstSeen && w.TextHash != "" && w.TextHash != textHash
	if err := assets.UpdateSiteContentHash(ctx, w.SiteID, repo.ContentHashUpdate{
		RawHash: rawHash, TextHash: textHash, Changed: isChange,
	}); err != nil {
		return false, false, err
	}
	if firstSeen || !isChange {
		return false, false, nil
	}

	// 真变更：事件 + 通知 + 慢爬（单飞 + 同站冷却）
	log.Printf("[SiteWatch] 内容变更: %s (%s:%d)", url, w.Host, w.Port)
	_ = repo.NewAssetRepo().InsertEvent(ctx, w.ProjectID, w.SiteID, nil, "content_change",
		"页面内容变更",
		map[string]any{"text_hash": w.TextHash},
		map[string]any{"text_hash": textHash, "url": url})
	s.notify.NotifyAssetChange("站点页面内容变更", fmt.Sprintf(
		"站点 %s（%s:%d）页面内容发生变化，已排队慢速爬虫复核。前往资产详情查看。",
		w.Host, w.Host, w.Port),
		map[string]interface{}{"link": fmt.Sprintf("/assets/%d", w.SiteID)})

	crawled = s.maybeStartSlowCrawl(ctx, w, url)
	return true, crawled, nil
}

// maybeStartSlowCrawl 变更站点下发慢爬任务：全局单飞 + 同站 24h 冷却。
// 数据清洗守卫：站点实测 404/410 时不下发——对死页慢爬只是浪费请求，
// 等它恢复可达后巡检自然会再次触发。
func (s *SiteWatchService) maybeStartSlowCrawl(ctx context.Context, w repo.WatchSite, url string) bool {
	s.crawlMu.Lock()
	defer s.crawlMu.Unlock()

	assets := repo.NewAssetRepo()
	if status, err := assets.SiteHTTPStatus(ctx, w.SiteID); err == nil && repo.SiteDeadByStatus(status) {
		log.Printf("[SiteWatch] %s 实测 http %d，死站不下发慢爬", w.Host, status)
		return false
	}
	if running, err := assets.HasRunningWatchCrawl(ctx); err == nil && running {
		log.Printf("[SiteWatch] 已有慢爬任务在跑，%s 排队下轮", url)
		return false
	}
	if last, err := assets.LastWatchCrawlForSite(ctx, w.ProjectID, w.Scheme, w.Host); err == nil &&
		last != nil && time.Since(*last) < 24*time.Hour {
		log.Printf("[SiteWatch] %s 距上次慢爬不足 24h，跳过", url)
		return false
	}

	maxPages := 30
	depth := 2

	task := &models.Task{
		Name:       fmt.Sprintf("[站点巡检] %s 内容变更复核 %s", w.Host, time.Now().Format("0102-1504")),
		ProjectID:  w.ProjectID,
		Type:       models.TaskTypeCrawler,
		Targets:    []string{url},
		TargetType: "url",
		Status:     models.TaskStatusPending,
		Config: models.TaskConfig{
			// 纯爬虫轻任务：case 默认路径不改 PortScan/Fingerprint 之外，
			// 通过 WatchCrawl 标记让 executor 走最轻配置
			WatchCrawl:    true,
			RatePerSec:    2,
			TargetDelayMs: 1000,
			MaxDepth:      depth,
			MaxPages:      maxPages,
		},
	}
	if err := NewTaskService().CreateTask(task); err != nil {
		log.Printf("[SiteWatch] 慢爬任务创建失败 %s: %v", url, err)
		return false
	}
	log.Printf("[SiteWatch] 慢爬任务已下发: %s (task=%s, 2rps/depth2/%d页)", url, task.ID.Hex(), maxPages)
	return true
}

// ---------------------------------------------------------------------------
// 工具
// ---------------------------------------------------------------------------

// watchIntervalHours / watchBatchSize 巡检节奏参数（ZRE_SITEWATCH_* 环境变量可调）。
func watchIntervalHours() int {
	if n, err := strconv.Atoi(os.Getenv("ZRE_SITEWATCH_INTERVAL_HOURS")); err == nil && n >= 1 {
		return n
	}
	return 24
}

func watchBatchSize() int {
	if n, err := strconv.Atoi(os.Getenv("ZRE_SITEWATCH_BATCH")); err == nil && n >= 1 && n <= 50 {
		return n
	}
	return 5
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

var (
	scriptRe  = regexp.MustCompile(`(?is)<script[^>]*>[\s\S]*?</script>`)
	styleRe   = regexp.MustCompile(`(?is)<style[^>]*>[\s\S]*?</style>`)
	commentRe = regexp.MustCompile(`(?is)<!--[\s\S]*?-->`)
	tagRe     = regexp.MustCompile(`(?s)<[^>]+>`)
	spaceRe   = regexp.MustCompile(`\s+`)
)

// extractVisibleText 剥离 script/style/注释/标签，留可见文本（与页面监控口径一致）。
func extractVisibleText(html string) string {
	html = scriptRe.ReplaceAllString(html, " ")
	html = styleRe.ReplaceAllString(html, " ")
	html = commentRe.ReplaceAllString(html, " ")
	html = tagRe.ReplaceAllString(html, " ")
	return spaceRe.ReplaceAllString(html, " ")
}

// net_JoinHostPort 兼容 IPv6（host 可能是 v6 地址）。
func net_JoinHostPort(host string, port int) string {
	if len(host) > 0 && host[0] != '[' && countColons(host) > 1 {
		return "[" + host + "]:" + strconv.Itoa(port)
	}
	return host + ":" + strconv.Itoa(port)
}

func countColons(s string) int {
	n := 0
	for _, r := range s {
		if r == ':' {
			n++
		}
	}
	return n
}
