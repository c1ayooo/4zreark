package service

import (
	"context"
	"log"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/repo"
)

// 自动存活验证：新扫描/导入的站点（state=pending、attempts=0）由后台按批次
// 真实探测，不再依赖人工点「探测」或治理 run。
//
// 只选有 HTTP 入口的站点；每批默认 20 个、并发 4、间隔 30 秒，避免把新资产
// 一次性全部打出去。可通过 ZRE_AUTOVERIFY_* 调整；设为 0 可关闭。

type AutoVerifyStats struct {
	Picked       int `json:"picked"`
	Reachable    int `json:"reachable"`
	Dead         int `json:"dead"`
	Inconclusive int `json:"inconclusive"`
	Failed       int `json:"failed"`
}

type AutoVerifyService struct {
	parallel int
	limit    int
	interval time.Duration
	delay    time.Duration
	stop     chan struct{}
	once     sync.Once
}

func envIntDefault(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func NewAutoVerifyService() *AutoVerifyService {
	parallel := envIntDefault("ZRE_AUTOVERIFY_PARALLEL", 4)
	if parallel < 1 || parallel > 32 {
		parallel = 4
	}
	limit := envIntDefault("ZRE_AUTOVERIFY_LIMIT", 20)
	if limit < 1 || limit > 500 {
		limit = 20
	}
	sec := envIntDefault("ZRE_AUTOVERIFY_INTERVAL_SEC", 30)
	if sec < 5 {
		sec = 30
	}
	delayMS := envIntDefault("ZRE_AUTOVERIFY_DELAY_MS", 200)
	if delayMS < 0 || delayMS > 10000 {
		delayMS = 200
	}
	return &AutoVerifyService{
		parallel: parallel, limit: limit, interval: time.Duration(sec) * time.Second,
		delay: time.Duration(delayMS) * time.Millisecond,
		stop:  make(chan struct{}),
	}
}

// RunOnce 验证一批候选站点；projectID=0 表示全部项目。
func (s *AutoVerifyService) RunOnce(ctx context.Context, projectID int64, limit int) (*AutoVerifyStats, error) {
	if repo.Default() == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = s.limit
	}
	ids, err := repo.NewAssetRepo().PendingVerificationSiteIDs(ctx, projectID, limit)
	if err != nil {
		return nil, err
	}
	stats := &AutoVerifyStats{Picked: len(ids)}
	if len(ids) == 0 {
		return stats, nil
	}

	verifier := NewVerifyService()
	sem := make(chan struct{}, s.parallel)
	var (
		wg sync.WaitGroup
		mu sync.Mutex
	)
	for _, id := range ids {
		if s.delay > 0 {
			time.Sleep(s.delay)
		}
		wg.Add(1)
		go func(siteID int64) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			report, perr := verifier.ProbeSite(ctx, siteID)
			mu.Lock()
			defer mu.Unlock()
			if perr != nil {
				stats.Failed++
				return
			}
			switch report.Verdict {
			case "reachable":
				stats.Reachable++
			case "inconclusive":
				stats.Inconclusive++
			default:
				stats.Dead++
			}
		}(id)
	}
	wg.Wait()
	log.Printf("[AutoVerify] picked=%d reachable=%d dead=%d inconclusive=%d failed=%d",
		stats.Picked, stats.Reachable, stats.Dead, stats.Inconclusive, stats.Failed)
	return stats, nil
}

// Tick 是后台循环的单步：跳过已经取消的上下文。
func (s *AutoVerifyService) Tick(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	if _, err := s.RunOnce(ctx, 0, s.limit); err != nil {
		log.Printf("[AutoVerify] %v", err)
	}
}

// Start 启动后台循环：10 秒后首轮，之后按间隔。
func (s *AutoVerifyService) Start() {
	s.once.Do(func() {
		go func() {
			select {
			case <-s.stop:
				return
			case <-time.After(10 * time.Second):
			}
			for {
				s.Tick(context.Background())
				select {
				case <-s.stop:
					return
				case <-time.After(s.interval):
				}
			}
		}()
	})
}

func (s *AutoVerifyService) Stop() {
	select {
	case <-s.stop:
	default:
		close(s.stop)
	}
}
