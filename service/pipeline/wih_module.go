package pipeline

import (
	"context"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/c1ayooo/4zreark/internal/recon/wih"
)

// WihResult WIH 接口候选探测结果
// 由 WihProbe 模块产出：从目标页面/JS 词法提取接口候选，
// 并在同源范围内受控探测后得到的结论列表。
type WihResult struct {
	Target    string              `json:"target"`    // 被提取分析的页面 URL
	Endpoints []wih.ProbeEndpoint `json:"endpoints"` // 探测结论列表
}

// WihConfig WihProbe 模块配置
type WihConfig struct {
	// Enabled 是否启用；关闭时模块对输入纯透传
	Enabled bool
	// Concurrency 单页处理并发数
	Concurrency int
	// MaxPageBytes 页面抓取大小上限（字节），默认 512KiB
	MaxPageBytes int64
	// Probe 同源受控探测配置，零值字段自动补默认值
	Probe wih.Config
}

// DefaultWihConfig 返回默认模块配置。
func DefaultWihConfig() WihConfig {
	return WihConfig{
		Enabled:      true,
		Concurrency:  4,
		MaxPageBytes: 512 << 10,
		Probe:        wih.DefaultConfig(),
	}
}

// WihProbeModule WIH 接口候选探测模块
// 接收 AssetHttp（有 URL）与 UrlResult（有 URL），抓取页面文本
// （text/html 或 javascript，大小上限 MaxPageBytes），做词法级接口
// 提取后同源受控探测，产出 WihResult 写入 out。
// 与 sensitive/crawler 模块的 nextModule 链式写法不同，本模块显式接收
// in/out 通道；输入原样透传到 out（crawler_module 的惯例），out 由本模块
// 在退出时负责关闭——调用方需保证 out 只由本模块写入和关闭。
type WihProbeModule struct {
	BaseModule
	out        chan interface{}
	cfg        WihConfig
	prober     *wih.Prober
	sem        chan struct{}
	resultChan chan interface{}
	workerWg   sync.WaitGroup
	done       chan struct{}
	enabled    atomic.Bool
}

// NewWihProbeModule 创建 WIH 探测模块。
// in 为上游输入通道，out 为下游输出通道；cfg.Enabled 为 false 时模块纯透传。
func NewWihProbeModule(ctx context.Context, in chan any, out chan any, cfg WihConfig) *WihProbeModule {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 4
	}
	if cfg.MaxPageBytes <= 0 {
		cfg.MaxPageBytes = 512 << 10
	}
	// NormalizeConfig 保证后续直接读取 PerSiteBudget 等字段时非零
	cfg.Probe = wih.NormalizeConfig(cfg.Probe)

	m := &WihProbeModule{
		BaseModule: BaseModule{
			name:       "WihProbe",
			ctx:        ctx,
			dupChecker: NewDuplicateChecker(),
		},
		out:        out,
		cfg:        cfg,
		prober:     wih.NewProber(cfg.Probe),
		sem:        make(chan struct{}, cfg.Concurrency),
		resultChan: make(chan interface{}, 500),
		done:       make(chan struct{}),
	}
	m.SetInput(in)
	m.enabled.Store(cfg.Enabled)
	return m
}

// SetEnabled 动态开关；Start 之后修改对后续处理的 URL 生效。
func (m *WihProbeModule) SetEnabled(v bool) { m.enabled.Store(v) }

// Start 启动模块 goroutine，立即返回。退出时自动关闭 out。
func (m *WihProbeModule) Start() {
	go func() {
		if err := m.run(); err != nil {
			log.Printf("[%s] Module error: %v", m.name, err)
		}
	}()
}

// Wait 等待模块完全退出（含结果写出与 out 关闭）。
func (m *WihProbeModule) Wait() { <-m.done }

// ModuleRun 同步运行模块，兼容 ModuleRunner 链式用法（与 Start 二选一）。
func (m *WihProbeModule) ModuleRun() error { return m.run() }

// run 主循环：读 in → 透传 → 按类型派发处理；退出时收拢 worker 并关闭 out。
func (m *WihProbeModule) run() error {
	defer close(m.done)
	m.ReportModuleStart(0)
	defer m.ReportModuleComplete()

	// 链式接入：链上每个模块负责拉起自己的下游。本模块的 nextModule
	// 不参与数据转发（数据走显式 out），仅用于启动下游 ModuleRun。
	if m.nextModule != nil {
		go func() {
			if err := m.nextModule.ModuleRun(); err != nil {
				log.Printf("[%s] Next module error: %v", m.name, err)
			}
		}()
	}

	// 结果转发协程：resultChan -> out
	fwdDone := make(chan struct{})
	go func() {
		defer close(fwdDone)
		for r := range m.resultChan {
			select {
			case <-m.ctx.Done():
				return
			case m.out <- r:
			}
		}
	}()

	defer func() {
		m.workerWg.Wait()
		close(m.resultChan)
		<-fwdDone
		if m.out != nil {
			close(m.out)
		}
	}()

	for {
		select {
		case <-m.ctx.Done():
			return nil

		case data, ok := <-m.input:
			if !ok {
				log.Printf("[%s] Input closed, waiting for workers", m.name)
				return nil
			}

			// 先透传原始数据（crawler_module 惯例），再按类型决定是否处理
			if !m.forward(data) {
				return nil
			}
			m.dispatch(data)
		}
	}
}

// forward 把数据写到 out，ctx 取消时返回 false。
func (m *WihProbeModule) forward(data interface{}) bool {
	if m.out == nil {
		return true
	}
	select {
	case <-m.ctx.Done():
		return false
	case m.out <- data:
		return true
	}
}

// dispatch 按类型提取目标 URL 并派发 worker；不认识的类型只透传不处理。
func (m *WihProbeModule) dispatch(data interface{}) {
	var target string
	switch v := data.(type) {
	case AssetHttp:
		target = v.URL
	case UrlResult:
		target = v.Output
	default:
		return
	}
	if target == "" || !m.enabled.Load() {
		return
	}
	// 同一 URL 只处理一次
	if m.dupChecker.IsURLDuplicate(target) {
		return
	}

	m.workerWg.Add(1)
	go func(url string) {
		defer m.workerWg.Done()
		m.sem <- struct{}{}
		defer func() { <-m.sem }()
		// 单 URL 处理互相隔离，panic 不拖垮主流
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[%s] Recovered from panic while processing %s: %v", m.name, url, r)
			}
		}()
		m.process(url)
	}(target)
}

// process 抓取页面文本 → 词法提取候选 → 同源受控探测 → 产出 WihResult。
func (m *WihProbeModule) process(target string) {
	// 抓页面的超时独立于探测预算
	ctx, cancel := context.WithTimeout(m.ctx, 30*time.Second)
	defer cancel()

	body, contentType, ok := m.prober.FetchPage(ctx, target, m.cfg.MaxPageBytes)
	if !ok {
		return
	}
	// 只处理 HTML 页面与 JS 文本，其它类型没有提取价值
	lowerCT := strings.ToLower(contentType)
	if !strings.Contains(lowerCT, "html") && !strings.Contains(lowerCT, "javascript") {
		return
	}

	candidates := wih.ExtractEndpoints(target, body)
	if len(candidates) == 0 {
		return
	}

	result := m.prober.ProbeSite(m.ctx, target, candidates)
	if result == nil || len(result.Endpoints) == 0 {
		return
	}

	log.Printf("[%s] %s: %d candidates, %d probed, %d verified",
		m.name, target, len(candidates), result.Probed, countVerified(result.Endpoints))

	m.ReportOutput(1)
	select {
	case <-m.ctx.Done():
	case m.resultChan <- WihResult{Target: target, Endpoints: result.Endpoints}:
	}
}

// countVerified 统计可验证的端点数，仅用于日志。
func countVerified(eps []wih.ProbeEndpoint) int {
	n := 0
	for _, ep := range eps {
		if ep.Verified {
			n++
		}
	}
	return n
}
