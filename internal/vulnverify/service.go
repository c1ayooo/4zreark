// Package vulnverify —— 指纹命中后的自动 nuclei 最小验证（docs/archive/nuclei自动验证方案.md P3）。
//
// 定位：只回答「该已知漏洞是否存在」——对指纹识别出的产品，召回确定性边对应的
// nuclei 模板（默认仅 critical/high/medium、http 类），后台串行执行最小验证；
// 命中经注入的 RecordHit 回调走平台既有漏洞落库/证据/通知链路，未命中只记台账。
//
// 安全边界（fail-closed）：
//   - 每个目标执行前过 ScopeCheck（项目授权范围），拒绝即 skipped_out_of_scope；
//   - 只允许 http/ 前缀模板（Recall 侧过滤，排除 network/file/code/javascript 队列）；
//   - 目标必须来自本轮指纹探活结果（调用方保证，见 infocollect 钩子）；
//   - 资源上限硬编码（单任务超时/速率/重试），配置只能调小不能放大。
//
// 解耦：本包不 import knowledge/componentprofile/notify——模板召回（Recall）、
// 命中落库（RecordHit）、scope 校验（ScopeCheck）均由 app 层注入闭包；执行器
// （Runner）可注入以便测试。
package vulnverify

import (
	"context"
	"log"
	"sync"
	"time"
)

// TemplateRef 召回出的一条模板（Path 相对模板根，如 http/cves/2021/x.yaml）。
type TemplateRef struct {
	ID       string `json:"id"`
	Path     string `json:"path"`
	Severity string `json:"severity"`
}

// Task 一次验证任务。
type Task struct {
	ProjectID string
	Target    string
	Product   string
}

// HitResult 一次命中的结构化结果（RecordHit 消费：落库+证据+通知+提取链）。
type HitResult struct {
	VulnTitle           string
	Severity            string
	ProjectID           string
	Target              string
	Product             string
	TemplateID          string
	TemplateName        string // 模板 info.name（nuclei JSONL，可空）
	TemplateDescription string // 模板 info.description（nuclei JSONL，可空；用于填充 impact）
	TemplateSeverity    string
	MatchedAt           string
	Host                string   // nuclei JSONL 命中 host（可空）
	ExtractedResults    []string // nuclei JSONL 里的 extracter/extra 结果片段（可空）
	Request             string   // nuclei JSONL 原始请求报文（提取链原料）
	Response            string   // nuclei JSONL 原始响应报文（提取链原料，如 phpinfo HTML）
	CurlCommand         string   // nuclei JSONL curl 复现命令（备份文件复现下载用）
	RawOutput           string   // 完整 stdout（证据正文，调用方自行截断）
	Command             string   // 复现命令行（poc_script 用）
}

// Options 服务选项。func 字段每次执行时现场读取（配置热更新免重启）。
type Options struct {
	// DB 任务台账存储（nil = 内存去重，仅测试用）。
	Store JobStore
	// Cfg 动态读取自动验证配置。
	Cfg func() Config
	// BinPath 动态解析 nuclei 二进制（nucleiruntime.LocalBinary）。
	BinPath func() string
	// JSONFlagFunc 动态探测二进制的 JSON 输出旗标（nucleiruntime.JSONFlag；
	// v3.11+ 为 -jsonl，旧版 -json）。nil = 写死 -json（旧版语义）。
	JSONFlagFunc func(binPath string) string
	// TemplatesRoot 动态解析模板根目录。
	TemplatesRoot func() string
	// CustomTemplatesRoot 动态解析自定义模板根目录（知识库分域方案 P2；可空）。
	// 模板文件在官方根缺失时按序回落自定义根解析（-t 双目录语义）。
	CustomTemplatesRoot func() string
	// ProxyURLFunc 动态读取 nuclei 执行的出站代理（nil/空 = 继承环境变量）。
	ProxyURLFunc func() string
	// Recall 模板召回（确定性边 + catalog 映射 + severity/http 过滤）。
	Recall func(ctx context.Context, projectID, product string) ([]TemplateRef, error)
	// Severities 动态读取参与自动验证的严重级集合（与模板灌库同源：
	// config.Nuclei.Templates.SeverityFilterEffective）。
	Severities func() []string
	// ScopeCheck 项目授权范围硬校验（fail-closed；nil = 拒绝全部——无 scope 能力不自动打）。
	ScopeCheck func(ctx context.Context, projectID, target string) error
	// RecordHit 命中落库回调（漏洞+证据+通知，app 胶水复用既有链路）；返回漏洞 id。
	RecordHit func(ctx context.Context, hit HitResult) (string, error)
	// Runner 命令执行器（nil = 默认 exec）；测试注入假执行器。
	Runner func(ctx context.Context, binPath string, args []string, timeout time.Duration) (string, error)
	// OnJobDone 任务完结回调（可选：通知聚合等）。
	OnJobDone func(jobID, status string)
}

// Service 自动验证服务：队列 + 串行 worker（并发可配，默认 1）。
type Service struct {
	opts Options

	mu      sync.Mutex
	queue   chan Task
	cancel  context.CancelFunc
	running bool
}

// New 创建服务（不启动 worker；Start 才消费队列）。
func New(opts Options) *Service {
	return &Service{opts: opts}
}

// Start 启动 worker 池。重复调用为空操作。
func (s *Service) Start(ctx context.Context) {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	ctx, s.cancel = context.WithCancel(ctx)
	s.queue = make(chan Task, 256)
	s.running = true
	queue := s.queue
	s.mu.Unlock()

	workers := 1
	if s.opts.Cfg != nil {
		workers = s.opts.Cfg().ConcurrencyEffective()
	}
	if workers < 1 {
		workers = 1
	}
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case task, ok := <-queue:
					if !ok {
						return
					}
					s.process(ctx, task)
				}
			}
		}()
	}
	go func() {
		<-ctx.Done()
		wg.Wait()
	}()
}

// Stop 停止 worker 并等待退出。
func (s *Service) Stop() {
	s.mu.Lock()
	cancel := s.cancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// Enqueue 投递任务：台账去重（recheck 窗口内已完结/待跑的同 (target, product) 跳过），
// 队列满则丢弃（记 debug，下轮指纹再触发）。指纹扫描路径上的非关键旁路，永不阻塞。
func (s *Service) Enqueue(task Task) {
	if task.Target == "" || task.Product == "" {
		return
	}
	recheckDays := 7
	if s.opts.Cfg != nil {
		recheckDays = s.opts.Cfg().RecheckDaysEffective()
	}
	if s.opts.Store != nil {
		queued, err := s.opts.Store.EnqueueJob(context.Background(), task, recheckDays)
		if err != nil {
			log.Printf("[vulnverify] 任务入账失败 target=%s product=%s: %v", task.Target, task.Product, err)
			return
		}
		if !queued {
			return // recheck 窗口内已有结论/排队中
		}
	}
	s.mu.Lock()
	q := s.queue
	s.mu.Unlock()
	if q == nil {
		return // 未 Start：丢弃（台账里仍是 queued，下轮重新触发时再入队）
	}
	select {
	case q <- task:
	default:
		log.Printf("[vulnverify] 队列已满，任务丢弃 target=%s product=%s", task.Target, task.Product)
	}
}
