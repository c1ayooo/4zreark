package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/internal/entityid"
	"github.com/c1ayooo/4zreark/internal/llm"
	"github.com/c1ayooo/4zreark/repo"
	"github.com/cloudwego/eino/compose"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"
	"github.com/riverqueue/river/rivertype"
)

const (
	CollectionGateQueueName = "collection_gate"
	CollectionGateJobKind   = "collection_gate_raw"
)

// CollectionGateArgs 是一条待判定信号的唯一参数。
type CollectionGateArgs struct {
	RawID string `json:"raw_id" river:"unique"`
}

func (CollectionGateArgs) Kind() string { return CollectionGateJobKind }

// CollectionGate 执行 Gate 判定并落 trace。它不读扫描结果、不写结论字段，
// 只在独立队列里消费，绝不阻塞信息收集主链。
type CollectionGate struct {
	// fallback 是启动配置；实际模型每次 Evaluate 时由 EffectiveLLMConfig 解析，
	// 因此系统设置页保存后无需重启即可生效。
	fallback  config.LLMConfig
	store     *repo.CollectionAIRepo
	promptVer string

	mu          sync.RWMutex
	graph       compose.Runnable[GatePrompt, *gateRunOutput]
	modelName   string
	fingerprint string

	// 便于测试注入；生产使用 EffectiveLLMConfig 与 eino JSON 图。
	effective func(context.Context, config.LLMConfig) config.LLMConfig
	build     func(context.Context, config.LLMConfig) (compose.Runnable[GatePrompt, *gateRunOutput], error)
}

// NewCollectionGate 始终返回对象：未配置密钥时不在启动期熔断，
// 而是由 Evaluate 跳过并记日志，等系统设置页保存后自动恢复。
func NewCollectionGate(cfg config.LLMConfig) *CollectionGate {
	g := &CollectionGate{
		fallback:  cfg,
		store:     repo.NewCollectionAIRepo(),
		promptVer: "gate_v1",
	}
	g.effective = EffectiveLLMConfig
	g.build = func(ctx context.Context, live config.LLMConfig) (compose.Runnable[GatePrompt, *gateRunOutput], error) {
		cm, err := llm.NewJSONChatModel(ctx, live)
		if err != nil {
			return nil, err
		}
		return BuildGateGraph(ctx, cm, decodeGateVerdict)
	}
	return g
}

// ensureGraph 按「有效配置指纹」缓存 eino 图：配置不变复用，变化则重建。
func (g *CollectionGate) ensureGraph(ctx context.Context) (compose.Runnable[GatePrompt, *gateRunOutput], string, error) {
	if g == nil {
		return nil, "", fmt.Errorf("gate 未初始化")
	}
	effective := g.effective
	if effective == nil {
		effective = EffectiveLLMConfig
	}
	live := effective(ctx, g.fallback)
	fingerprint := llmConfigFingerprint(live)

	g.mu.RLock()
	graph, cachedFingerprint, model := g.graph, g.fingerprint, g.modelName
	g.mu.RUnlock()
	if graph != nil && cachedFingerprint == fingerprint {
		return graph, model, nil
	}

	build := g.build
	if build == nil {
		return nil, "", fmt.Errorf("gate 构建器未初始化")
	}
	graph, err := build(ctx, live)
	if err != nil {
		return nil, "", err
	}
	g.mu.Lock()
	g.graph = graph
	g.fingerprint = fingerprint
	g.modelName = live.Model
	g.mu.Unlock()
	return graph, live.Model, nil
}

// llmConfigFingerprint 不含明文密钥：只用于判断配置是否变化。
func llmConfigFingerprint(cfg config.LLMConfig) string {
	cfg.Normalize()
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%s|%s|%s|%.2f|%d|%d",
		cfg.BaseURL, cfg.Model, cfg.EffectiveAPIKey(), cfg.Temperature, cfg.MaxTokens, cfg.TimeoutSeconds)
	return hex.EncodeToString(h.Sum(nil))
}

// Evaluate 读原文快照 → 模型判定 → 写 ai_gate_verdicts。
// 没有快照/模型 partial 时不写判定，交给人工或下一轮补判。
func (g *CollectionGate) Evaluate(ctx context.Context, rawID string) error {
	if g == nil || g.store == nil {
		return nil
	}
	graph, modelName, err := g.ensureGraph(ctx)
	if err != nil {
		if errors.Is(err, llm.ErrNoKey) {
			log.Printf("[CollectionGate] 未配置模型密钥，跳过 raw=%s（保存设置后自动恢复）", rawID)
			return nil
		}
		return err
	}
	body, entityID, err := g.store.Snapshot(ctx, rawID)
	if err != nil {
		return nil // 没有快照不是错误：影子跑允许缺数据
	}
	body = strings.TrimSpace(body)
	if body == "" {
		return nil
	}

	start := time.Now()
	out, err := graph.Invoke(ctx, GatePrompt{
		System: gateSystemPrompt,
		User:   "标题/来源：未知\n摘要：\n" + gateTruncate(body, 800),
	})
	if err != nil {
		return err
	}
	if out == nil || out.Verdict == nil {
		log.Printf("[CollectionGate] raw=%s 判定输出不合法（partial），稍后补判: %s", rawID, out.LastError)
		return nil
	}
	verdictJSON, _ := json.Marshal(out.Verdict)
	if err := g.store.InsertGateVerdict(ctx, &repo.GateVerdictRow{
		RawID:         rawID,
		PromptVer:     g.promptVer,
		Model:         modelName,
		InputSnapshot: gateTruncate(body, 4000),
		VerdictJSON:   verdictJSON,
		Keep:          out.Verdict.Keep,
		Score:         out.Verdict.Score,
		LatencyMS:     int(time.Since(start).Milliseconds()),
	}); err != nil {
		return err
	}

	// enforce 才路由；shadow 只留 trace。路由失败不回滚 verdict，避免重复判定。
	if config.GetConfig().Collection.GateMode == "enforce" && out.Verdict.Keep {
		g.route(ctx, rawID, entityID, out.Verdict)
	}
	return nil
}

// route 把 Gate 结果结构化为 ai_items；只有 repo@ref 形态的实体才触发 diff_jobs。
// 站点类实体只落条目，不触发 diff（没有可比较的代码引用）。
func (g *CollectionGate) route(ctx context.Context, rawID, entityID string, v *GateVerdict) {
	if g.store == nil || v == nil {
		return
	}
	if entityID == "" {
		entityID = rawID
	}
	impact, _ := json.Marshal(map[string]any{
		"score": v.Score, "tags": v.Tags, "ambiguous": v.Ambiguous,
	})
	if err := g.store.InsertAIItem(ctx, &repo.AIItemRow{
		EntityID: entityID, RawID: rawID, Source: "collection_gate",
		Summary: v.Reason, ImpactJSON: impact, State: "new",
	}); err != nil {
		log.Printf("[CollectionGate] 写 ai_items 失败 raw=%s: %v", rawID, err)
		return
	}

	// 仅 repo@ref 形态触发 diff；ref 为空不触发。
	if i := strings.Index(entityID, "@"); i > 0 && i < len(entityID)-1 {
		ref := entityID[i+1:]
		key := entityid.DiffJobKey(entityID, time.Now().Format("2006-01-02"))
		if err := g.store.UpsertDiffJob(ctx, entityID, "", ref, "pending", key); err != nil {
			log.Printf("[CollectionGate] 写 diff_jobs 失败 entity=%s: %v", entityID, err)
		}
	}
}

func gateTruncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

type collectionGateWorker struct {
	river.WorkerDefaults[CollectionGateArgs]
	gate *CollectionGate
}

func (w *collectionGateWorker) Work(ctx context.Context, job *river.Job[CollectionGateArgs]) error {
	if w.gate == nil {
		return nil
	}
	return sentinelJobError(w.gate.Evaluate(ctx, job.Args.RawID))
}

// CollectionGateQueue 是独立的 River 客户端。影子模式下只消费、不入队，
// 主链（扫描/判定）不会因为 Gate 慢而阻塞。
type CollectionGateQueue struct {
	client     *river.Client[pgx.Tx]
	workerMode bool
}

var (
	collectionGateMu sync.RWMutex
	collectionGateQ  *CollectionGateQueue
)

func SetDefaultCollectionGateQueue(q *CollectionGateQueue) {
	collectionGateMu.Lock()
	collectionGateQ = q
	collectionGateMu.Unlock()
}

func DefaultCollectionGateQueue() *CollectionGateQueue {
	collectionGateMu.RLock()
	defer collectionGateMu.RUnlock()
	return collectionGateQ
}

func NewCollectionGateQueue(ctx context.Context, pool *pgxpool.Pool, gate *CollectionGate, workers int, workerMode bool) (*CollectionGateQueue, error) {
	if pool == nil {
		return nil, fmt.Errorf("Gate 队列缺少 PostgreSQL 连接池")
	}
	if workers <= 0 {
		workers = 4
	}
	driver := riverpgxv5.New(pool)
	migrator, err := rivermigrate.New(driver, nil)
	if err != nil {
		return nil, err
	}
	if _, err := migrator.Migrate(ctx, rivermigrate.DirectionUp, nil); err != nil {
		return nil, err
	}
	cfg := &river.Config{
		MaxAttempts:          3,
		JobTimeout:           30 * time.Minute,
		RescueStuckJobsAfter: 90 * time.Minute,
		SoftStopTimeout:      30 * time.Second,
	}
	if workerMode {
		w := river.NewWorkers()
		river.AddWorker(w, &collectionGateWorker{gate: gate})
		cfg.Workers = w
		cfg.Queues = map[string]river.QueueConfig{
			CollectionGateQueueName: {MaxWorkers: workers},
		}
	}
	client, err := river.NewClient(driver, cfg)
	if err != nil {
		return nil, err
	}
	return &CollectionGateQueue{client: client, workerMode: workerMode}, nil
}

func (q *CollectionGateQueue) Enqueue(ctx context.Context, rawID string) error {
	if q == nil || q.client == nil {
		return fmt.Errorf("Gate 队列未初始化")
	}
	_, err := q.client.Insert(ctx, CollectionGateArgs{RawID: rawID}, &river.InsertOpts{
		Queue:       CollectionGateQueueName,
		MaxAttempts: 3,
		UniqueOpts: river.UniqueOpts{
			ByArgs: true,
			ByState: []rivertype.JobState{
				rivertype.JobStateAvailable, rivertype.JobStatePending,
				rivertype.JobStateRetryable, rivertype.JobStateRunning,
				rivertype.JobStateScheduled,
			},
		},
	})
	return err
}

func (q *CollectionGateQueue) Start(ctx context.Context) error {
	if q == nil || !q.workerMode {
		return nil
	}
	return q.client.Start(ctx)
}

func (q *CollectionGateQueue) Stop(ctx context.Context) error {
	if q == nil || !q.workerMode {
		return nil
	}
	return q.client.Stop(ctx)
}
