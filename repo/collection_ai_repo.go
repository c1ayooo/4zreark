package repo

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// GateVerdictRow 是 ai_gate_verdicts 的一行。AI 只写判定字段，不写结论。
type GateVerdictRow struct {
	RawID         string
	PromptVer     string
	Model         string
	InputSnapshot string
	VerdictJSON   []byte
	Keep          bool
	Score         float64
	LatencyMS     int
}

// SnapshotRow 是 raw_snapshots 的一行，对应一条 raw_record 的原文快照。
type SnapshotRow struct {
	RawID       string
	TaskID      string
	EntityID    string
	Source      string
	Body        string
	ContentHash string
}

// AIItemRow 是 Gate 判定 keep 后结构化的条目。
type AIItemRow struct {
	EntityID   string
	RawID      string
	Source     string
	Summary    string
	ImpactJSON []byte
	State      string
}

// CollectionAIRepo 访问 raw_snapshots / ai_gate_verdicts / ai_items / diff_jobs。
type CollectionAIRepo struct {
	pool *pgxpool.Pool
}

func NewCollectionAIRepo() *CollectionAIRepo {
	r := Default()
	if r == nil || r.Pool() == nil {
		return nil
	}
	return &CollectionAIRepo{pool: r.Pool()}
}

// Snapshot 取某条 raw 的原文与实体键；没有快照时返回空串（Gate 直接跳过）。
func (r *CollectionAIRepo) Snapshot(ctx context.Context, rawID string) (body, entityID string, err error) {
	if r == nil || r.pool == nil {
		return "", "", fmt.Errorf("数据层未初始化")
	}
	err = r.pool.QueryRow(ctx, `
		select body, entity_id from raw_snapshots
		 where raw_id = $1
		 order by fetched_at desc
		 limit 1`, rawID).Scan(&body, &entityID)
	return body, entityID, err
}

// UpsertSnapshot 幂等写原文快照。同一 raw + 同一内容不会重复落盘。
func (r *CollectionAIRepo) UpsertSnapshot(ctx context.Context, s *SnapshotRow) error {
	if r == nil || r.pool == nil {
		return fmt.Errorf("数据层未初始化")
	}
	_, err := r.pool.Exec(ctx, `
		insert into raw_snapshots (raw_id, task_id, entity_id, source, body, content_hash, fetched_at)
		values ($1, nullif($2,''), $3, $4, $5, $6, now())
		on conflict (raw_id, content_hash) do update set fetched_at = now()`,
		s.RawID, s.TaskID, s.EntityID, s.Source, s.Body, s.ContentHash)
	return err
}

func (r *CollectionAIRepo) InsertGateVerdict(ctx context.Context, v *GateVerdictRow) error {
	if r == nil || r.pool == nil {
		return fmt.Errorf("数据层未初始化")
	}
	_, err := r.pool.Exec(ctx, `
		insert into ai_gate_verdicts
		  (raw_id, prompt_ver, model, input_snapshot, verdict, keep, score, latency_ms)
		values ($1,$2,$3,$4,$5,$6,$7,$8)`,
		v.RawID, v.PromptVer, v.Model, v.InputSnapshot, v.VerdictJSON, v.Keep, v.Score, v.LatencyMS)
	return err
}

// InsertAIItem 写结构化条目；只有 enforce 且 keep 时才调用。
func (r *CollectionAIRepo) InsertAIItem(ctx context.Context, item *AIItemRow) error {
	if r == nil || r.pool == nil {
		return fmt.Errorf("数据层未初始化")
	}
	if item.State == "" {
		item.State = "new"
	}
	_, err := r.pool.Exec(ctx, `
		insert into ai_items (entity_id, raw_id, source, summary, impact, state)
		values ($1,$2,$3,$4,$5::jsonb,$6)`,
		item.EntityID, item.RawID, item.Source, item.Summary, item.ImpactJSON, item.State)
	return err
}

// UpsertDiffJob 按 idempotency_key 幂等触发 diff 分析。
func (r *CollectionAIRepo) UpsertDiffJob(ctx context.Context, entityID, fromRef, toRef, status, idemKey string) error {
	if r == nil || r.pool == nil {
		return fmt.Errorf("数据层未初始化")
	}
	if status == "" {
		status = "pending"
	}
	_, err := r.pool.Exec(ctx, `
		insert into diff_jobs (entity_id, from_ref, to_ref, status, idempotency_key)
		values ($1,$2,$3,$4,$5)
		on conflict (idempotency_key) do nothing`,
		entityID, fromRef, toRef, status, idemKey)
	return err
}
