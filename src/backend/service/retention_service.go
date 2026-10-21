package service

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/repo"
)

// 数据保留策略：scan_results / raw_records / verifications / asset_events
// 按天批量清理。默认每天跑一次；HTTP 入口可手动触发与 dry-run。
//
// 默认值刻意保守：scan_results 90 天、raw_records 180 天、verifications 90 天，
// asset_events 继续沿用「最多 1 万条 + 7 天」。把某张表的 days 配成 0 即关闭该表清理。

type RetentionPolicy struct {
	ScanResultsDays   int `json:"scan_results_days"`
	RawRecordsDays    int `json:"raw_records_days"`
	VerificationsDays int `json:"verifications_days"`
	EventsKeep        int `json:"events_keep"`
	EventsDays        int `json:"events_days"`
	BatchLimit        int `json:"batch_limit"`
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// DefaultRetentionPolicy 从环境变量读取，未配置用内置默认值。
func DefaultRetentionPolicy() RetentionPolicy {
	p := RetentionPolicy{
		ScanResultsDays:   envInt("ZRE_RETENTION_SCAN_RESULTS_DAYS", 90),
		RawRecordsDays:    envInt("ZRE_RETENTION_RAW_RECORDS_DAYS", 180),
		VerificationsDays: envInt("ZRE_RETENTION_VERIFICATIONS_DAYS", 90),
		EventsKeep:        envInt("ZRE_RETENTION_EVENTS_KEEP", 10000),
		EventsDays:        envInt("ZRE_RETENTION_EVENTS_DAYS", 7),
		BatchLimit:        envInt("ZRE_RETENTION_BATCH", 10000),
	}
	return p.normalized()
}

func (p RetentionPolicy) normalized() RetentionPolicy {
	if p.ScanResultsDays < 0 {
		p.ScanResultsDays = 0
	}
	if p.RawRecordsDays < 0 {
		p.RawRecordsDays = 0
	}
	if p.VerificationsDays < 0 {
		p.VerificationsDays = 0
	}
	if p.EventsKeep <= 0 {
		p.EventsKeep = 10000
	}
	if p.EventsDays <= 0 {
		p.EventsDays = 7
	}
	if p.BatchLimit <= 0 || p.BatchLimit > 50000 {
		p.BatchLimit = 10000
	}
	return p
}

// RetentionReport 是一次清理的回执。
type RetentionReport struct {
	Policy        RetentionPolicy `json:"policy"`
	DryRun        bool            `json:"dry_run"`
	ScanResults   int64           `json:"scan_results"`
	RawRecords    int64           `json:"raw_records"`
	Verifications int64           `json:"verifications"`
	Events        int64           `json:"events"`
	DurationMS    int64           `json:"duration_ms"`
	Errors        []string        `json:"errors,omitempty"`
}

// RetentionService 负责定时清理历史流水。
type RetentionService struct {
	policy RetentionPolicy
	stop   chan struct{}
	once   sync.Once
}

func NewRetentionService() *RetentionService {
	return &RetentionService{policy: DefaultRetentionPolicy(), stop: make(chan struct{})}
}

// NewRetentionServiceWithPolicy 供测试与运维脚本注入策略。
func NewRetentionServiceWithPolicy(p RetentionPolicy) *RetentionService {
	return &RetentionService{policy: p.normalized(), stop: make(chan struct{})}
}

func (s *RetentionService) Policy() RetentionPolicy { return s.policy }

const retentionMaxBatches = 20

// RunOnce 执行一轮清理；dryRun 只统计不删除。
func (s *RetentionService) RunOnce(ctx context.Context, dryRun bool, actor, ip string) (*RetentionReport, error) {
	r := repo.Default()
	if r == nil {
		return nil, fmt.Errorf("数据层未初始化")
	}
	start := time.Now()
	rep := &RetentionReport{Policy: s.policy, DryRun: dryRun}

	runTable := func(name string, days int, count func() (int64, error), purge func() (int64, error)) {
		if days <= 0 {
			return
		}
		if dryRun {
			n, err := count()
			if err != nil {
				rep.Errors = append(rep.Errors, name+": "+err.Error())
				return
			}
			rep.set(name, n)
			return
		}
		var total int64
		for i := 0; i < retentionMaxBatches; i++ {
			n, err := purge()
			if err != nil {
				rep.Errors = append(rep.Errors, name+": "+err.Error())
				return
			}
			total += n
			if n < int64(s.policy.BatchLimit) {
				break
			}
		}
		rep.set(name, total)
	}

	runTable("scan_results", s.policy.ScanResultsDays,
		func() (int64, error) { return r.RetentionCount(ctx, "scan_results", s.policy.ScanResultsDays) },
		func() (int64, error) { return r.PurgeScanResults(ctx, s.policy.ScanResultsDays, s.policy.BatchLimit) },
	)
	runTable("verifications", s.policy.VerificationsDays,
		func() (int64, error) { return r.RetentionCount(ctx, "verifications", s.policy.VerificationsDays) },
		func() (int64, error) {
			return r.PurgeVerifications(ctx, s.policy.VerificationsDays, s.policy.BatchLimit)
		},
	)

	// raw_records 需要先取受害者 ID，再在事务里摘引用；dry-run 只计数。
	if s.policy.RawRecordsDays > 0 {
		if dryRun {
			n, err := r.RetentionCount(ctx, "raw_records", s.policy.RawRecordsDays)
			if err != nil {
				rep.Errors = append(rep.Errors, "raw_records: "+err.Error())
			} else {
				rep.RawRecords = n
			}
		} else {
			var total int64
			for i := 0; i < retentionMaxBatches; i++ {
				ids, err := r.RawRecordVictims(ctx, s.policy.RawRecordsDays, s.policy.BatchLimit)
				if err != nil {
					rep.Errors = append(rep.Errors, "raw_records: "+err.Error())
					break
				}
				if len(ids) == 0 {
					break
				}
				n, err := r.PurgeRawRecords(ctx, ids)
				if err != nil {
					rep.Errors = append(rep.Errors, "raw_records: "+err.Error())
					break
				}
				total += n
				if len(ids) < s.policy.BatchLimit {
					break
				}
			}
			rep.RawRecords = total
		}
	}

	if dryRun {
		n, err := r.RetentionCount(ctx, "asset_events", s.policy.EventsDays)
		if err != nil {
			rep.Errors = append(rep.Errors, "asset_events: "+err.Error())
		} else {
			rep.Events = n
		}
	} else {
		n, err := repo.NewAssetRepo().PruneEvents(ctx, s.policy.EventsKeep, s.policy.EventsDays)
		if err != nil {
			rep.Errors = append(rep.Errors, "asset_events: "+err.Error())
		} else {
			rep.Events = n
		}
	}

	rep.DurationMS = time.Since(start).Milliseconds()
	if actor == "" {
		actor = "system"
	}
	if !dryRun {
		target := "manual"
		if actor == "system" {
			target = "scheduled"
		}
		_ = r.LogOperation(ctx, repo.OperationLogInput{
			Username:  actor,
			Action:    "retention_run",
			Module:    "data_retention",
			Target:    target,
			Detail:    fmt.Sprintf("清理 scan_results=%d raw_records=%d verifications=%d events=%d", rep.ScanResults, rep.RawRecords, rep.Verifications, rep.Events),
			IP:        ip,
			UserAgent: "governance/retention",
		})
	}
	log.Printf("[Retention] dry_run=%v scan_results=%d raw_records=%d verifications=%d events=%d errors=%d",
		dryRun, rep.ScanResults, rep.RawRecords, rep.Verifications, rep.Events, len(rep.Errors))
	return rep, nil
}

func (r *RetentionReport) set(table string, n int64) {
	switch table {
	case "scan_results":
		r.ScanResults = n
	case "verifications":
		r.Verifications = n
	}
}

// Start 启动每日清理：启动 1 分钟后先跑一轮，之后每 24 小时一次。
func (s *RetentionService) Start() {
	s.once.Do(func() {
		go func() {
			timer := time.NewTimer(time.Minute)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-s.stop:
				return
			}
			for {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
				_, _ = s.RunOnce(ctx, false, "system", "")
				cancel()
				select {
				case <-time.After(24 * time.Hour):
				case <-s.stop:
					return
				}
			}
		}()
	})
}

func (s *RetentionService) Stop() {
	select {
	case <-s.stop:
	default:
		close(s.stop)
	}
}
