package githubleak

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/c1ayooo/4zreark/internal/lz"
)

const (
	// freshnessPolicyVersion 回溯策略版本：版本或窗口变化时旧游标/ETag 整体失效。
	freshnessPolicyVersion   = "path-commit-v1"
	freshnessRecheckInterval = 24 * time.Hour
	// maxFreshnessChecksPerRun 单轮路径提交校验总预算（跨规则公平分配，未用完的
	// 额度留给后续规则；预算耗尽时游标续跑，下一轮从断点继续而非重头再来）。
	maxFreshnessChecksPerRun = 200
	// maxSearchPagesPerRule GitHub legacy code search 硬上限：page≤10 × per_page≤100，
	// 即每规则可达 Universe 封顶 1000 条。翻页游标在此范围内跨轮滚动。
	maxSearchPagesPerRule = 10
	// maxSourceFutureSkew 允许的时钟偏移：提交时间超前本机时间超过该值视为异常。
	maxSourceFutureSkew = 15 * time.Minute
)

var errPathCommitInFuture = errors.New("GitHub path commit timestamp is in the future")

func freshnessPolicy(lookbackDays int) string {
	return fmt.Sprintf("%s:%dd", freshnessPolicyVersion, lookbackDays)
}

func (s *Service) loop() {
	s.purgeOnce()
	defer s.wg.Done()
	lastPurge := time.Now()
	for {
		s.mu.Lock()
		ctx := s.ctx
		settings := s.settings
		next := copyTime(s.nextRun)
		s.mu.Unlock()
		if ctx == nil {
			return
		}
		if time.Since(lastPurge) >= 24*time.Hour {
			lastPurge = time.Now()
			s.purgeOnce()
		}
		delay := time.Hour
		if settings.Enabled && settings.Configured() && next != nil {
			delay = time.Until(*next)
			if delay < 0 {
				delay = 0
			}
		}
		timer := time.NewTimer(delay)
		manual := false
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return
		case <-s.wake:
			if !timer.Stop() {
				<-timer.C
			}
			continue
		case <-s.queue:
			manual = true
			if !timer.Stop() {
				<-timer.C
			}
		case <-timer.C:
		}
		s.mu.Lock()
		manual = s.claimQueuedRunLocked(manual)
		if s.closed || !s.settings.Configured() || s.detector == nil || s.running || (!manual && !s.settings.Enabled) {
			s.mu.Unlock()
			continue
		}
		s.running = true
		settings = s.settings
		provider := s.client
		detector := s.detector
		s.mu.Unlock()

		rateReset := s.execute(ctx, settings, provider, detector)

		s.mu.Lock()
		s.running = false
		pendingApplied := s.pending != nil
		if pendingApplied {
			s.applyRuntimeLocked(s.pending, provider)
		}
		now := time.Now().UTC()
		if s.settings.Enabled && s.settings.Configured() && s.detector != nil {
			nextAt := now.Add(s.settings.pollInterval())
			if pendingApplied {
				nextAt = now
			} else if rateReset != nil && rateReset.After(now) {
				nextAt = rateReset.UTC()
			}
			s.nextRun = &nextAt
		} else {
			s.nextRun = nil
		}
		s.mu.Unlock()
	}
}

// claimQueuedRunLocked coalesces a manual trigger with a scheduled run that is
// already due. Without draining the queued marker when the timer wins select,
// startup can consume the same intent twice and immediately repeat every rule.
func (s *Service) claimQueuedRunLocked(manual bool) bool {
	if manual {
		s.queued = false
		return true
	}
	if !s.queued {
		return false
	}
	select {
	case <-s.queue:
	default:
	}
	s.queued = false
	return true
}

func (s *Service) execute(parent context.Context, settings Settings, provider searchProvider, detector secretDetector) *time.Time {
	// Token 池轮换：池有可用号且与当前号不同 → 本轮换号执行。
	// 指纹键在池启用时固定（firstRun 缓存），避免换号后已存指纹对不上。
	s.mu.Lock()
	picker := s.picker
	if !s.fingerprintKeyFixed && settings.FingerprintKey == "" {
		s.fingerprintKeyFixed = true
		s.fixedFingerprintKey = deriveFingerprintKey(settings.Token)
	}
	baseKey := s.fixedFingerprintKey
	s.mu.Unlock()
	if picker != nil && baseKey != "" {
		// 轮换前刷新池内额度（rate_limit 不计配额）：保证 Pick 能按真实剩余
		// 配额在各号之间轮换，而不是在额度未知时固定用列表第一个号。
		if refresher, ok := picker.(interface{ RefreshRates(context.Context) []error }); ok {
			rctx, rcancel := context.WithTimeout(contextWithoutCancellation(parent), 30*time.Second)
			if errs := refresher.RefreshRates(rctx); len(errs) > 0 {
				s.logger.Warn("GitHub Token 额度采集部分失败", lz.Int("failed", len(errs)))
			}
			rcancel()
		}
		if picked := picker.Pick(parent); picked != "" && picked != settings.Token {
			rotated := settings
			rotated.Token = picked
			rotated.FingerprintKey = baseKey // 固定：不随 token 派生
			if c, err := NewClient(rotated); err == nil {
				c.SetSearchLimiter(s.searchLimiter)
				if d, err2 := NewDetector(rotated); err2 == nil {
					provider, detector = c, d
					s.logger.Info("GitHub Token 池轮换执行", lz.Bool("rotated", true))
				}
			}
		}
	}
	rules, err := compiledRules(settings, false)
	if err != nil || len(rules) == 0 {
		s.logger.Warn("GitHub leak monitor rule unavailable")
		return nil
	}
	unlock, locked, err := s.store.AcquireRunLock(parent)
	if err != nil || !locked {
		if err != nil {
			s.logger.Warn("GitHub leak monitor lock unavailable", lz.Error(err))
		}
		return nil
	}
	defer unlock()

	runTimeout := runTimeoutForRules(settings, len(rules))
	ctx, cancel := context.WithTimeout(parent, runTimeout)
	defer cancel()
	now := time.Now().UTC()
	run, err := s.store.BeginRun(ctx, now)
	if err != nil {
		s.logger.Warn("GitHub leak monitor could not create run", lz.Error(err))
		return nil
	}
	run.Status = "success"
	run.RateRemaining = -1
	completedRules := 0
	failedRules := 0
	// 本轮真正新增的命中（跨规则累计）——运行结束后聚合为一条 IM 通知。
	var newFindings []Candidate
	incompleteRules := 0
	budgetLimitedRules := 0
	permanentSearchFailure := false
	stopRun := false
	// 路径时效：回溯窗口在本轮开始时冻结；策略版本/窗口变化使旧游标与 ETag 失效。
	lookbackDays := settings.ResolveLookbackDays()
	cutoff := run.StartedAt.AddDate(0, 0, -lookbackDays)
	type recencyResult struct {
		updatedAt time.Time
		err       error
	}
	recencyCache := make(map[string]recencyResult)
	freshnessChecksRemaining := maxFreshnessChecksPerRun
	policy := freshnessPolicy(lookbackDays)
	// 静默清单（每轮一次加载；store 不支持时为 nil = 无静默）。规则维度静默
	// 在搜索之前整条跳过；条目/指纹维度在 item 循环内逐条判定。
	var suppressions *suppressionSet
	if src, ok := s.store.(suppressionSource); ok {
		if list, listErr := src.ListSuppressions(ctx); listErr == nil {
			suppressions, _ = compileSuppressions(list)
		}
	}
	for ruleIndex, rule := range rules {
		if ctx.Err() != nil {
			run.Status = "cancelled"
			run.Error = "run cancelled"
			break
		}
		// 规则维度静默（R7 规则自净产物/运营手动停用）：不搜索不检测。
		if suppressions != nil && suppressions.suppressRule(rule.Name) {
			s.logger.Info("GitHub leak monitor 规则已静默，本轮跳过", lz.String("rule", rule.Name))
			continue
		}
		state, stateErr := s.store.KeywordState(ctx, rule.Query)
		if stateErr != nil {
			failedRules++
			continue
		}
		if state.FreshnessPolicy != policy {
			// 回溯窗口或策略版本变化：旧游标/ETag 全部失效，强制全量重查。
			state.ETag = ""
			state.FreshnessCheckedAt = nil
			state.FreshnessCursor = 0
			state.FreshnessCursorETag = ""
		}
		state.FreshnessPolicy = policy
		if state.FreshnessCheckedAt == nil || !state.FreshnessCheckedAt.After(run.StartedAt.Add(-freshnessRecheckInterval)) {
			// ETag 描述的是搜索响应而非路径提交历史；至少每天强制一次全量响应，
			// 否则 304 会让已有命中永远不再做路径时效复核。
			state.ETag = ""
		}
		attemptAt := time.Now().UTC()
		state.LastAttemptAt = &attemptAt
		run.Requests++
		page := state.PageCursor
		if page < 1 {
			page = 1
		}
		result, searchErr := provider.SearchKeywords(ctx, rule.Keywords, state.ETag, settings.MaxResultsPerKeyword, page)
		if searchErr != nil {
			state.LastStatus = "error"
			state.LastError = classifySearchError(searchErr)
			_ = s.saveKeywordState(ctx, state)
			var httpErr *HTTPStatusError
			if errors.As(searchErr, &httpErr) && httpErr.RateLimited {
				run.Status = "rate_limited"
				run.Error = state.LastError
				run.RateResetAt = copyTime(httpErr.RateReset)
				break
			}
			if errors.As(searchErr, &httpErr) && isPermanentSearchFailure(httpErr) {
				failedRules++
				permanentSearchFailure = true
				break
			}
			if errors.Is(searchErr, context.Canceled) || errors.Is(searchErr, context.DeadlineExceeded) {
				run.Status = "cancelled"
				run.Error = "run cancelled"
				break
			}
			failedRules++
			continue
		}
		if result.RateRemaining >= 0 || run.RateRemaining < 0 {
			run.RateRemaining = result.RateRemaining
		}
		if result.RateResetAt != nil {
			run.RateResetAt = copyTime(result.RateResetAt)
		}
		state.LastError = ""
		state.Incomplete = result.Incomplete
		state.Truncated = result.Truncated
		completedAt := time.Now().UTC()
		state.LastSuccessAt = &completedAt
		if result.NotModified {
			state.LastStatus = "not_modified"
			if result.ETag != "" {
				state.ETag = result.ETag
			}
			if page > 1 {
				// 翻页模式下深页 304 只说明该页无变化：推进游标探索更深页，
				// 旧页 ETag 不再有意义。首页 304 保持停驻（最便宜的去重路径）。
				state.PageCursor = page + 1
				if state.PageCursor > maxSearchPagesPerRule {
					state.PageCursor = 1
				}
				state.ETag = ""
			}
			if err = s.saveKeywordState(ctx, state); err != nil {
				s.logger.Warn("GitHub leak monitor state write failed", lz.String("error_type", fmt.Sprintf("%T", err)), lz.Bool("run_context_done", ctx.Err() != nil))
				failedRules++
				continue
			}
			completedRules++
			continue
		}
		candidates := make([]Candidate, 0)
		skippedStale := 0
		skippedFork := 0
		skippedNoise := 0
		skippedSuppressed := 0
		skippedOldCode := 0
		staleCutoff := time.Time{}
		if settings.RepoMaxAgeDays > 0 {
			staleCutoff = time.Now().UTC().AddDate(0, 0, -settings.RepoMaxAgeDays)
		}
		excludeForks := settings.ResolveExcludeForks()
		excludeNoise := settings.ResolveExcludeNoisePaths()
		blobBudget := settings.ResolveMaxBlobRescans()
		// 游标续跑：上一轮因时效校验预算中断时从断点继续；搜索快照变化则重头。
		cursor := state.FreshnessCursor
		cursorETag := state.FreshnessCursorETag
		if cursor > 0 && cursorETag != result.ETag {
			cursor = 0
		}
		if cursor < 0 || cursor >= len(result.Items) {
			cursor = 0
		}
		visitedItems := 0
		recencyFailures := 0
		budgetLimited := false
		fatalFreshnessFailure := false
		ruleFreshnessChecks := 0
		rulesRemaining := len(rules) - ruleIndex
		perRuleFreshnessLimit := 0
		if freshnessChecksRemaining > 0 {
			perRuleFreshnessLimit = freshnessChecksRemaining / rulesRemaining
			if perRuleFreshnessLimit < 1 {
				perRuleFreshnessLimit = 1
			}
		}
		for step := 0; step < len(result.Items); step++ {
			item := result.Items[(cursor+step)%len(result.Items)]
			// 仓库时效过滤：归档或超过 N 天无 push 的仓库视为陈旧内容，不入库不提醒。
			// pushed_at 缺失（上游未返回）时保守放行，避免误吞新命中。
			if !staleCutoff.IsZero() {
				if item.RepoArchived {
					skippedStale++
					visitedItems++
					continue
				}
				if !item.RepoPushedAt.IsZero() && item.RepoPushedAt.Before(staleCutoff) {
					skippedStale++
					visitedItems++
					continue
				}
			}
			// fork 过滤：fork 内容多为上游复制，重复命中占比高。
			if excludeForks && item.RepoFork {
				skippedFork++
				visitedItems++
				continue
			}
			// 噪声路径过滤：测试/示例/文档路径的样板凭据不入库不通知（误报主源）。
			if excludeNoise && isNoisePath(item.Path) {
				skippedNoise++
				visitedItems++
				continue
			}
			// 静默清单：运营级具体误报源（仓库/组织/路径通配）整条跳过。
			if suppressions != nil && suppressions.suppressItem(item.Repository, item.Path) {
				skippedSuppressed++
				visitedItems++
				continue
			}
			detected := detector.Detect(rule.Query, item)
			// 漏检补扫（P1-6）：零命中且预算未耗尽时回读 blob 全文重跑——
			// text_matches 片段可能截断跨边界密钥。core 桶请求，有每规则上限。
			if len(detected) == 0 && settings.ResolveBlobRescan() && blobBudget > 0 && item.BlobSHA != "" {
				blobBudget--
				blobClient, isClient := provider.(*Client)
				var content []byte
				var blobErr error
				if isClient {
					content, blobErr = blobClient.FetchBlob(ctx, item.Repository, item.BlobSHA)
				}
				if isClient && blobErr == nil && len(content) > 0 {
					full := item
					full.Fragments = []string{string(content)}
					detected = detector.Detect(rule.Query, full)
				}
			}
			if suppressions != nil {
				filtered := detected[:0]
				for _, c := range detected {
					if suppressions.suppressCandidate(c.Fingerprint) {
						continue
					}
					filtered = append(filtered, c)
				}
				detected = filtered
			}
			// 路径时效校验（core API，仅对检测命中付费）：文件最近提交时间在回溯
			// 窗口外的陈旧代码不入库；预算跨规则公平分配，耗尽时游标续跑下一轮。
			if len(detected) > 0 {
				cacheKey := item.RepoNodeID + "\x00" + item.Repository + "\x00" + item.Path + "\x00" + item.BlobSHA
				freshness, cached := recencyCache[cacheKey]
				if !cached {
					if ruleFreshnessChecks >= perRuleFreshnessLimit {
						recencyFailures++
						budgetLimited = true
						break
					}
					ruleFreshnessChecks++
					freshnessChecksRemaining--
					run.Requests++
					freshness.updatedAt, freshness.err = provider.LatestPathCommitAt(ctx, item)
					if freshness.err == nil && freshness.updatedAt.After(time.Now().UTC().Add(maxSourceFutureSkew)) {
						freshness.err = errPathCommitInFuture
					}
					recencyCache[cacheKey] = freshness
				}
				if freshness.err != nil {
					recencyFailures++
					if isItemLocalMetadataError(freshness.err) {
						// 搜索索引可能残留已删除/改名路径：仅跳过该项。
						visitedItems++
						continue
					}
					state.LastStatus = "partial"
					state.LastError = "candidate freshness verification failed"
					fatalFreshnessFailure = true
					run.Status = "partial"
					run.Error = state.LastError
					var httpErr *HTTPStatusError
					if errors.As(freshness.err, &httpErr) && httpErr.RateLimited {
						run.Status = "rate_limited"
						run.Error = "GitHub metadata rate limited"
						run.RateResetAt = copyTime(httpErr.RateReset)
					} else if errors.Is(freshness.err, context.Canceled) || errors.Is(freshness.err, context.DeadlineExceeded) {
						run.Status = "cancelled"
						run.Error = "run cancelled"
					}
					stopRun = true
					break
				}
				if freshness.updatedAt.IsZero() || freshness.updatedAt.Before(cutoff) {
					skippedOldCode++
					visitedItems++
					continue
				}
				for i := range detected {
					detected[i].SourceUpdatedAt = freshness.updatedAt.UTC()
				}
				// R8-4/R8-5 静态降级：低可信来源与失效快类别的陈旧命中退出高危
				// 队列（likely → suspected，不丢弃）。
				s.downgradeLowCredibility(item, detected)
				s.downgradeStaleSecrets(detected, freshness.updatedAt)
			}
			for i := range detected {
				detected[i].RuleName = rule.Name
			}
			candidates = append(candidates, detected...)
			visitedItems++
		}
		if len(result.Items) == 0 || visitedItems == len(result.Items) {
			state.FreshnessCursor = 0
			state.FreshnessCursorETag = ""
		} else {
			state.FreshnessCursor = (cursor + visitedItems) % len(result.Items)
			if state.FreshnessCursor == 0 {
				state.FreshnessCursorETag = ""
			} else {
				state.FreshnessCursorETag = result.ETag
			}
		}
		if skippedStale > 0 {
			s.logger.Info("GitHub leak monitor 已过滤陈旧仓库命中",
				lz.Int("skipped", skippedStale), lz.Int("repo_max_age_days", settings.RepoMaxAgeDays))
		}
		if skippedFork > 0 || skippedNoise > 0 {
			s.logger.Info("GitHub leak monitor 误报治理过滤",
				lz.Int("fork", skippedFork), lz.Int("noise_path", skippedNoise))
		}
		if skippedSuppressed > 0 {
			s.logger.Info("GitHub leak monitor 静默清单过滤", lz.Int("skipped", skippedSuppressed))
		}
		if skippedOldCode > 0 {
			s.logger.Info("GitHub leak monitor 已过滤回溯窗口外陈旧代码命中",
				lz.Int("skipped", skippedOldCode), lz.Int("lookback_days", lookbackDays))
		}
		run.FilteredFork += skippedFork
		run.FilteredNoise += skippedNoise
		run.FilteredSuppressed += skippedSuppressed
		var boilerplateDropped int
		candidates, boilerplateDropped = s.filterBoilerplateStorm(rule.Name, candidates, settings.ResolveBoilerplateRepos())
		run.FilteredBoilerplate += boilerplateDropped
		// 值级频次抑制（R8 闸门三）：同一密钥值跨 ≥N 仓库 = 合集/转发，likely 降级
		// suspected、suspected 丢弃；阈值与样板风暴共用，计数并入 FilteredBoilerplate。
		var valueStormDropped int
		candidates, valueStormDropped = s.filterValueStorm(rule.Name, candidates, settings.ResolveBoilerplateRepos())
		run.FilteredBoilerplate += valueStormDropped
		run.Processed += visitedItems
		run.Detected += len(candidates)
		inserted, _, upErr := s.store.UpsertCandidates(ctx, candidates, completedAt)
		if upErr == nil {
			newFindings = append(newFindings, inserted...)
		}
		if upErr != nil {
			err = upErr
			// 候选事务失败：游标回退到本轮起点，避免跳过未落库的命中。
			state.FreshnessCursor = cursor
			state.FreshnessCursorETag = cursorETag
			state.LastStatus = "error"
			state.LastError = "finding storage failed"
			_ = s.saveKeywordState(ctx, state)
			failedRules++
			if stopRun {
				break
			}
			continue
		}
		switch {
		case budgetLimited:
			state.LastStatus = "partial"
			state.LastError = fmt.Sprintf("per-rule candidate freshness check limit %d reached", perRuleFreshnessLimit)
			state.ETag = ""
			incompleteRules++
			budgetLimitedRules++
		case fatalFreshnessFailure:
			state.LastStatus = "partial"
			state.LastError = "candidate freshness verification failed"
			state.ETag = ""
			incompleteRules++
		case recencyFailures > 0:
			state.LastStatus = "partial"
			state.LastError = fmt.Sprintf("%d candidate freshness checks failed", recencyFailures)
			state.ETag = ""
			incompleteRules++
		case result.Incomplete:
			state.LastStatus = "partial"
			// Do not save an ETag for an incomplete snapshot; otherwise a later
			// 304 could turn a partial result into a permanent high-water mark.
			state.ETag = ""
			incompleteRules++
		default:
			state.LastStatus = "success"
			state.ETag = result.ETag
			state.FreshnessCheckedAt = &completedAt
			state.FreshnessCursor = 0
			state.FreshnessCursorETag = ""
		}
		// 跨轮翻页：total_count 超出单页时按页滚动，多轮覆盖可达搜索结果
		// （legacy API 前 maxSearchPagesPerRule 页），不再永远钉死在相关度排序
		// 头部。换页后上一页 ETag 失去意义，直接作废；停驻页（total≤单页）
		// 保留 304 快路径。Truncated 在翻页模式下是预期常态，不再据此降级。
		totalPages := 1
		if per := settings.MaxResultsPerKeyword; per > 0 && result.TotalCount > per {
			totalPages = (result.TotalCount + per - 1) / per
			if totalPages > maxSearchPagesPerRule {
				totalPages = maxSearchPagesPerRule
			}
		}
		nextPage := page + 1
		if nextPage > totalPages {
			nextPage = 1
		}
		state.PageCursor = nextPage
		if nextPage != page {
			state.ETag = ""
		}
		if err = s.saveKeywordState(ctx, state); err != nil {
			s.logger.Warn("GitHub leak monitor state write failed", lz.String("error_type", fmt.Sprintf("%T", err)), lz.Bool("run_context_done", ctx.Err() != nil))
			failedRules++
			if stopRun {
				break
			}
			continue
		}
		completedRules++
		if stopRun {
			break
		}
	}
	if run.Status != "rate_limited" && run.Status != "cancelled" {
		switch {
		case permanentSearchFailure && completedRules == 0:
			run.Status = "error"
			run.Error = "GitHub authentication or authorization failed; remaining rules were skipped"
		case permanentSearchFailure:
			run.Status = "partial"
			run.Error = "GitHub authentication or authorization failed; remaining rules were skipped"
		case failedRules > 0 && completedRules == 0:
			run.Status = "error"
			run.Error = fmt.Sprintf("%d of %d rule searches failed", failedRules, len(rules))
		case failedRules > 0:
			run.Status = "partial"
			run.Error = fmt.Sprintf("%d of %d rule searches failed", failedRules, len(rules))
		case incompleteRules > 0:
			run.Status = "partial"
			if budgetLimitedRules > 0 {
				run.Error = fmt.Sprintf("%d of %d rule searches were partial; %d reached the per-rule freshness check limit", incompleteRules, len(rules), budgetLimitedRules)
			} else {
				run.Error = fmt.Sprintf("%d of %d rule searches were incomplete, truncated, or failed freshness verification", incompleteRules, len(rules))
			}
		default:
			run.Status = "success"
		}
	}
	finished := time.Now().UTC()
	run.FinishedAt = &finished
	finishCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if err = s.store.FinishRun(finishCtx, run); err != nil {
		s.logger.Warn("GitHub leak monitor run status write failed", lz.Error(err))
	}
	s.logger.Info("GitHub leak monitor run completed", lz.String("status", run.Status), lz.Int("requests", run.Requests), lz.Int("processed", run.Processed), lz.Int("detected", run.Detected))
	s.notifyNewFindings(run, newFindings)
	// 明文回填（尽力而为）：主要覆盖明文入库特性上线前的历史行；
	// core API 配额宽松，单轮限量避免拉长锁持有时间。
	bctx, cancel := context.WithTimeout(contextWithoutCancellation(parent), 3*time.Minute)
	if filled, backfillErr := s.BackfillSecretValues(bctx, 20); backfillErr != nil {
		s.logger.Warn("GitHub leak plaintext backfill failed", lz.Error(backfillErr))
	} else if filled > 0 {
		s.logger.Info("GitHub leak plaintext backfilled", lz.Int("filled", filled))
	}
	// 规则自净（R7-1）：run 收尾后按精确率统计自动停用高误报规则。
	// 用脱离取消链的 ctx——run 结束时原 ctx 可能已被取消，静默写入不应被连带取消。
	if run.Status == "success" || run.Status == "partial" {
		s.autoDisableNoisyRules(contextWithoutCancellation(ctx))
	}
	cancel()
	if run.Status == "rate_limited" {
		return copyTime(run.RateResetAt)
	}
	return nil
}

func runTimeoutForRules(settings Settings, enabledRules int) time.Duration {
	runTimeout := 30 * time.Minute
	if enabledRules < 1 {
		return runTimeout
	}
	// Search calls are serialized and spacing starts after the previous call
	// finishes, so both the timeout and the quiet interval scale per rule.
	// Metadata（路径提交）请求同样串行；首次网络级失败即结束本轮，按满额预算
	// 加上一次请求超时并留出余量。
	minimum := time.Duration(enabledRules)*(settings.interval()+settings.timeout()) +
		time.Duration(maxFreshnessChecksPerRun)*metadataInterval + settings.timeout() + 5*time.Minute
	if minimum > runTimeout {
		runTimeout = minimum
	}
	if runTimeout > 6*time.Hour {
		runTimeout = 6 * time.Hour
	}
	return runTimeout
}

func isPermanentSearchFailure(err *HTTPStatusError) bool {
	if err == nil || err.RateLimited {
		return false
	}
	return err.StatusCode == 401 || err.StatusCode == 403
}

// isItemLocalMetadataError 可归因于单个条目的元数据错误（路径已删除/改名或
// 提交时间异常超前）：只跳过该项，不影响本轮其余条目。
func isItemLocalMetadataError(err error) bool {
	return errors.Is(err, errPathCommitUnavailable) || errors.Is(err, errPathCommitInFuture)
}

func classifySearchError(err error) string {
	var statusErr *HTTPStatusError
	if errors.As(err, &statusErr) {
		if statusErr.RateLimited {
			return "github search rate limited"
		}
		switch statusErr.StatusCode {
		case 422:
			return "github rejected the exact keyword query"
		default:
			return fmt.Sprintf("github search HTTP %d", statusErr.StatusCode)
		}
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "github search cancelled"
	}
	return "github search unavailable"
}

func (s *Service) saveKeywordState(ctx context.Context, state KeywordState) error {
	writeCtx, cancel := context.WithTimeout(contextWithoutCancellation(ctx), 5*time.Second)
	defer cancel()
	return s.store.SaveKeywordState(writeCtx, state)
}

func contextWithoutCancellation(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return context.WithoutCancel(ctx)
}

// purgeOnce 处置完结 findings 定期清理（保留天数取 settings；负数=关闭）。
func (s *Service) purgeOnce() {
	retain := s.settings.ResolveRetentionDays()
	if retain <= 0 || s.settings.RetentionDays < 0 {
		return
	}
	if s.settings.RetentionDays == 0 {
		retain = 180
	}
	src, ok := s.store.(interface {
		PurgeExpiredFindings(context.Context, int) (int64, error)
	})
	if !ok {
		return
	}
	n, err := src.PurgeExpiredFindings(context.Background(), retain)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("泄露 findings 保留期清理失败", lz.Error(err))
		}
		return
	}
	if n > 0 && s.logger != nil {
		s.logger.Info("泄露 findings 保留期清理完成", lz.Int64("purged", n), lz.Int("retain_days", retain))
	}
}
