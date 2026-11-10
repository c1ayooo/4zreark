package service

// 靶场验证的「自动 + 串行」控制：
//   - 高危发现产物流水线生成 PoC 后自动入队，不需要人工把产物改成 verified；
//   - sentinel_poc_verify 队列单 worker，且靶场验证与差分复现共用一把进程级
//     闸门，保证同一时刻只有一个 docker 验证在跑（固定容器名 pocverify-target
//     与 1g/2cpu 资源限制都要求不能并发）。
//
// 语义变化：自动模式下平台自动生成的 draft/pending_review PoC 可直接进容器执行，
// 不再等待人工审核。要恢复「人工 verified 才验证」的旧铁律，设
// sentinel.poc_verify.auto_enqueue=false；PoC 仍只在 --internal 隔离网络里打
// 白名单靶场，不接触真实目标。

import (
	"context"
	"log"

	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/repo"
)

// sentinelVerifyGate 容量 1：跨 sentinel_poc_verify / sentinel_repro 两个队列
// 串行化 docker 编排。多 pocsmith 实例部署时需另加分布式锁，compose 单机只有
// 一个实例，这里足够。
var sentinelVerifyGate = make(chan struct{}, 1)

func acquireSentinelVerifyGate(ctx context.Context) (func(), error) {
	select {
	case sentinelVerifyGate <- struct{}{}:
		return func() { <-sentinelVerifyGate }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// pocVerifyAutoEnqueue 读自动模式开关，未配置默认开启。
func pocVerifyAutoEnqueue() bool {
	if c := config.Loaded(); c != nil && c.Sentinel.PocVerify.AutoEnqueue != nil {
		return *c.Sentinel.PocVerify.AutoEnqueue
	}
	return true
}

// pocVerifyInputAllowed 判断产物能否作为验证输入。auto=true（自动模式）时放行
// 自动生成的 draft/pending_review；auto=false 时严格只认人工 verified。
// rejected/deprecated 任何模式都不采信。
func pocVerifyInputAllowed(a *repo.CommitArtifact, auto bool) bool {
	if a == nil {
		return false
	}
	if a.Kind != "nuclei" && !(a.Kind == "poc" && a.Title == pythonPocTitle) {
		return false
	}
	switch a.Status {
	case "verified":
		return true
	case "draft", "pending_review":
		return auto
	default:
		return false
	}
}

// maybeAutoEnqueuePocVerify 在产物生成完毕后由流水线调用：有可用 PoC、没验证过、
// 且总开关与自动模式都开着时入队。River unique + 「已有 poc-verify 产物」判断
// 保证幂等，重复调用不会堆作业、也不会反复拉镜像。入队失败只记日志，不影响
// 产物流水线本身的成败。返回是否实际入队（调用方可据此写事件流）。
func maybeAutoEnqueuePocVerify(ctx context.Context, findingID int64) bool {
	if !pocVerifyEnabled() || !pocVerifyAutoEnqueue() {
		return false
	}
	q := DefaultSentinelQueue()
	if q == nil {
		return false
	}
	store := repo.Default().Sentinel()
	f, err := store.GetFinding(ctx, findingID)
	if err != nil || f.VerifiedAt != nil {
		return false
	}
	arts, err := store.ListArtifacts(ctx, findingID)
	if err != nil {
		return false
	}
	hasInput := false
	for _, a := range arts {
		if a.Kind == "repro_log" && a.Title == pocVerifyTitle {
			return false // 已有验证结论（含未通过），不自动重跑；需要时人工 force=true
		}
		if pocVerifyInputAllowed(a, true) {
			hasInput = true
		}
	}
	if !hasInput {
		return false
	}
	if err := q.EnqueuePocVerify(ctx, findingID, false); err != nil {
		log.Printf("[Sentinel] 自动入队靶场验证失败 finding=%d: %v", findingID, err)
		return false
	}
	log.Printf("[Sentinel] 产物就绪，已自动入队靶场验证 finding=%d（单 worker 串行，一次一个）", findingID)
	return true
}
