package vulnverify

// 默认执行器与任务台账存储接口。

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"time"
)

// execRunner 默认执行器：exec nuclei，注入出站代理环境变量；回环目标强制
// no_proxy 直连（与 infocollect 客户端同语义：回环经远端代理必死），整树 ctx 取消。
// 返回合并 stdout（nuclei -json 输出走 stdout）；非 0 退出返回错误与已捕获输出。
func execRunner(ctx context.Context, binPath string, args []string, timeout time.Duration, proxyURL string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, binPath, args...)
	if proxyURL != "" {
		cmd.Env = append(os.Environ(),
			"HTTP_PROXY="+proxyURL, "HTTPS_PROXY="+proxyURL, "ALL_PROXY="+proxyURL,
			"NO_PROXY=127.0.0.0/8,::1,localhost")
	}
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	out := buf.String()
	if err != nil {
		return out, err
	}
	return out, nil
}

// JobStore 任务台账（SQL 实现见 store_sql.go；测试用内存实现见 _test）。
// DB 不可用时服务以内存去重降级运行（Store=nil）。
type JobStore interface {
	// EnqueueJob 台账登记 + 去重判定：recheckDays 内已有 hit/miss、或已有
	// queued/running 的同 (target, product) 返回 false（不去重也入队会重复打目标）。
	EnqueueJob(ctx context.Context, task Task, recheckDays int) (queued bool, err error)
	// FinishJob 任务完结。
	FinishJob(task Task, status, vulnID, errMsg string, templateIDs []string) error
}
