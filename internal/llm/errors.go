package llm

import (
	"errors"
	"fmt"

	sdkopenai "github.com/meguminnnnnnnnn/go-openai"
)

// 三类错误对应 River 的失败语义（v0.3 §6）：
//
//	ErrPermanent  → 重试无意义，river.JobCancel
//	ErrRateLimited→ 配额/限流，river.JobSnooze(5m)
//	其它（含 ErrTransient）→ 默认退避重试
var (
	// ErrPermanent 表示请求本身有问题：参数非法、鉴权失败、模型不存在、响应无法解析。
	ErrPermanent = errors.New("llm permanent error")
	// ErrRateLimited 表示上游限流或配额耗尽。
	ErrRateLimited = errors.New("llm rate limited")
	// ErrTransient 表示可重试的临时故障（5xx、网络抖动、超时）。
	ErrTransient = errors.New("llm transient error")
	// ErrNoKey 表示未配置 API Key，调用方应降级而不是重试。
	ErrNoKey = errors.New("llm api key not configured")
)

// Classify 把 eino-ext/go-openai 抛出的错误归一到上面的三类语义。
// 非 HTTP 错误（网络、超时、context）统一视为可重试。
func Classify(err error) error {
	if err == nil {
		return nil
	}
	for _, target := range []error{ErrPermanent, ErrRateLimited, ErrTransient, ErrNoKey} {
		if errors.Is(err, target) {
			return err
		}
	}

	var apiErr *sdkopenai.APIError
	if errors.As(err, &apiErr) {
		switch code := apiErr.HTTPStatusCode; {
		case code == 429:
			return fmt.Errorf("%w: %s", ErrRateLimited, apiErr.Message)
		case code >= 500:
			return fmt.Errorf("%w: HTTP %d %s", ErrTransient, code, apiErr.Message)
		case code >= 400:
			return fmt.Errorf("%w: HTTP %d %s", ErrPermanent, code, apiErr.Message)
		}
	}
	return fmt.Errorf("%w: %v", ErrTransient, err)
}
