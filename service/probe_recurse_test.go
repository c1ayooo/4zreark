package service

import (
	"context"
	"testing"
	"time"
)

// 安全审计 M17 验证：probeHTTPAndCert 已无自递归（改为每 scheme 至多一次的
// 显式循环）。对「443 与 80 都无服务」的目标，函数必须在有限时间、有限资源
// 下返回——此前递归版本会无限重入。跑多轮同时验证无 panic 与栈累积。
func TestProbeHTTPAndCertBoundedRetries(t *testing.T) {
	deadline := time.Now().Add(30 * time.Second)
	for i := 0; i < 20; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		start := time.Now()
		_, _, _, err := probeHTTPAndCert(ctx, "127.0.0.1")
		elapsed := time.Since(start)
		cancel()
		if err == nil {
			t.Fatalf("无服务目标应返回错误")
		}
		// 每轮至多 https(1s TLS 失败) + http(6s dial) 两段，不应超 10s
		if elapsed > 10*time.Second {
			t.Fatalf("第 %d 轮耗时 %v——疑似回退失控", i, elapsed)
		}
		if time.Now().After(deadline) {
			t.Fatalf("20 轮未在 30s 内完成——疑似资源泄漏")
		}
	}
}
