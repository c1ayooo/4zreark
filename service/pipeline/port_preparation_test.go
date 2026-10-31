package pipeline

import (
	"context"
	"testing"
	"time"
)

// 同一子域以 SubdomainResult 与 DomainResolve 两种形态到达时，端口扫描
// 输入（DomainSkip）只能放行一份——此前两路各转一份，同一域名被 gogo 实扫
// 两次（worker 日志同一域两行 Starting），对外扫描流量翻倍；且两路 CDN
// 结论可能相反，httpx 判「Unknown CDN」的一路直接漏扫。
func TestPortPrepEmitsSingleSkipPerDomain(t *testing.T) {
	next := newCaptureModule()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	prep := NewPortScanPreparationModule(ctx, next)
	prep.SetInput(make(chan interface{}, 8))

	done := make(chan struct{})
	go func() {
		_ = prep.ModuleRun()
		close(done)
	}()

	const host = "single-scan-fixture.invalid"
	prep.GetInput() <- SubdomainResult{Host: host, Domain: "fixture.invalid"}
	prep.GetInput() <- DomainResolve{Domain: host, IP: []string{"93.184.216.34"}}
	// 第三种形态再到达一次：已被 seen 拦下，不再产出
	prep.GetInput() <- DomainSkip{Domain: host, IP: []string{"93.184.216.34"}}
	prep.CloseInput()

	skips := 0
	sawSubdomain := false
	deadline := time.After(15 * time.Second)
	collect := func(v interface{}) bool {
		switch r := v.(type) {
		case DomainSkip:
			if r.Domain != host {
				t.Fatalf("未知目标的 DomainSkip: %+v", r)
			}
			skips++
		case SubdomainResult:
			if r.Host != host {
				t.Fatalf("未知目标的 SubdomainResult: %+v", r)
			}
			sawSubdomain = true
		}
		return false
	}
	// 期望恰好两条输出：sr 转发 + 一份 DomainSkip
	for i := 0; i < 2; i++ {
		select {
		case v, open := <-next.GetInput():
			if !open {
				t.Fatal("下游输入通道过早关闭")
			}
			collect(v)
		case <-deadline:
			t.Fatalf("超时：只收到 %d 条输出（DomainSkip=%d）", i, skips)
		}
	}
	if !sawSubdomain {
		t.Fatal("SubdomainResult 未原样下沉（结果收集器会丢子域记录）")
	}
	if skips != 1 {
		t.Fatalf("DomainSkip 放行 %d 份，期望恰好 1 份", skips)
	}

	select {
	case extra, open := <-next.GetInput():
		if open {
			t.Fatalf("不应有多余输出: %+v", extra)
		}
	case <-time.After(500 * time.Millisecond):
	}
	select {
	case <-done:
	case <-deadline:
		t.Fatal("ModuleRun 未返回")
	}
}
