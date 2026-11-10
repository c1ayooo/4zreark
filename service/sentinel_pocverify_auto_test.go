package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/repo"
)

func TestPocVerifyInputAllowed(t *testing.T) {
	cases := []struct {
		name        string
		kind, title string
		status      string
		auto        bool
		want        bool
	}{
		{"人工闸门下 verified 放行", "poc", pythonPocTitle, "verified", false, true},
		{"人工闸门下 draft 拦截", "poc", pythonPocTitle, "draft", false, false},
		{"自动模式放行 draft", "poc", pythonPocTitle, "draft", true, true},
		{"自动模式放行待审", "poc", pythonPocTitle, "pending_review", true, true},
		{"rejected 任何模式都拦截", "poc", pythonPocTitle, "rejected", true, false},
		{"deprecated 任何模式都拦截", "poc", pythonPocTitle, "deprecated", true, false},
		{"自动模式放行 nuclei draft", "nuclei", "nuclei-template", "draft", true, true},
		{"人工闸门拦截 nuclei draft", "nuclei", "nuclei-template", "draft", false, false},
		{"报告产物不是验证输入", "report", "exploit-guide", "verified", true, false},
		{"自定义标题 PoC 不是自动输入", "poc", "my-poc", "verified", true, false},
		{"patch 不是验证输入", "patch", "patch: abc", "verified", true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := &repo.CommitArtifact{Kind: c.kind, Title: c.title, Status: c.status}
			if got := pocVerifyInputAllowed(a, c.auto); got != c.want {
				t.Fatalf("pocVerifyInputAllowed(%+v, auto=%v) = %v, want %v", a, c.auto, got, c.want)
			}
		})
	}
	if pocVerifyInputAllowed(nil, true) {
		t.Fatal("nil 产物不应放行")
	}
}

func TestAcquireSentinelVerifyGateSerializes(t *testing.T) {
	first, err := acquireSentinelVerifyGate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	released := false
	release := func() {
		if !released {
			first()
			released = true
		}
	}
	defer release()

	// 第一个验证在跑时，第二个必须等待（这里用短超时证明拿不到锁）。
	waitCtx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := acquireSentinelVerifyGate(waitCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("并发验证应等待闸门，得到 %v", err)
	}

	release()
	second, err := acquireSentinelVerifyGate(context.Background())
	if err != nil {
		t.Fatalf("第一个释放后应可获取闸门: %v", err)
	}
	second()
}
