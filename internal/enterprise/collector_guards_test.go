package enterprise

import (
	"context"
	"errors"
	"log"
	"os"
	"strings"
	"testing"
)

func discardLogger() *log.Logger { return log.New(os.Stderr, "", 0) }

// 树穿透能力闸门：Branches/Investments 为占位空实现的数据源（qcc）必须被
// 拒绝并给出替代源指引——此前静默空转一轮后标 done（nodes=1 entities=0），
// 用户以为采集过了。
func TestWalkRejectsProviderWithoutTreeExpansion(t *testing.T) {
	c := &Collector{log: discardLogger(), store: nil}
	p := &qccProvider{}
	job := Job{Depth: 2, MaxNodes: 10}

	_, err := c.walk(context.Background(), p, job, CompanyRef{ExtID: "x", Name: "x"}, nil)
	if err == nil {
		t.Fatal("qcc 应被能力闸门拒绝")
	}
	if !strings.Contains(err.Error(), "xiaolanben") || !strings.Contains(err.Error(), "qcc") {
		t.Fatalf("错误信息应含数据源名与替代源指引: %v", err)
	}
}

// 节点配额哨兵：达到上限返回哨兵（终态转 done+提示），不再误标 error。
func TestNodeCapSentinel(t *testing.T) {
	if !NodeCapReached(errNodeCapReached) {
		t.Fatal("哨兵应被识别")
	}
	if NodeCapReached(errors.New("other")) || NodeCapReached(nil) {
		t.Fatal("普通错误/nil 不应误判")
	}
	msg := nodeCapMessage(200)
	if !strings.Contains(msg, "200") || !strings.Contains(msg, "续穿") {
		t.Fatalf("提示应含配额与续穿指引: %s", msg)
	}
}
