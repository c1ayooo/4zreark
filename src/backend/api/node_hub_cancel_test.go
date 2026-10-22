package api

import (
	"encoding/json"
	"testing"
	"time"
)

func TestNodeHubCancelTaskSendsCommand(t *testing.T) {
	h := NewNodeHub()
	c := &nodeConn{
		nodeID: "node-1",
		send:   make(chan []byte, 1),
		done:   make(chan struct{}),
	}
	h.taskConns["task-1"] = c

	if !h.CancelTask("task-1") {
		t.Fatal("CancelTask 应命中正在执行的任务")
	}
	select {
	case raw := <-c.send:
		var cmd wsCommand
		if err := json.Unmarshal(raw, &cmd); err != nil {
			t.Fatalf("解析 cancel 指令失败: %v", err)
		}
		if cmd.Type != "cancel" || cmd.TaskID != "task-1" {
			t.Fatalf("cancel 指令不符: %+v", cmd)
		}
	case <-time.After(time.Second):
		t.Fatal("未收到 cancel 指令")
	}

	if h.CancelTask("missing-task") {
		t.Fatal("不存在的任务不应返回 true")
	}
}
