package service

import (
	"log"
	"runtime/debug"
)

// GoSafe 启动一个带 panic 兜底的 goroutine。
//
// gin.Recovery 只覆盖 HTTP handler；后台采集、判定、巡航等长驻协程一旦 panic
// 会直接带走整个控制面进程，正在跑的任务全部中断且无法收尾。新增后台协程
// 一律经由此函数启动，panic 记日志与堆栈后只损失该协程。
func GoSafe(name string, fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[GoSafe] 协程 %s panic: %v\n%s", name, r, debug.Stack())
			}
		}()
		fn()
	}()
}
