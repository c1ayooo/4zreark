// Package lz 是迁移自 4zreco 的包所依赖的最小 zap 兼容垫片：
// 镜像用到的字段构造器与 Logger 方法，落到标准库 log。
// 只服务 githubleak/githubtokens 等迁移包，新代码直接用标准库 log。
package lz

import (
	"fmt"
	"log"
	"time"
)

// Field 结构化字段：仅用于拼日志行，不做序列化。
type Field struct {
	Key string
	Val any
}

func String(key, val string) Field { return Field{key, val} }
func Int(key string, val int) Field {
	return Field{key, val}
}
func Bool(key string, val bool) Field  { return Field{key, val} }
func Time(key string, val time.Time) Field { return Field{key, val} }
func Int64(key string, val int64) Field { return Field{key, val} }
func Error(err error) Field {
	if err == nil {
		return Field{"error", nil}
	}
	return Field{"error", err.Error()}
}

func format(fields []Field) string {
	out := ""
	for _, f := range fields {
		if f.Val == nil {
			continue
		}
		out += fmt.Sprintf(" %s=%v", f.Key, f.Val)
	}
	return out
}

// Logger 标准库日志的薄壳；带模块前缀。
type Logger struct {
	prefix string
}

func New(prefix string) *Logger { return &Logger{prefix: prefix} }

// NewNop 静音 Logger：迁移代码里"可选日志"的缺省值。
func NewNop() *Logger { return &Logger{prefix: "quiet"} }

// Quiet 静音标记：log 层直接吞掉输出。
func (l *Logger) quiet() bool { return l.prefix == "quiet" }

func (l *Logger) log(level, msg string, fields []Field) {
	if l.quiet() {
		return
	}
	log.Printf("[%s] %s %s%s", l.prefix, level, msg, format(fields))
}

func (l *Logger) Debug(msg string, fields ...Field) { l.log("DEBUG", msg, fields) }
func (l *Logger) Info(msg string, fields ...Field)  { l.log("INFO", msg, fields) }
func (l *Logger) Warn(msg string, fields ...Field)  { l.log("WARN", msg, fields) }
func (l *Logger) Error(msg string, fields ...Field) { l.log("ERROR", msg, fields) }

// With 返回带前缀补记的新 Logger（字段拍平进前缀，够迁移包用）。
func (l *Logger) With(fields ...Field) *Logger {
	return &Logger{prefix: l.prefix + format(fields)}
}
