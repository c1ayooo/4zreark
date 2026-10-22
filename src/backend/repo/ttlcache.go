package repo

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// ttlCache 是 repo 层专用的极简进程缓存：只为「每请求全量算分」的读路径
// （风险排序、指纹评分）挡住翻页重复计算。仅 TTL 过期，不做主动失效——
// 评分输入变化后最多 stale 一个 TTL，对评分展示可接受。
type ttlCache[T any] struct {
	mu    sync.Mutex
	ttl   time.Duration
	items map[string]ttlItem[T]
}

type ttlItem[T any] struct {
	value   T
	expires time.Time
}

func newTTLCache[T any](ttl time.Duration) *ttlCache[T] {
	return &ttlCache[T]{ttl: ttl, items: make(map[string]ttlItem[T])}
}

func (c *ttlCache[T]) get(key string) (T, bool) {
	var zero T
	c.mu.Lock()
	defer c.mu.Unlock()
	item, ok := c.items[key]
	if !ok || time.Now().After(item.expires) {
		if ok {
			delete(c.items, key)
		}
		return zero, false
	}
	return item.value, true
}

func (c *ttlCache[T]) put(key string, value T) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// 顺手清理过期项，避免长期运行的 map 膨胀。
	if len(c.items) > 64 {
		now := time.Now()
		for k, it := range c.items {
			if now.After(it.expires) {
				delete(c.items, k)
			}
		}
	}
	c.items[key] = ttlItem[T]{value: value, expires: time.Now().Add(c.ttl)}
}

// cacheKey 把查询要素散列成短 key（cond 里的参数值参与散列，不同筛选互不命中）。
func cacheKey(parts ...any) string {
	h := sha1.New()
	for _, p := range parts {
		h.Write([]byte(fmt.Sprint(p)))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}
