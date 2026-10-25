package notify

import (
	"context"
	"log"
	"strings"
	"time"
)

// channelTypeFilter 归并渠道类型集合：小写、去空白、去重，空串丢弃。
func channelTypeFilter(channelTypes []string) map[NotifyType]bool {
	out := make(map[NotifyType]bool, len(channelTypes))
	for _, t := range channelTypes {
		if t = strings.ToLower(strings.TrimSpace(t)); t != "" {
			out[NotifyType(t)] = true
		}
	}
	return out
}

// SendTargetedAsync 只把通知发到指定类型的渠道（如 ["feishu","email"]），
// 空列表退化为 SendAsync 的全渠道语义。巡航等场景按任务自带配置路由通知时使用；
// 不能走 SendAsync 的队列——队列消费者会广播到所有渠道，无法按渠道过滤。
func (m *NotifyManager) SendTargetedAsync(msg *NotifyMessage, channelTypes []string) {
	if msg == nil {
		return
	}
	if len(channelTypeFilter(channelTypes)) == 0 {
		m.SendAsync(msg)
		return
	}
	if msg.Timestamp.IsZero() {
		msg.Timestamp = time.Now()
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		m.sendTargeted(ctx, msg, channelTypeFilter(channelTypes))
	}()
}

// sendTargeted 定向分发：脱敏、站内落库与级别过滤的语义与 Send 保持一致，
// 差别仅在只投递类型命中的渠道。
func (m *NotifyManager) sendTargeted(ctx context.Context, msg *NotifyMessage, types map[NotifyType]bool) {
	if !NotifyLevelAllowed(msg.Level) {
		return
	}
	m.mu.RLock()
	dispatch := m.dispatch
	m.mu.RUnlock()

	masked := *msg
	if msg.Extra != nil {
		masked.Extra = make(map[string]interface{}, len(msg.Extra))
		for k, v := range msg.Extra {
			masked.Extra[k] = v
		}
	}
	MaskMessage(&masked)
	msg = &masked

	m.saveNotification(msg)

	for _, d := range dispatch {
		if !types[d.cfg.Type] {
			continue
		}
		if !ChannelLevelAllowed(msg.Level, d.cfg.MinLevel) {
			continue
		}
		if err := d.notifier.Send(ctx, msg); err != nil {
			perr := MaskSensitive(err.Error())
			log.Printf("[Notify] Failed to send via %s: %s", d.notifier.Type(), perr)
			m.addHistory(msg, d.notifier.Type(), "failed", perr)
		} else {
			m.addHistory(msg, d.notifier.Type(), "success", "")
		}
	}
}
