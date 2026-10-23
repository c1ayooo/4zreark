package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/repo"
)

// 全局通知管理器实例
var (
	globalManager     *NotifyManager
	globalManagerOnce sync.Once
)

// GetGlobalManager 获取全局通知管理器实例
func GetGlobalManager() *NotifyManager {
	globalManagerOnce.Do(func() {
		globalManager = NewNotifyManager()
		globalManager.loadConfigs()
		globalManager.loadEnvFeishuConfig()
		globalManager.Start()
		log.Println("[Notify] Global notify manager initialized")
	})
	return globalManager
}

// NotifyManager 通知管理器
type NotifyManager struct {
	notifiers []Notifier
	configs   []NotifyConfig
	mu        sync.RWMutex

	// 通知队列
	queue  chan *NotifyMessage
	stopCh chan struct{}

	// 通知历史
	history    []*NotifyHistory
	historyMu  sync.RWMutex
	maxHistory int
}

// NotifyHistory 通知历史记录
type NotifyHistory struct {
	ID        string         `json:"id"`
	Message   *NotifyMessage `json:"message"`
	Type      NotifyType     `json:"type"`
	Status    string         `json:"status"` // success, failed
	Error     string         `json:"error,omitempty"`
	Timestamp time.Time      `json:"timestamp"`
}

// NewNotifyManager 创建通知管理器
func NewNotifyManager() *NotifyManager {
	return &NotifyManager{
		notifiers:  make([]Notifier, 0),
		configs:    make([]NotifyConfig, 0),
		queue:      make(chan *NotifyMessage, 1000),
		stopCh:     make(chan struct{}),
		history:    make([]*NotifyHistory, 0),
		maxHistory: 1000,
	}
}

// Start 启动通知管理器
func (m *NotifyManager) Start() {
	go m.processQueue()
}

// Stop 停止通知管理器
func (m *NotifyManager) Stop() {
	close(m.stopCh)
}

// loadConfigs 从 PostgreSQL 恢复渠道配置。repo 未初始化（worker 节点）时跳过。
func (m *NotifyManager) loadConfigs() {
	r := repo.Default()
	if r == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	recs, err := r.Notify().ListConfigs(ctx)
	if err != nil {
		log.Printf("[Notify] 加载通知配置失败（表可能未创建）: %v", err)
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	for _, rec := range recs {
		var c NotifyConfig
		if err := json.Unmarshal(rec.Config, &c); err != nil {
			log.Printf("[Notify] 配置 %s/%s 解析失败: %v", rec.Name, rec.Type, err)
			continue
		}
		c.Name = rec.Name
		c.Type = NotifyType(rec.Type)
		c.Enabled = rec.Enabled
		m.configs = append(m.configs, c)
	}
	m.rebuildNotifiers()
	log.Printf("[Notify] 已加载 %d 个通知配置", len(recs))
}

// loadEnvFeishuConfig 支持用环境变量提供飞书企业应用凭据，避免把 secret 写进配置文件。
// 环境变量优先于同名渠道：库里已有同一个 app_id 时不再重复添加。
func (m *NotifyManager) loadEnvFeishuConfig() {
	appID := os.Getenv("ZRE_FEISHU_APP_ID")
	appSecret := os.Getenv("ZRE_FEISHU_APP_SECRET")
	receiveID := os.Getenv("ZRE_FEISHU_RECEIVE_ID")
	if appID == "" || appSecret == "" || receiveID == "" {
		return
	}
	receiveIDType := os.Getenv("ZRE_FEISHU_RECEIVE_ID_TYPE")
	if receiveIDType == "" {
		receiveIDType = "open_id"
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.configs {
		if c.Type == NotifyTypeFeishu && c.FeishuAppID == appID {
			return
		}
	}
	m.configs = append(m.configs, NotifyConfig{
		Name:                "飞书企业应用",
		Type:                NotifyTypeFeishu,
		Enabled:             true,
		FeishuAppID:         appID,
		FeishuAppSecret:     appSecret,
		FeishuReceiveIDType: receiveIDType,
		FeishuReceiveID:     receiveID,
	})
	m.rebuildNotifiers()
	log.Println("[Notify] 已从环境变量加载飞书企业应用配置")
}

// persistConfig 把渠道配置写回 PostgreSQL；失败只记日志，不影响当前进程内发送。
func (m *NotifyManager) persistConfig(c NotifyConfig) {
	r := repo.Default()
	if r == nil {
		return
	}
	raw, err := json.Marshal(c)
	if err != nil {
		log.Printf("[Notify] 配置序列化失败: %v", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := r.Notify().UpsertConfig(ctx, &repo.NotifyConfigRecord{
		Name:    c.Name,
		Type:    string(c.Type),
		Enabled: c.Enabled,
		Config:  raw,
	}); err != nil {
		log.Printf("[Notify] 配置 %s/%s 持久化失败: %v", c.Name, c.Type, err)
	}
}

func (m *NotifyManager) deleteConfigRecord(name string, t NotifyType) {
	r := repo.Default()
	if r == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := r.Notify().DeleteConfig(ctx, name, string(t)); err != nil {
		log.Printf("[Notify] 配置 %s/%s 删除失败: %v", name, t, err)
	}
}

// mergeMaskedSecrets 保住前端回传的脱敏字段：GET 返回的是 abcd****wxyz，
// 直接保存会把真实密钥覆盖成星号。
func mergeMaskedSecrets(in, existing NotifyConfig) NotifyConfig {
	keep := func(v, old string) string {
		if strings.Contains(v, "****") {
			return old
		}
		return v
	}
	in.DingTalkSecret = keep(in.DingTalkSecret, existing.DingTalkSecret)
	in.FeishuSecret = keep(in.FeishuSecret, existing.FeishuSecret)
	in.FeishuAppSecret = keep(in.FeishuAppSecret, existing.FeishuAppSecret)
	in.SMTPPassword = keep(in.SMTPPassword, existing.SMTPPassword)
	return in
}

// MergeConfigSecrets 供测试接口使用：用已保存的真实密钥补齐脱敏字段。
func (m *NotifyManager) MergeConfigSecrets(config NotifyConfig) NotifyConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, c := range m.configs {
		if c.Name == config.Name && c.Type == config.Type {
			return mergeMaskedSecrets(config, c)
		}
	}
	return config
}

// AddConfig 添加或更新通知配置（按 name + type 唯一）。
func (m *NotifyManager) AddConfig(config NotifyConfig) {
	m.mu.Lock()
	for i, c := range m.configs {
		if c.Name == config.Name && c.Type == config.Type {
			config = mergeMaskedSecrets(config, c)
			m.configs[i] = config
			m.rebuildNotifiers()
			m.mu.Unlock()
			m.persistConfig(config)
			return
		}
	}
	m.configs = append(m.configs, config)
	m.rebuildNotifiers()
	m.mu.Unlock()
	m.persistConfig(config)
}

// RemoveConfig 移除通知配置
func (m *NotifyManager) RemoveConfig(name string, t NotifyType) {
	m.mu.Lock()
	for i, c := range m.configs {
		if c.Name == name && c.Type == t {
			m.configs = append(m.configs[:i], m.configs[i+1:]...)
			m.rebuildNotifiers()
			m.mu.Unlock()
			m.deleteConfigRecord(name, t)
			return
		}
	}
	m.mu.Unlock()
}

// GetConfigs 获取所有配置
func (m *NotifyManager) GetConfigs() []NotifyConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()

	configs := make([]NotifyConfig, len(m.configs))
	copy(configs, m.configs)
	return configs
}

// EnableConfig 启用配置
func (m *NotifyManager) EnableConfig(name string, t NotifyType, enabled bool) {
	m.mu.Lock()
	for i, c := range m.configs {
		if c.Name == name && c.Type == t {
			m.configs[i].Enabled = enabled
			updated := m.configs[i]
			m.rebuildNotifiers()
			m.mu.Unlock()
			m.persistConfig(updated)
			return
		}
	}
	m.mu.Unlock()
}

// rebuildNotifiers 重建通知器列表
func (m *NotifyManager) rebuildNotifiers() {
	m.notifiers = make([]Notifier, 0)

	for _, config := range m.configs {
		if !config.Enabled {
			continue
		}

		notifier := m.createNotifier(config)
		if notifier != nil {
			m.notifiers = append(m.notifiers, notifier)
		}
	}
}

// createNotifier 根据配置创建通知器
func (m *NotifyManager) createNotifier(config NotifyConfig) Notifier {
	switch config.Type {
	case NotifyTypeDingTalk:
		if config.DingTalkWebhook != "" {
			return NewDingTalkNotifier(config.DingTalkWebhook, config.DingTalkSecret)
		}
	case NotifyTypeFeishu:
		if config.FeishuAppID != "" && config.FeishuAppSecret != "" && config.FeishuReceiveID != "" {
			return NewFeishuAppNotifier(
				config.FeishuAppID,
				config.FeishuAppSecret,
				config.FeishuReceiveIDType,
				config.FeishuReceiveID,
			)
		}
		if config.FeishuWebhook != "" {
			return NewFeishuNotifier(config.FeishuWebhook, config.FeishuSecret)
		}
	case NotifyTypeWechat:
		if config.WechatWebhook != "" {
			return NewWechatNotifier(config.WechatWebhook)
		}
	case NotifyTypeEmail:
		if config.SMTPHost != "" && len(config.EmailTo) > 0 {
			return NewEmailNotifier(
				config.SMTPHost,
				config.SMTPPort,
				config.SMTPUser,
				config.SMTPPassword,
				config.SMTPFrom,
				config.EmailTo,
			)
		}
	case NotifyTypeWebhook:
		if config.WebhookURL != "" {
			return NewWebhookNotifier(config.WebhookURL, config.WebhookMethod, config.WebhookHeaders)
		}
	}
	return nil
}

// Send 发送通知（同步）
func (m *NotifyManager) Send(ctx context.Context, msg *NotifyMessage) error {
	if msg == nil {
		return nil
	}
	if !NotifyLevelAllowed(msg.Level) {
		return nil
	}
	m.mu.RLock()
	notifiers := m.notifiers
	m.mu.RUnlock()

	if msg.Timestamp.IsZero() {
		msg.Timestamp = time.Now()
	}
	// 脱敏后再发给任何通道，历史记录也保存脱敏后的内容。
	masked := *msg
	if msg.Extra != nil {
		masked.Extra = make(map[string]interface{}, len(msg.Extra))
		for k, v := range msg.Extra {
			masked.Extra[k] = v
		}
	}
	MaskMessage(&masked)
	msg = &masked

	// 站内通知先落库：即使一个外部渠道都没配，页面铃铛也能收到。
	m.saveNotification(msg)

	var lastErr error
	for _, notifier := range notifiers {
		if err := notifier.Send(ctx, msg); err != nil {
			lastErr = err
			perr := MaskSensitive(err.Error())
			log.Printf("[Notify] Failed to send via %s: %s", notifier.Type(), perr)
			m.addHistory(msg, notifier.Type(), "failed", perr)
		} else {
			m.addHistory(msg, notifier.Type(), "success", "")
		}
	}

	return lastErr
}

// SendAsync 发送通知（异步）
func (m *NotifyManager) SendAsync(msg *NotifyMessage) {
	if msg.Timestamp.IsZero() {
		msg.Timestamp = time.Now()
	}

	select {
	case m.queue <- msg:
	default:
		log.Printf("[Notify] Queue full, dropping message: %s", msg.Title)
	}
}

// processQueue 处理消息队列
func (m *NotifyManager) processQueue() {
	for {
		select {
		case <-m.stopCh:
			return
		case msg := <-m.queue:
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			m.Send(ctx, msg)
			cancel()
		}
	}
}

// saveNotification 把消息写入站内通知表。独立超时，调用方取消不影响落库。
func (m *NotifyManager) saveNotification(msg *NotifyMessage) {
	r := repo.Default()
	if r == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := r.Notify().AddNotification(ctx,
		string(msg.Level), msg.Title, msg.Content, msg.Source, msg.Extra); err != nil {
		log.Printf("[Notify] 站内通知落库失败: %v", err)
	}
}

// addHistory 添加历史记录
func (m *NotifyManager) addHistory(msg *NotifyMessage, t NotifyType, status, errMsg string) {
	m.historyMu.Lock()
	defer m.historyMu.Unlock()

	history := &NotifyHistory{
		ID:        generateID(),
		Message:   msg,
		Type:      t,
		Status:    status,
		Error:     errMsg,
		Timestamp: time.Now(),
	}

	m.history = append(m.history, history)

	// 限制历史记录数量
	if len(m.history) > m.maxHistory {
		m.history = m.history[len(m.history)-m.maxHistory:]
	}
}

// GetHistory 获取历史记录
func (m *NotifyManager) GetHistory(limit int) []*NotifyHistory {
	m.historyMu.RLock()
	defer m.historyMu.RUnlock()

	if limit <= 0 || limit > len(m.history) {
		limit = len(m.history)
	}

	// 返回最新的记录
	start := len(m.history) - limit
	if start < 0 {
		start = 0
	}

	result := make([]*NotifyHistory, limit)
	copy(result, m.history[start:])

	// 反转顺序，最新的在前
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return result
}

// TestNotifier 测试通知器
func (m *NotifyManager) TestNotifier(config NotifyConfig) error {
	notifier := m.createNotifier(config)
	if notifier == nil {
		return fmt.Errorf("通知配置不完整：请检查渠道类型与必填字段")
	}

	msg := &NotifyMessage{
		Level:     NotifyLevelInfo,
		Title:     "测试通知",
		Content:   "这是一条来自 4zreark 的测试通知消息。\n\n如果您收到此消息，说明通知配置正确。",
		Source:    "system",
		Timestamp: time.Now(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	return notifier.Send(ctx, msg)
}

// NotifyVulnerability 发送漏洞通知
func (m *NotifyManager) NotifyVulnerability(vulnName, target, severity, details string) {
	level := NotifyLevelInfo
	switch severity {
	case "critical", "high":
		level = NotifyLevelCritical
	case "medium":
		level = NotifyLevelWarning
	}

	msg := &NotifyMessage{
		Level:     level,
		Title:     "发现漏洞: " + vulnName,
		Content:   fmt.Sprintf("**目标**: %s\n**严重程度**: %s\n\n%s", target, severity, details),
		Source:    "vuln_scanner",
		Timestamp: time.Now(),
		Extra: map[string]interface{}{
			"vuln_name": vulnName,
			"target":    target,
			"severity":  severity,
		},
	}

	m.SendAsync(msg)
}

// NotifyTaskComplete 发送任务完成通知
func (m *NotifyManager) NotifyTaskComplete(taskName string, taskID string, success bool, summary string, stats map[string]interface{}) {
	level := NotifyLevelInfo
	title := "✅ 扫描完成: " + taskName
	if !success {
		level = NotifyLevelWarning
		title = "❌ 扫描失败: " + taskName
	}

	msg := &NotifyMessage{
		Level:     level,
		Title:     title,
		Content:   summary,
		Source:    "task_manager",
		Timestamp: time.Now(),
		Extra: map[string]interface{}{
			"task_name": taskName,
			"task_id":   taskID,
			"success":   success,
			"stats":     stats,
		},
	}

	m.SendAsync(msg)
}

// NotifyAssetChange 发送资产变更通知
// NotifyAssetChange 资产变更通知。changeType 用中文短句（进通知标题），
// extra 会随站内通知落库（前端 notificationLink 优先读 extra.link 做跳转）。
func (m *NotifyManager) NotifyAssetChange(changeType, assetInfo string, extra map[string]interface{}) {
	msg := &NotifyMessage{
		Level:     NotifyLevelInfo,
		Title:     "资产变更: " + changeType,
		Content:   assetInfo,
		Source:    "asset_monitor",
		Extra:     extra,
		Timestamp: time.Now(),
	}

	m.SendAsync(msg)
}

// generateID 生成简单ID
func generateID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}
