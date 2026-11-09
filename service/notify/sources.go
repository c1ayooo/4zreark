package notify

import "strings"

// 通知对象目录：按事件来源（及资产变更子类型）的开关口径。
// key 与消息的 Source 字段一致；资产变更的子键用「父键:子键」。
// manual / system 不设开关：避免把管理员自己的测试与系统通知关聋。

// NotifySourceItem 是目录里一条可开关的通知对象。Enabled 是当前开关状态。
type NotifySourceItem struct {
	Key         string             `json:"key"`
	Label       string             `json:"label"`
	Group       string             `json:"group"`
	Description string             `json:"description"`
	Enabled     bool               `json:"enabled"`
	Children    []NotifySourceItem `json:"children,omitempty"`
}

// SourceCatalog 顶级通知对象。enabled 状态由管理器的 disabledSources 决定，不进目录。
var SourceCatalog = []NotifySourceItem{
	{
		Key: "asset_monitor", Label: "资产变更", Group: "资产",
		Description: "站点内容变更、新资产候选、证书到期、资产失联",
		Children: []NotifySourceItem{
			{Key: "asset_monitor:site_content_change", Label: "站点页面内容变更", Group: "资产", Description: "站点监控发现的页面内容变化"},
			{Key: "asset_monitor:new_asset_candidate", Label: "巡航新资产候选", Group: "资产", Description: "巡航发现的新资产候选"},
			{Key: "asset_monitor:cert_expiry", Label: "证书到期", Group: "资产", Description: "证书已过期 / 即将到期 / 到期提醒"},
			{Key: "asset_monitor:site_down", Label: "资产失联与恢复", Group: "资产", Description: "站点失联告警与恢复通知"},
		},
	},
	{Key: "sentinel", Label: "提交哨兵", Group: "代码审计", Description: "判定命中安全修复、采集批次失败"},
	{Key: "pocsmith", Label: "差分复现", Group: "代码审计", Description: "沙箱差分复现的结论"},
	{Key: "vuln_scanner", Label: "漏洞发现", Group: "漏洞", Description: "扫描发现高危漏洞聚合"},
	{Key: "vuln-review", Label: "漏洞复核", Group: "漏洞", Description: "漏洞复核流程通知"},
	{Key: "vuln-intel", Label: "漏洞情报", Group: "漏洞", Description: "高危漏洞情报提醒"},
	{Key: "task_manager", Label: "扫描任务", Group: "任务", Description: "任务完成 / 失败"},
	{Key: "cruise", Label: "巡航", Group: "任务", Description: "巡航轮次结论与目标路由通知"},
	{Key: "github-leak", Label: "GitHub 泄漏监控", Group: "监控", Description: "仓库泄漏规则命中"},
	{Key: "node-watchdog", Label: "节点告警", Group: "监控", Description: "节点离线与恢复"},
	{Key: "datasource-session", Label: "数据源会话", Group: "采集", Description: "数据源会话过期等告警"},
	{Key: "collection-assessment", Label: "采集评估", Group: "采集", Description: "采集质量评估结论"},
}

// assetChangeTypeKeys 把资产变更的中文 changeType 归一到子键。
// 证书到期是动态标题（剩余天数），按前缀归一。
var assetChangeTypeKeys = map[string]string{
	"站点页面内容变更":  "asset_monitor:site_content_change",
	"巡航发现新资产候选": "asset_monitor:new_asset_candidate",
	"资产失联":      "asset_monitor:site_down",
	"失联资产恢复":    "asset_monitor:site_down",
}

// AssetChangeTypeKey 返回 changeType 对应的子键；未登记的变更类型返回空串（回落到父键开关）。
func AssetChangeTypeKey(changeType string) string {
	changeType = strings.TrimSpace(changeType)
	if changeType == "" {
		return ""
	}
	if k, ok := assetChangeTypeKeys[changeType]; ok {
		return k
	}
	if strings.HasPrefix(changeType, "证书") {
		return "asset_monitor:cert_expiry"
	}
	return ""
}

// knownSourceKeys 是合法的通知对象 key 集合（顶级 + 资产变更子键）。
var knownSourceKeys = func() map[string]bool {
	m := make(map[string]bool)
	for _, s := range SourceCatalog {
		m[s.Key] = true
		for _, c := range s.Children {
			m[c.Key] = true
		}
	}
	return m
}()

// KnownSourceKey 校验 key 是否在目录内，防止把任意串写进开关配置。
func KnownSourceKey(key string) bool {
	return knownSourceKeys[key]
}
