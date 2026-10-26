// notifier 垫片：迁移自 4zreco 的 githubleak 包原先依赖 4zreco/internal/notifier
// 与 robot；4zreark 用本包内的最小镜像替代，Service.notify 出口由 main 接到
// 标准库日志（后续要接 IM 机器人时在 main 一处换实现即可）。
package githubleak

// AlertItem 通知卡片条目（AlertItem 镜像）。
type AlertItem struct {
	Tag  string
	Text string
	Link string
	Sub  string
}

// 事件类型常量（Kind* 镜像）。
const (
	KindGithubLeakFound        = "githubleak.found"         // GitHub 泄露监控新命中
	KindGithubLeakRuleDisabled = "githubleak.rule_disabled" // GitHub 泄露监控规则自净停用（R7）
)

// Event 通知事件（Event 的 githubleak 用面子集）。
type Event struct {
	Kind     string
	Level    string // critical/high/medium/low/info
	Title    string
	Summary  string
	Items    []AlertItem
	Footer   string
	DedupKey string
	// Broadcast 强制广播（系统级事件）。
	Broadcast bool
}
