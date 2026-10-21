// Package extractor 提取链：nuclei 命中后的「检测 → 提取 → 落盘」第三段。
//
// 定位：自动验证（vulnverify）已经确认「模板命中」，本包负责把命中报文中携带的
// 凭据（sftp.json）、内网信息（phpinfo）、仓库（.git/config）、备份文件等解析成
// 结构化产物（Finding），由 app 层转存 recon_findings 表。
//
// 解耦：本包不 import vulnverify / database——Ctx 直接携带提取所需字段（从
// HitResult 复制），Finding 是独立类型；具体提取器按模板 id 注册进注册表，
// app 层装配时用 ForTemplate 查表分派。
package extractor

import (
	"context"
	"net/http"
	"time"
)

// Finding 一次提取的结构化产物（app 层转存 database.ReconFinding）。
type Finding struct {
	ProjectID   string
	Domain      string // 目标域（可空）
	Target      string // 命中目标（URL / 主机 / CNAME）
	Category    string // sftp_credential / phpinfo_field / git_repo / backup_file / cloud_credential ...
	Kind        string // 该类别下的具体类型（如 bucket / storage_account）
	Data        string // 结构化 JSON（云资源 provider/kind/name 等）
	RawEvidence string // 原始命中片段（正文/报文关键行）
	FilePath    string // 归档文件路径（相对项目根；可空）
}

// Ctx 提取上下文：命中信息 + 注入的可复用能力（下载客户端、归档目录）。
type Ctx struct {
	ProjectID   string
	Domain      string
	Target      string // 验证目标（task.Target，域名或 URL）
	MatchURL    string // 命中 URL（host + matched-at 路径，可空）
	TemplateID  string
	Severity    string
	Request     string
	Response    string
	CurlCommand string
	Extracted   []string
	// HTTPClient 下载用客户端（app 注入；nil = 拒绝下载，仅解析已有报文）。
	HTTPClient *http.Client
	// DownloadDir 归档根目录（相对项目根；nil = 不落盘归档）。
	DownloadDir string
	// Timeout 单次提取超时（0 = 默认 20s）。
	Timeout time.Duration
}

// Extractor 模板命中后的提取器。
type Extractor interface {
	// Supports 该提取器是否处理此模板 id（按 nuclei template-id 匹配）。
	Supports(templateID string) bool
	// Extract 从命中上下文提取结构化产物。nil 产物 = 本次无可用信息（不落盘）。
	Extract(ctx context.Context, c *Ctx) (*Finding, error)
}

// registry 内置提取器注册表（包 init 时注册；测试可直接构造 Ctx 调用单个提取器）。
var registry []Extractor

// Register 注册一个提取器。
func Register(e Extractor) { registry = append(registry, e) }

// ForTemplate 返回第一个支持该模板 id 的提取器；无则 nil。
func ForTemplate(templateID string) Extractor {
	for _, e := range registry {
		if e.Supports(templateID) {
			return e
		}
	}
	return nil
}

// All 全部注册提取器（装配层遍历用，如启动自检）。
func All() []Extractor { return registry }
