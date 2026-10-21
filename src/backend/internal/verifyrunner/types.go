// Package verifyrunner 提供「验证剧本」的确定性运行器（施工单 E1，见
// docs/渗透Agent优化施工单-验证剧本化与假设质量闭环.md）。
//
// 解决的问题：hypothesis 机制的 verify 三要素解决了「想到什么、怎么算证实」，
// 但多步有状态验证（POST 降级 → 触发请求 → GET 读回）仍靠 LLM 临场编排——
// 实测（深度审计 2026-09-27）LLM 编排不可靠（1.03 条漏洞/目标、会话双峰）。
// 本包把 verify 固化为可执行剧本：确定性 HTTP 步骤 + 断言 + 变量提取 + 终态判定。
//
// 红线（施工单 §五.2，runner 硬编码兜底，不信任 YAML 自报）：
//   - limits 是硬顶：max_requests ≤ 32 / steps ≤ 16 / repeat ≤ 4 / 并发恒 1；
//   - parse 期拒绝爆破形态（步骤/请求总量超限、非法方法）；
//   - 破坏性动作止步「证明可达」——剧本只发最小请求，不落地 payload；
//   - 重定向仅限同 host（302 跳登录/回跳允许，跨 host 一律停在 3xx 不跟随）。
package verifyrunner

import (
	"context"
	"net"
	"time"
)

// 剧本终态（写回 hp 条目 payload.hyp_verdict / 漏洞关联）。
const (
	VerdictConfirmed = "confirmed" // 全部步骤断言通过
	VerdictRefuted   = "refuted"   // 某步命中 playbook.refuted_status_in（如 401/404），假设证伪
	VerdictBlocked   = "blocked"   // 中途失败/超时/网络错误——不是「测过」，证据保留到失败步
)

// runner 硬顶（不信任 YAML 自报，超出即 parse 拒绝或运行 abort）。
const (
	MaxStepsHard        = 16
	MaxRequestsHard     = 32
	MaxRepeatPerStep    = 4
	DefaultMaxRequests  = 12
	DefaultStepTimeout  = 8 * time.Second
	MaxStepTimeout      = 30 * time.Second
	MaxRedirectsPerStep = 5
	MaxResponseBody     = 2 << 20 // 2MB：响应体读取上限
	RespSnippetLen      = 4096    // 步骤结果保留的响应片段长度（tcp banner 同规格截断）
	MaxTCPPayloadBytes  = 512     // tcp 步 payload 解码后上限（施工单 V1 红线，超出 parse 拒绝）
)

// 步骤 kind 词汇表（施工单 V1/V2）。缺省 http——兼容红线：既有预设剧本与历史
// inline JSON 无 kind 字段零改动仍跑通。词汇表封闭：未知值 parse 拒绝，
// 不给「偷渡新原语」留口（verify_run 是假设验证原语，不是自由执行通道）。
const (
	StepKindHTTP = "http"
	StepKindTCP  = "tcp"
	StepKindDNS  = "dns"
)

// Expectation 步骤断言（全部声明项满足 = 通过）。任一字段省略 = 不检查该维度。
// 断言字段按步骤 kind 分词汇表封闭（parse 期拒绝跨 kind 混用，见 parse.go）。
type Expectation struct {
	Status      int      `yaml:"status,omitempty" json:"status,omitempty"`             // 期望状态码（精确）
	StatusIn    []int    `yaml:"status_in,omitempty" json:"status_in,omitempty"`       // 期望状态码集合
	Contains    []string `yaml:"contains,omitempty" json:"contains,omitempty"`         // 响应体须全部包含
	ContainsAny []string `yaml:"contains_any,omitempty" json:"contains_any,omitempty"` // 响应体包含任一
	NotContains []string `yaml:"not_contains,omitempty" json:"not_contains,omitempty"` // 响应体不得包含
	Regex       string   `yaml:"regex,omitempty" json:"regex,omitempty"`               // 响应体须匹配（RE2）

	// V3（HTTP 侧断言面补齐）：header 断言与时长差分。
	RespHeaderContains []string `yaml:"resp_header_contains,omitempty" json:"resp_header_contains,omitempty"` // 响应头文本须全部包含（如 "Set-Cookie: sid="）
	RespHeaderRegex    string   `yaml:"resp_header_regex,omitempty" json:"resp_header_regex,omitempty"`       // 响应头文本须匹配（RE2）
	DurationMSLt       int      `yaml:"duration_ms_lt,omitempty" json:"duration_ms_lt,omitempty"`             // 步耗时须低于该毫秒值（0=不检查）
	DurationMSGt       int      `yaml:"duration_ms_gt,omitempty" json:"duration_ms_gt,omitempty"`             // 步耗时须高于该毫秒值（盲注 sleep 类差分判据）

	// V1（tcp 步）：connect/banner 断言。
	ConnectOK         *bool    `yaml:"connect_ok,omitempty" json:"connect_ok,omitempty"`           // 连接须建立（false=断言端口不可达；超时/被过滤不算「关闭」）
	BannerContains    []string `yaml:"banner_contains,omitempty" json:"banner_contains,omitempty"` // banner 须全部包含
	BannerNotContains []string `yaml:"banner_not_contains,omitempty" json:"banner_not_contains,omitempty"`
	BannerRegex       string   `yaml:"banner_regex,omitempty" json:"banner_regex,omitempty"` // banner 须匹配（RE2）

	// V2（dns 步）：解析观测断言（仅观测，查询固定走平台侧 resolver）。
	ResolveContains    []string `yaml:"resolve_contains,omitempty" json:"resolve_contains,omitempty"`         // 解析结果文本须全部包含（A 记录 IP 段/NS 名等）
	CnameChainContains []string `yaml:"cname_chain_contains,omitempty" json:"cname_chain_contains,omitempty"` // CNAME 解析目标须包含（悬挂/接管判据）
	TxtContains        []string `yaml:"txt_contains,omitempty" json:"txt_contains,omitempty"`                 // TXT 记录文本须包含
	ResolveCountLT     int      `yaml:"resolve_count_lt,omitempty" json:"resolve_count_lt,omitempty"`         // 解析记录数须少于该值（NXDOMAIN 判据：resolve_count_lt:1）
}

// StepRequest 一步请求。字段按 kind 分词汇表（http: method/url/headers/body；
// tcp: host/port/payload_hex；dns: query_name/query_type），跨 kind 混用 parse 拒绝。
type StepRequest struct {
	Method  string            `yaml:"method" json:"method"`
	URL     string            `yaml:"url" json:"url"`
	Headers map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
	Body    string            `yaml:"body,omitempty" json:"body,omitempty"`
	Repeat  int               `yaml:"repeat,omitempty" json:"repeat,omitempty"` // 默认 1；>MaxRepeatPerStep parse 拒绝（各 kind 通用）

	// tcp 步（kind=tcp）：host 须过 scope 硬校验（IP 直连不得绕过，工具层复用
	// agentTargetScopeCheck 同源通道逐目标校验）。
	Host       string `yaml:"host,omitempty" json:"host,omitempty"`               // 支持 {{var}}
	Port       int    `yaml:"port,omitempty" json:"port,omitempty"`               // 1~65535
	PayloadHex string `yaml:"payload_hex,omitempty" json:"payload_hex,omitempty"` // hex 编码探针（≤512B，如 redis PING）

	// dns 步（kind=dns）：query_name 须过 scope 硬校验；resolver 固定平台侧。
	QueryName string `yaml:"query_name,omitempty" json:"query_name,omitempty"` // 支持 {{var}}
	QueryType string `yaml:"query_type,omitempty" json:"query_type,omitempty"` // A（默认）/CNAME/TXT/NS
	// Resolver 字段只为 parse 期拒绝而存在（红线：不接受步骤内自定义 resolver，
	// 防把查询导向任意服务器），运行期永不消费。
	Resolver string `yaml:"resolver,omitempty" json:"resolver,omitempty"`
}

// StepExtract 响应提取：捕获组 1 存入变量，供后续步骤 {{var}} 引用。
type StepExtract struct {
	Name  string `yaml:"name" json:"name"`
	Regex string `yaml:"regex" json:"regex"`
	From  string `yaml:"from,omitempty" json:"from,omitempty"` // body（默认）| headers | banner（仅 tcp 步）
}

// Step 剧本单步。
type Step struct {
	Name string `yaml:"name" json:"name"`
	// Kind 步骤类型：http（缺省）/tcp/dns。缺省 http 是兼容红线——既有 9 份预设与
	// 历史 inline JSON 无 kind 字段零改动仍跑通。
	Kind    string        `yaml:"kind,omitempty" json:"kind,omitempty"`
	Request StepRequest   `yaml:"request" json:"request"`
	Expect  *Expectation  `yaml:"expect,omitempty" json:"expect,omitempty"`
	Extract []StepExtract `yaml:"extract,omitempty" json:"extract,omitempty"`
}

// Playbook 验证剧本。
type Playbook struct {
	ID   string `yaml:"id" json:"id"`
	Name string `yaml:"name,omitempty" json:"name,omitempty"`
	// RefutedStatusIn 任一步骤实际状态码命中即判 refuted（假设证伪）——典型 [401,403,404]。
	RefutedStatusIn []int `yaml:"refuted_status_in,omitempty" json:"refuted_status_in,omitempty"`
	// VarsRequired 运行期必须由调用方提供的外部变量（除内置 host 外）；闭包校验据此放行。
	VarsRequired []string `yaml:"vars_required,omitempty" json:"vars_required,omitempty"`
	Steps        []Step   `yaml:"steps" json:"steps"`
	Limits       Limits   `yaml:"limits,omitempty" json:"limits,omitempty"`
	Note         string   `yaml:"note,omitempty" json:"note,omitempty"` // 人工说明（判据来源等），runner 不消费
}

// Limits 剧本级限速（YAML 可写更小值，runner 以硬顶为准取 min）。
type Limits struct {
	MaxRequests      int `yaml:"max_requests,omitempty" json:"max_requests,omitempty"`
	PerStepTimeoutMS int `yaml:"per_step_timeout_ms,omitempty" json:"per_step_timeout_ms,omitempty"`
	// Concurrency 恒为 1（runner 串行）；YAML 声明 >1 直接 parse 拒绝（红线：并发 ≤2，取更严）。
	Concurrency int `yaml:"concurrency,omitempty" json:"concurrency,omitempty"`
}

// StepResult 单步执行结果（证据链：请求/响应摘要落 tool_executions）。
// Status 语义按 kind：http=状态码；tcp/dns：0=未获观测（网络错误→blocked），
// 1=观测完成（连接建立/明确拒绝/解析完成——NXDOMAIN 也是可观测结论）。
type StepResult struct {
	Name        string            `json:"name"`
	Method      string            `json:"method"` // http 方法；tcp/dns 步为 "TCP"/"DNS"
	URL         string            `json:"url"`
	Status      int               `json:"status"`
	OK          bool              `json:"ok"`
	FailReason  string            `json:"fail_reason,omitempty"`
	ReqHeaders  map[string]string `json:"req_headers,omitempty"`
	RespSnippet string            `json:"resp_snippet,omitempty"` // http=响应体片段；tcp=banner；dns=解析结果
	Extracted   map[string]string `json:"extracted,omitempty"`
	DurationMS  int64             `json:"duration_ms,omitempty"`
}

// DNSResolver dns 观测步的解析接口（*net.Resolver 天然满足，测试可注入桩）。
// resolver 恒为平台侧（运行环境系统配置）——步骤内自定义 resolver parse 期拒绝。
type DNSResolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
	LookupTXT(ctx context.Context, host string) ([]string, error)
	LookupNS(ctx context.Context, host string) ([]*net.NS, error)
}

// TCPDialer tcp 步的拨号接口（*net.Dialer 天然满足，测试可注入桩）。
// 「连接被明确拒绝（RST）→ 端口关闭是可观测结论」的判定依赖回环 RST 语义，
// 部分 WSL2 宿主上 Windows 侧 TUN 会间歇接管已关端口的握手导致假红——
// 涉及该语义的用例必须注入桩（2026-09-29 实测踩坑），不依赖真实回环行为。
type TCPDialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// RunResult 一次剧本运行结果。
type RunResult struct {
	PlaybookID string            `json:"playbook_id"`
	Verdict    string            `json:"verdict"` // confirmed | refuted | blocked
	Reason     string            `json:"reason,omitempty"`
	Steps      []StepResult      `json:"steps"`
	Extracted  map[string]string `json:"extracted,omitempty"` // 全部提取变量（终态快照）
	Requests   int               `json:"requests"`            // 实际发出的请求数
	DurationMS int64             `json:"duration_ms"`
}
