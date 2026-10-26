// Package svcid 开放端口的服务协议识别:基于 fingerprintx 的真实协议握手探测。
//
// fingerprintx 内部自带端口先验(3389 先试 RDP、6379 先试 Redis……,dddd 风格),
// 先验命中可跳过逐协议试探的超时等待;不匹配再退化到通用探测。
// 并发模型:按端口分发的 worker 池(单主机内并发,主机间由调用方控制)。
package svcid

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/praetorian-inc/fingerprintx/pkg/scan"
)

// Service 单个开放端口的服务识别结论。
type Service struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"` // http/https/ssh/redis/mysql/postgres/ftp/smtp/telnet/rdp/unknown…
	TLS      bool   `json:"tls"`
	Version  string `json:"version,omitempty"`
	// Banner 协议横幅/握手文本（从 fingerprintx metadata 提取，如 SSH 的
	// "SSH-2.0-OpenSSH_8.9p1 …"）。规则引擎的 banner 字段匹配源：非 HTTP
	// 协议识别结论经此字段回流 Observation，见 pipeline/matchNonHTTPService。
	Banner string `json:"banner,omitempty"`
}

// Options 识别参数。
type Options struct {
	Timeout    time.Duration // 单协议握手超时,<=0 按 3s
	PerPortMax time.Duration // 单端口识别总预算(fingerprintx 慢速通道会逐协议
	//                            试探,未知端口最坏可达数十秒;超预算返回 unknown
	//                            保证流水线有界),<=0 按 Timeout×4 且不小于 10s
	Concurrency int // worker 数,<=0 按 32
}

// perPortBudget 单端口识别总预算。
func (o Options) perPortBudget() time.Duration {
	if o.PerPortMax > 0 {
		return o.PerPortMax
	}
	t := o.Timeout
	if t <= 0 {
		t = 3 * time.Second
	}
	if budget := 4 * t; budget > 10*time.Second {
		return budget
	}
	return 10 * time.Second
}

// Scan 对一个主机的开放端口做并发协议识别。
// 识别失败的端口返回 Protocol=unknown(调用方可回退端口先验静态名)。
func Scan(ctx context.Context, ip string, ports []int, opts Options) []Service {
	if opts.Timeout <= 0 {
		opts.Timeout = 3 * time.Second
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 32
	}

	jobs := make(chan int)
	results := make([]Service, 0, len(ports))
	var mu sync.Mutex
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case port, ok := <-jobs:
				if !ok {
					return
				}
				svc := probeBounded(ctx, ip, port, opts)
				mu.Lock()
				results = append(results, svc)
				mu.Unlock()
			}
		}
	}
	for i := 0; i < opts.Concurrency; i++ {
		wg.Add(1)
		go worker()
	}
	for _, p := range ports {
		select {
		case <-ctx.Done():
		case jobs <- p:
		}
	}
	close(jobs)
	wg.Wait()
	return results
}

// probeBounded 单端口识别总预算看门狗:超预算返回 unknown,保证有界。
func probeBounded(ctx context.Context, ip string, port int, opts Options) Service {
	done := make(chan Service, 1)
	go func() { done <- probe(ctx, ip, port, opts.Timeout) }()
	budget := opts.perPortBudget()
	select {
	case svc := <-done:
		return svc
	case <-time.After(budget):
		return Service{Port: port, Protocol: "unknown"}
	case <-ctx.Done():
		return Service{Port: port, Protocol: "unknown"}
	}
}

func probe(ctx context.Context, ip string, port int, timeout time.Duration) Service {
	if err := ctx.Err(); err != nil {
		return Service{Port: port, Protocol: "unknown"}
	}
	addr, err := netip.ParseAddrPort(fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		return Service{Port: port, Protocol: "unknown"}
	}
	cfg := scan.Config{DefaultTimeout: timeout}
	res, scanErr := cfg.SimpleScanTarget(plugins.Target{Address: addr, Host: ip})
	if scanErr != nil || res == nil {
		return Service{Port: port, Protocol: "unknown"}
	}
	return Service{
		Port:     port,
		Protocol: normalizeProtocol(res.Protocol),
		TLS:      res.TLS,
		Version:  strings.TrimSpace(res.Version),
		Banner:   extractBanner(res.Raw),
	}
}

// extractBanner 从 fingerprintx 的协议 metadata(Raw) 提取可匹配的横幅文本。
// fingerprintx 各插件的 Service 结构不同:SSH/FTP 等把横幅放 "banner" 键,
// 其余协议是结构化语义字段(如 Redis 的 authRequired、SMB 的 signingRequired/
// osVersion、MongoDB 的 serverType)。优先取 "banner" 键的字符串值;取不到时
// 把 metadata 的顶层键值对扁平化为 "k1=v1 k2=v2" 文本——协议语义经此处
// 暴露给规则引擎的 banner 字段(协议面扩展 L3),任意 proto.* 语义都能用
// bare 规则 `banner ~= "authRequired=false"` 匹配,零新增引擎字段。
func extractBanner(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	if s, ok := bannerString(raw, "banner"); ok {
		return s
	}
	return flattenMetadata(raw)
}

// bannerString 取 metadata 中指定键的字符串值。
func bannerString(raw json.RawMessage, key string) (string, bool) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return "", false
	}
	v, ok := m[key]
	if !ok {
		return "", false
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		return "", false
	}
	if s = strings.TrimSpace(s); s == "" {
		return "", false
	}
	return s, true
}

// metadataNoiseKeys 扁平化时忽略的噪音键(规则匹配无价值或易误报)。
var metadataNoiseKeys = map[string]bool{
	"confidence": true, "cpes": true,
}

// flattenMetadata 把 metadata 顶层键值对拼成 "k=v k=v" 文本(确定性键序)。
// 语义键优先于原文输出,保证规则可匹配;值做类型归一与截断,上限防爆。
func flattenMetadata(raw json.RawMessage) string {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return string(raw)
	}
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		if metadataNoiseKeys[k] {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		v := metadataValue(m[k])
		if v == "" {
			continue
		}
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, " ")
}

// metadataValue 归一 metadata 值到可匹配文本:字符串原样、数字/布尔转
// 文本、数组/对象 JSON 紧凑化。截断单值上限,防超大字段拖慢规则求值。
func metadataValue(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return truncateBanner(s)
	}
	var num json.Number
	if err := json.Unmarshal(raw, &num); err == nil {
		return num.String()
	}
	// 布尔(false 也保留:authRequired=false 正是「未授权」信号,丢掉会漏检)
	var b bool
	if err := json.Unmarshal(raw, &b); err == nil {
		return strconv.FormatBool(b)
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err == nil {
		return truncateBanner(buf.String())
	}
	return truncateBanner(string(raw))
}

// truncateBanner 单值截断上限(128 字符),保证 banner 总量有界。
const bannerValueCap = 128

func truncateBanner(s string) string {
	if len(s) <= bannerValueCap {
		return s
	}
	return s[:bannerValueCap-1] + "…"
}

// normalizeProtocol 归一 fingerprintx 协议名(HTTPTLS/TCPTLS 等)。
func normalizeProtocol(p string) string {
	switch strings.ToUpper(strings.TrimSpace(p)) {
	case "HTTP":
		return "http"
	case "HTTPTLS", "TCPTLS", "HTTPS":
		return "https"
	case "SSH":
		return "ssh"
	case "REDIS":
		return "redis"
	case "MYSQL":
		return "mysql"
	case "POSTGRES", "POSTGRESQL":
		return "postgres"
	case "FTP":
		return "ftp"
	case "SMTP":
		return "smtp"
	case "TELNET":
		return "telnet"
	case "RDP":
		return "rdp"
	case "MQTT":
		return "mqtt"
	case "MEMCACHED":
		return "memcached"
	case "POP3":
		return "pop3"
	case "IMAP":
		return "imap"
	case "":
		return "unknown"
	default:
		return strings.ToLower(strings.TrimSpace(p))
	}
}
