// Package portscan 纯 Go TCP connect 端口扫描：worker 池 + 令牌桶限速。
// 不做 SYN 扫描（raw socket 需要特权且平台差异大），与本项目"单二进制、
// 免特权运行"的定位一致；connect 模式的授权边界与 HTTP 探测完全相同。
package portscan

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Result 单个端口结论（只保留开放端口）。
type Result struct {
	IP      string `json:"ip"`
	Port    int    `json:"port"`
	Service string `json:"service"`
}

// Options 扫描参数。
type Options struct {
	Ports       []int         // 待扫端口列表
	Concurrency int           // 并发 worker 数，<=0 按 256
	Timeout     time.Duration // 单连接超时，<=0 按 2s
	RatePerSec  int           // 每秒新建连接上限，<=0 按 500
}

// Top100 常用端口集（naabu top-ports 的等价精简集）。
var Top100 = []int{
	21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 161, 389, 443, 445, 465, 500, 514,
	587, 623, 636, 873, 990, 993, 995, 1080, 1099, 1194, 1433, 1521, 1723, 1883, 2049, 2082,
	2083, 2181, 2375, 2376, 2425, 3000, 3128, 3268, 3306, 3389, 3690, 4443, 4444, 4711, 4848,
	5000, 5432, 5555, 5601, 5672, 5900, 5901, 5984, 6379, 6380, 6443, 6666, 7000, 7001, 7002, 7077, 7180,
	8000, 8001, 8008, 8009, 8010, 8020, 8040, 8060, 8069, 8080, 8081, 8082, 8083, 8086, 8088,
	8090, 8091, 8161, 8443, 8500, 8649, 8686, 8848, 8899, 8983, 9000, 9001, 9042, 9080, 9090,
	9091, 9200, 9300, 9418, 9443, 9999, 10000, 10250, 11211, 15672, 18080, 20000, 27017, 28017,
	50000, 50070, 61616,
}

// WebPorts 纯 Web 端口集（不启 TCP 端口扫描时的最小验证集）。
var WebPorts = []int{80, 443, 8000, 8080, 8081, 8443, 8888, 9000, 9090}

// ResolvePorts 把 port_set / custom_ports 表达式解析为端口列表。
// set 取 "top100" | "web"；custom 形如 "80,443,8000-9000" 与 set 取并集。
func ResolvePorts(set, custom string) []int {
	merged := map[int]bool{}
	switch set {
	case "top100":
		for _, p := range Top100 {
			merged[p] = true
		}
	case "web":
		for _, p := range WebPorts {
			merged[p] = true
		}
	}
	for _, part := range splitAndTrim(custom, ',') {
		if idx := indexOfByte(part, '-'); idx > 0 {
			lo, err1 := strconv.Atoi(strings.TrimSpace(part[:idx]))
			hi, err2 := strconv.Atoi(strings.TrimSpace(part[idx+1:]))
			if err1 == nil && err2 == nil && lo > 0 && hi >= lo && hi <= 65535 {
				for p := lo; p <= hi && p-lo < 2048; p++ { // 单段上限 2048，防手滑全段
					merged[p] = true
				}
			}
			continue
		}
		if p, err := strconv.Atoi(part); err == nil && p > 0 && p <= 65535 {
			merged[p] = true
		}
	}
	out := make([]int, 0, len(merged))
	for p := range merged {
		out = append(out, p)
	}
	slices.Sort(out)
	return out
}

// Scan 对每个 IP 的端口集做 connect 扫描，返回开放端口。ctx 取消时立即返回已得结果。
func Scan(ctx context.Context, ips []string, opts Options) []Result {
	if len(ips) == 0 || len(opts.Ports) == 0 {
		return nil
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 256
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 2 * time.Second
	}
	if opts.RatePerSec <= 0 {
		opts.RatePerSec = 500
	}

	limiter := newTokenBucket(opts.RatePerSec)
	defer limiter.stop() // 停掉补令牌 goroutine,否则每次 Scan 泄漏一个常驻 ticker
	jobs := make(chan job)
	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		results []Result
	)
	worker := func() {
		defer wg.Done()
		for j := range jobs {
			if !limiter.take(ctx) {
				return
			}
			addr := net.JoinHostPort(j.ip, strconv.Itoa(j.port))
			d := net.Dialer{Timeout: opts.Timeout}
			conn, err := d.DialContext(ctx, "tcp", addr)
			if err != nil {
				continue
			}
			_ = conn.Close()
			mu.Lock()
			results = append(results, Result{IP: j.ip, Port: j.port, Service: GuessService(j.port)})
			mu.Unlock()
		}
	}
	for i := 0; i < opts.Concurrency; i++ {
		wg.Add(1)
		go worker()
	}
	go func() {
		defer close(jobs)
		for _, ip := range ips {
			for _, port := range opts.Ports {
				select {
				case jobs <- job{ip: ip, port: port}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	wg.Wait()
	return results
}

type job struct {
	ip   string
	port int
}

// tokenBucket 简单令牌桶：按固定速率补充令牌，阻塞直到有令牌或 ctx 结束。
type tokenBucket struct {
	tokens  chan struct{}
	stopCh  chan struct{}
	stopped sync.Once
}

func newTokenBucket(rate int) *tokenBucket {
	t := &tokenBucket{tokens: make(chan struct{}, rate), stopCh: make(chan struct{})}
	go func() {
		interval := time.Second / time.Duration(rate)
		if interval < time.Millisecond {
			interval = time.Millisecond
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-t.stopCh:
				return
			case <-ticker.C:
				select {
				case t.tokens <- struct{}{}:
				default:
				}
			}
		}
	}()
	return t
}

// stop 停止补令牌 goroutine（Scan 结束必须调用，否则泄漏常驻 ticker）。
func (b *tokenBucket) stop() {
	b.stopped.Do(func() { close(b.stopCh) })
}

func (b *tokenBucket) take(ctx context.Context) bool {
	select {
	case <-b.tokens:
		return true
	case <-ctx.Done():
		return false
	}
}

// GuessService 按端口号猜服务名（展示用途，非协议识别）。
func GuessService(port int) string {
	if name, ok := wellKnown[port]; ok {
		return name
	}
	switch {
	case port == 80 || port == 8080 || port == 8000 || port == 8888:
		return "http"
	case port == 443 || port == 8443:
		return "https"
	}
	return ""
}

var wellKnown = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3",
	111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap", 161: "snmp", 389: "ldap",
	443: "https", 445: "smb", 465: "smtps", 514: "syslog", 587: "smtp", 623: "ipmi",
	636: "ldaps", 1433: "mssql", 1521: "oracle", 2049: "nfs", 2375: "docker", 2376: "docker-tls",
	3128: "squid", 3306: "mysql", 3389: "rdp", 5432: "postgresql", 5555: "adb", 5601: "kibana",
	5672: "amqp", 5900: "vnc", 5985: "winrm", 5986: "winrm-tls", 6379: "redis", 6380: "redis-tls",
	6443: "k8s-api", 683: "giop", 684: "giop", 7000: "frp", 7001: "weblogic", 8009: "ajp",
	10250: "kubelet", 10255: "kubelet-ro", 1080: "socks5", 1099: "rmi",
	8080: "http-alt", 8443: "https-alt", 8500: "consul", 873: "rsync", 8848: "nacos",
	8983: "solr", 9000: "http-alt", 9090: "http-alt", 9092: "kafka", 9200: "elasticsearch",
	9300: "elasticsearch", 11211: "memcached", 2181: "zookeeper", 27017: "mongodb",
	50070: "hadoop",
}

// ── 小工具 ──

func splitAndTrim(s string, sep byte) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == sep {
			part := trimSpace(s[start:i])
			if part != "" {
				out = append(out, part)
			}
			start = i + 1
		}
	}
	return out
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

func indexOfByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// String 调试输出。
func (r Result) String() string {
	if r.Service == "" {
		return fmt.Sprintf("%s:%d", r.IP, r.Port)
	}
	return fmt.Sprintf("%s:%d(%s)", r.IP, r.Port, r.Service)
}
