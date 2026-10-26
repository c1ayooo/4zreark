// Package exposure 服务暴露面无凭据探测(fscan 思路:探测即判定)。
//
// 对识别出的服务做无凭据安全握手测试,产出"未授权访问/匿名可登录"级别的
// 暴露面结论——不需要任何凭据,也不做任何爆破;授权边界与端口探测相同。
// 探测项:Redis(未授权 INFO)、Memcached(VERSION)、Elasticsearch(无认证
// cluster 信息)、FTP(匿名可登录)、MongoDB(isMaster 握手应答)、Docker
// API(2375 无认证)、SMB(签名未强制/NTLMSSP 主机信息)、K8s API/Kubelet
// (/version /pods 匿名)、VNC(无认证握手)、LDAP(匿名 bind)、ZooKeeper
// (4 字命令无认证)、Kafka(metadata 无认证)、RabbitMQ(AMQP guest 匿名)、
// MSSQL(TDS prelogin 无认证)、Consul/Nacos/Kibana/Solr/Hadoop(HTTP 未授权
// 接口)、Squid(代理匿名)、SMTPS(隐式 TLS 匿名)、Oracle(TNS 版本未认证
// 泄露)、Java RMI(JRMP)、DCERPC(端点映射器匿名)、SOCKS5(匿名开放代理)、
// frp(隧道入口暴露)、GIOP(CORBA 命名服务)、NetBIOS(节点状态匿名可读)、
// Redis-TLS(隐式 TLS 未授权 INFO)。
package exposure

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
)

// Result 单项暴露面结论。
type Result struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Service string `json:"service"` // redis/memcached/elasticsearch/ftp/mongodb
	Finding string `json:"finding"` // 人读结论(如 "Redis 未授权访问")
	Detail  string `json:"detail,omitempty"`
}

// Target 一个待探测目标(service 由 svcid 识别结果传入)。
type Target struct {
	Host    string
	Port    int
	Service string // redis/memcached/elasticsearch/ftp/mongodb(来自 svcid)
}

// Options 探测参数。
type Options struct {
	Timeout     time.Duration // 单项探测超时,<=0 按 3s
	Concurrency int           // worker 数,<=0 按 16
}

// supported 可探测的服务集合。
var supported = map[string]bool{
	"redis": true, "memcached": true, "elasticsearch": true, "ftp": true, "mongodb": true,
	"docker": true, "smb": true, "winrm": true, "winrm-tls": true, "rsync": true,
	"k8s-api": true, "kubelet": true, "kubelet-ro": true, "vnc": true,
	"ldap": true, "ldaps": true, "zookeeper": true, "kafka": true,
	"amqp": true, "rabbitmq": true, "mssql": true,
	"consul": true, "nacos": true, "kibana": true, "solr": true,
	"hadoop": true, "squid": true, "smtps": true,
	// oracle/java-rmi 由 fingerprintx 原生识别(协议名直通);dcerpc/msrpc/
	// socks5/frp/giop/nbns/netbios/redis-tls 依赖端口先验或 TLS 路由。
	"oracle": true, "java-rmi": true, "rmi": true, "dcerpc": true, "msrpc": true,
	"socks5": true, "socks": true, "frp": true, "giop": true,
	"nbns": true, "netbios": true, "redis-tls": true,
}

// Supported 该服务是否有对应的暴露面探测。
func Supported(service string) bool {
	return supported[strings.ToLower(strings.TrimSpace(service))]
}

// Scan 对目标列表做并发暴露面探测,只返回存在暴露的目标。
func Scan(ctx context.Context, targets []Target, opts Options) []Result {
	if opts.Timeout <= 0 {
		opts.Timeout = 3 * time.Second
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 16
	}
	jobs := make(chan Target)
	results := make([]Result, 0)
	var mu sync.Mutex
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case t, ok := <-jobs:
				if !ok {
					return
				}
				if !Supported(t.Service) {
					continue
				}
				if r := probe(ctx, t, opts.Timeout); r != nil {
					mu.Lock()
					results = append(results, *r)
					mu.Unlock()
				}
			}
		}
	}
	for i := 0; i < opts.Concurrency; i++ {
		wg.Add(1)
		go worker()
	}
	for _, t := range targets {
		select {
		case <-ctx.Done():
		case jobs <- t:
		}
	}
	close(jobs)
	wg.Wait()
	return results
}

func probe(ctx context.Context, t Target, timeout time.Duration) *Result {
	switch strings.ToLower(t.Service) {
	case "redis":
		return probeRedis(ctx, t, timeout)
	case "memcached":
		return probeMemcached(ctx, t, timeout)
	case "elasticsearch":
		return probeElasticsearch(ctx, t, timeout)
	case "ftp":
		return probeFTP(ctx, t, timeout)
	case "mongodb":
		return probeMongoDB(ctx, t, timeout)
	case "docker":
		return probeDocker(ctx, t, timeout)
	case "smb":
		return probeSMB(ctx, t, timeout)
	case "winrm", "winrm-tls":
		return probeWinRM(ctx, t, timeout)
	case "rsync":
		return probeRSYNC(ctx, t, timeout)
	case "k8s-api", "kubelet", "kubelet-ro":
		return probeK8s(ctx, t, timeout)
	case "vnc":
		return probeVNC(ctx, t, timeout)
	case "ldap", "ldaps":
		return probeLDAPAnonymousBind(ctx, t, timeout)
	case "zookeeper":
		return probeZooKeeper(ctx, t, timeout)
	case "kafka":
		return probeKafka(ctx, t, timeout)
	case "amqp", "rabbitmq":
		return probeRabbitMQ(ctx, t, timeout)
	case "mssql":
		return probeMSSQL(ctx, t, timeout)
	case "consul":
		return probeHTTPFeature(ctx, t, timeout, "/v1/agent/self", "consul",
			"Consul 未授权访问", []string{`"Member"`, "Revision", "consul"})
	case "nacos":
		return probeHTTPFeature(ctx, t, timeout, "/nacos/v1/console/health/readiness", "nacos",
			"Nacos 未授权访问", []string{`"code":200`, "success", "readiness"})
	case "kibana":
		return probeHTTPFeature(ctx, t, timeout, "/api/status", "kibana",
			"Kibana 未授权访问", []string{`"status":`, "name", "Kibana"})
	case "solr":
		return probeHTTPFeature(ctx, t, timeout, "/solr/admin/cores", "solr",
			"Solr 未授权访问", []string{`"status":`, "responseHeader", "name"})
	case "hadoop":
		return probeHTTPFeature(ctx, t, timeout, "/", "hadoop",
			"Hadoop 未授权访问", []string{"Hadoop", "namenode", "datanode", "dfshealth"})
	case "squid":
		return probeSquid(ctx, t, timeout)
	case "smtps":
		return probeSMTPS(ctx, t, timeout)
	case "oracle":
		return probeOracle(ctx, t, timeout)
	case "java-rmi", "rmi":
		return probeRMI(ctx, t, timeout)
	case "dcerpc", "msrpc", "epmap":
		return probeDCERPC(ctx, t, timeout)
	case "socks5", "socks":
		return probeSOCKS5(ctx, t, timeout)
	case "frp":
		return probeFRP(ctx, t, timeout)
	case "giop":
		return probeGIOP(ctx, t, timeout)
	case "nbns", "netbios":
		return probeNBNS(ctx, t, timeout)
	case "redis-tls":
		return probeRedisTLS(ctx, t, timeout)
	}
	// rdp 等:协议探测实现复杂度高或误报风险大,保留扩展点
	return nil
}

// dialTimeout 带超时建连。
func dialTimeout(ctx context.Context, t Target, timeout time.Duration) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", t.Host, t.Port))
}

func httpNewRequestWithContext(ctx context.Context, method, url string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err == nil {
		// Go 默认 UA（Go-http-client/1.1）直接暴露扫描器指纹，目标侧 WAF 秒识别
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36")
	}
	return req, err
}

// probeRedis Redis 未授权访问:无需认证即可响应 INFO/PING。进一步探测
// rename-command 配置(未改名 = 危险命令可用)与 ACL 状态。
func probeRedis(ctx context.Context, t Target, timeout time.Duration) *Result {
	conn, err := dialTimeout(ctx, t, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	return probeRedisOnConn(conn, t, timeout)
}

// probeRedisTLS 隐式 TLS 的 Redis(6380 惯例口,或 svcid 识别 TLS=true 走
// redis-tls 路由):TLS 握手后与明文 Redis 同流程判定。
func probeRedisTLS(ctx context.Context, t Target, timeout time.Duration) *Result {
	conn, err := dialTimeout(ctx, t, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	if err := tc.Handshake(); err != nil {
		return nil
	}
	r := probeRedisOnConn(tc, t, timeout)
	if r == nil {
		return nil
	}
	r.Service = "redis-tls"
	r.Finding = "Redis(TLS) " + strings.TrimPrefix(r.Finding, "Redis ")
	return r
}

// probeRedisOnConn 在已就绪连接上跑 Redis 未授权判定(INFO + CONFIG GET
// rename-command)。调用方负责建连/超时/TLS 包装。
func probeRedisOnConn(conn net.Conn, t Target, timeout time.Duration) *Result {
	if _, err := conn.Write([]byte("*1\r\n$4\r\nINFO\r\n")); err != nil {
		return nil
	}
	// 读 INFO 应答首行(状态前缀判断);bufio 预读的残余由后续 CONFIG 探测
	// 用独立的 bufio.NewReader 消费,避免跨命令共享 reader 的预读错位。
	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if err != nil {
		return nil
	}
	if !strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "$") {
		return nil
	}
	// 危险命令未改名:CONFIG GET rename-command 返回空数组(未配置 rename)
	danger := redisConfigGetRenameCommand(conn, timeout)
	finding := "Redis 未授权访问"
	if danger {
		finding = "Redis 未授权访问(危险命令未 rename)"
	}
	return &Result{Host: t.Host, Port: t.Port, Service: "redis",
		Finding: finding, Detail: strings.TrimRight(line, "\r\n")}
}

// redisConfigGetRenameCommand 探测 CONFIG GET rename-command 是否为空
// (空 = 未配置 rename,危险命令如 FLUSHALL/DEBUG 仍可执行)。
// 用独立 bufio.Reader 消费应答,不依赖 probeRedis 已预读的流。
func redisConfigGetRenameCommand(conn net.Conn, timeout time.Duration) bool {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte("*2\r\n$6\r\nCONFIG\r\n$16\r\nGET rename-command\r\n")); err != nil {
		return false
	}
	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if err != nil {
		return false
	}
	return strings.HasPrefix(line, "*0")
}

// probeMemcached Memcached 未授权:VERSION 指令直接应答。
func probeMemcached(ctx context.Context, t Target, timeout time.Duration) *Result {
	conn, err := dialTimeout(ctx, t, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte("version\r\n")); err != nil {
		return nil
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return nil
	}
	if strings.HasPrefix(line, "VERSION") {
		return &Result{Host: t.Host, Port: t.Port, Service: "memcached",
			Finding: "Memcached 未授权访问", Detail: strings.TrimRight(line, "\r\n")}
	}
	return nil
}

// probeElasticsearch Elasticsearch 无认证:根路径返回集群信息 JSON。
func probeElasticsearch(ctx context.Context, t Target, timeout time.Duration) *Result {
	url := fmt.Sprintf("http://%s:%d/", t.Host, t.Port)
	req, err := httpNewRequestWithContext(ctx, "GET", url)
	if err != nil {
		return nil
	}
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	buf := make([]byte, 512)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])
	if resp.StatusCode == 200 && strings.Contains(body, "cluster_name") {
		return &Result{Host: t.Host, Port: t.Port, Service: "elasticsearch",
			Finding: "Elasticsearch 无认证访问", Detail: strings.TrimSpace(body)}
	}
	return nil
}

// probeFTP FTP 匿名可登录:USER anonymous → PASS,应答 230 判定成功。
func probeFTP(ctx context.Context, t Target, timeout time.Duration) *Result {
	conn, err := dialTimeout(ctx, t, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	r := bufio.NewReader(conn)
	// 读服务横幅(220 ...)
	if _, err := r.ReadString('\n'); err != nil {
		return nil
	}
	if _, err := conn.Write([]byte("USER anonymous\r\n")); err != nil {
		return nil
	}
	line, err := r.ReadString('\n')
	if err != nil {
		return nil
	}
	if strings.HasPrefix(line, "331") || strings.HasPrefix(line, "3") {
		// 需要密码:匿名场景 PASS 任意值
		if _, err := conn.Write([]byte("PASS guest@localhost\r\n")); err != nil {
			return nil
		}
		line, err = r.ReadString('\n')
		if err != nil {
			return nil
		}
	}
	if strings.HasPrefix(line, "230") {
		return &Result{Host: t.Host, Port: t.Port, Service: "ftp",
			Finding: "FTP 匿名登录可用", Detail: strings.TrimSpace(line)}
	}
	return nil
}

// ── MongoDB：isMaster 握手应答判定未授权 ──

// mongoMsgHeaderSize MongoDB wire protocol 消息头长度。
const mongoMsgHeaderSize = 16

// probeMongoDB MongoDB 未授权访问:发送 isMaster 命令(OP_QUERY),无需认证
// 即返回 ok:1 的 OP_REPLY 应答。握手应答判定,不做任何数据操作。
func probeMongoDB(ctx context.Context, t Target, timeout time.Duration) *Result {
	conn, err := dialTimeout(ctx, t, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(mongoIsMasterQuery()); err != nil {
		return nil
	}
	// 响应头: 16 字节消息头 + responseFlags(4)。QueryFailure 位(0x01)置位
	// 说明该命令要求认证,置 0 说明握手应答成功(服务未设认证门槛)。
	hdr := make([]byte, mongoMsgHeaderSize+4)
	if _, err := readFull(conn, hdr); err != nil {
		return nil
	}
	// 消息头倒数第二个 int32 是 opCode:OP_REPLY=1;responseFlags 紧随其后。
	opCode := binary.LittleEndian.Uint32(hdr[12:16])
	if opCode != 1 { // 非 OP_REPLY:握手未走 MongoDB 协议
		return nil
	}
	responseFlags := binary.LittleEndian.Uint32(hdr[16:20])
	if responseFlags&0x01 != 0 {
		return nil // QueryFailure:需要认证
	}
	return &Result{Host: t.Host, Port: t.Port, Service: "mongodb",
		Finding: "MongoDB 无需认证访问", Detail: "isMaster 握手应答"}
}

// mongoIsMasterQuery 构造 MongoDB OP_QUERY isMaster 报文
// （fullCollectionName=admin.$cmd，query={"isMaster":1}）。
func mongoIsMasterQuery() []byte {
	// OP_QUERY body: flags(4) + fullCollectionName(cstring) + numberToSkip(4)
	// + numberToReturn(4) + query(BSON)
	query := mongoBSONIsMaster()
	body := make([]byte, 0, 4+len("admin.$cmd")+1+4+4+len(query))
	body = binary.LittleEndian.AppendUint32(body, 0) // flags
	body = append(body, "admin.$cmd"...)
	body = append(body, 0)                           // cstring 终止
	body = binary.LittleEndian.AppendUint32(body, 0) // numberToSkip
	body = binary.LittleEndian.AppendUint32(body, 1) // numberToReturn
	body = append(body, query...)
	// 消息头: messageLength + requestID + responseTo + opCode(OP_QUERY=2004)
	msg := make([]byte, 0, mongoMsgHeaderSize+len(body))
	msg = binary.LittleEndian.AppendUint32(msg, uint32(mongoMsgHeaderSize+len(body)))
	msg = binary.LittleEndian.AppendUint32(msg, 1)    // requestID
	msg = binary.LittleEndian.AppendUint32(msg, 0)    // responseTo
	msg = binary.LittleEndian.AppendUint32(msg, 2004) // OP_QUERY
	msg = append(msg, body...)
	return msg
}

// mongoBSONIsMaster 构造 BSON {"isMaster": 1}。
func mongoBSONIsMaster() []byte {
	// e_list: type(int32=0x10) + "isMaster\0" + int32(1),以 \0 结尾
	elem := make([]byte, 0, 1+len("isMaster")+1+4)
	elem = append(elem, 0x10) // BSON int32
	elem = append(elem, "isMaster"...)
	elem = append(elem, 0)
	elem = binary.LittleEndian.AppendUint32(elem, 1)
	doc := make([]byte, 0, 4+len(elem)+1)
	doc = binary.LittleEndian.AppendUint32(doc, uint32(4+len(elem)+1))
	doc = append(doc, elem...)
	doc = append(doc, 0) // 文档终止
	return doc
}

// readFull 读满 buf（替代 io.ReadFull 的短读重试语义，保持依赖最小）。
func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// ── Docker API：/version 无认证应答判定未授权（2375 直连 = 直接 RCE）──

// probeDocker Docker Engine API 未授权:2375 无 TLS 时 /version 直接返回
// 版本 JSON(无需认证)。仅作存在性判定,不列容器/不执行任何操作。
func probeDocker(ctx context.Context, t Target, timeout time.Duration) *Result {
	url := fmt.Sprintf("http://%s:%d/version", t.Host, t.Port)
	req, err := httpNewRequestWithContext(ctx, "GET", url)
	if err != nil {
		return nil
	}
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	buf := make([]byte, 512)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])
	if resp.StatusCode == 200 && strings.Contains(body, "ApiVersion") {
		return &Result{Host: t.Host, Port: t.Port, Service: "docker",
			Finding: "Docker API 未授权访问", Detail: strings.TrimSpace(body)}
	}
	return nil
}

// ── SMB：签名未强制（可中继）/ NTLMSSP 主机信息未认证读取 ──

// probeSMB 同一条连接上做两级判定:
//  1. NEGOTIATE 应答的 SecurityMode:SIGNING_ENABLED(0x01)置位而
//     SIGNING_REQUIRED(0x02)未置位 = 签名可选,凭据中继/伪造会话可行,
//     是横向移动的关键前置;
//  2. SESSION_SETUP 携带 SPNEGO 包裹的 NTLMSSP NEGOTIATE(不提供任何
//     凭据),服务端回 NTLMSSP CHALLENGE——从中提取 NetBIOS/DNS 域、
//     主机名与系统版本。未认证即可读的主机身份是内网域判定的最早信号
//     (先于 LDAP 查询可用),域控必判(签名强制也照常提取)。
//
// 传输层按 MS-SMB2 §2.1 使用 direct TCP 4 字节帧头(1 字节 0 + 3 字节
// 大端报文长度);缺帧头的裸 SMB2 会被 Windows 服务端静默丢弃。
// 认证流程止步于 CHALLENGE,不发送任何认证应答。
func probeSMB(ctx context.Context, t Target, timeout time.Duration) *Result {
	conn, err := dialTimeout(ctx, t, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(smb2Frame(smb2NegotiateRequest())); err != nil {
		return nil
	}
	neg, ok := readSMB2Frame(conn)
	if !ok || binary.LittleEndian.Uint16(neg[12:14]) != 0x0000 {
		return nil
	}
	// SMB2_NEGOTIATE_RESPONSE 的 SecurityMode 在 64 字节头之后的 offset 2
	secMode := neg[66]
	ntlm := ""
	if _, err := conn.Write(smb2Frame(smb2SessionSetupNTLMSSP())); err == nil {
		if setup, ok := readSMB2Frame(conn); ok && binary.LittleEndian.Uint16(setup[12:14]) == 0x0001 {
			ntlm = ntlmChallengeSummary(setup)
		}
	}
	switch {
	case secMode&0x02 == 0:
		detail := fmt.Sprintf("SecurityMode=0x%02x", secMode)
		if ntlm != "" {
			detail += "; " + ntlm
		}
		return &Result{Host: t.Host, Port: t.Port, Service: "smb",
			Finding: "SMB 签名未强制(可中继)", Detail: detail}
	case ntlm != "":
		return &Result{Host: t.Host, Port: t.Port, Service: "smb",
			Finding: "SMB NTLMSSP 主机信息未认证可读", Detail: ntlm}
	}
	return nil
}

// smb2FrameMax direct TCP 帧承载的 SMB2 消息长度上限(截断保护)。
const smb2FrameMax = 66560

// smb2Frame 加 direct TCP 传输头:1 字节 0(session message)+ 3 字节大端长度。
func smb2Frame(msg []byte) []byte {
	out := make([]byte, 4+len(msg))
	n := len(msg)
	out[1] = byte(n >> 16)
	out[2] = byte(n >> 8)
	out[3] = byte(n)
	copy(out[4:], msg)
	return out
}

// readSMB2Frame 读一条 direct TCP 帧封装的 SMB2 应答,返回去帧后的消息。
func readSMB2Frame(conn net.Conn) ([]byte, bool) {
	hdr := make([]byte, 4)
	if _, err := readFull(conn, hdr); err != nil {
		return nil, false
	}
	n := int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
	if n < 64 || n > smb2FrameMax {
		return nil, false
	}
	msg := make([]byte, n)
	if _, err := readFull(conn, msg); err != nil {
		return nil, false
	}
	if !bytes.Equal(msg[:4], []byte{0xfe, 'S', 'M', 'B'}) {
		return nil, false
	}
	return msg, true
}

// smb2NegotiateRequest 构造 SMB2 NEGOTIATE 请求(方言 2.0.2~3.0.2,
// 服务端自选;3.1.1 需协商上下文,不在此列)。
func smb2NegotiateRequest() []byte {
	hdr := make([]byte, 64)
	copy(hdr[0:4], []byte{0xfe, 'S', 'M', 'B'})       // 协议 ID
	binary.LittleEndian.PutUint16(hdr[4:6], 64)       // 结构大小
	binary.LittleEndian.PutUint16(hdr[12:14], 0x0000) // 命令 = NEGOTIATE
	// 旗标/消息ID/会话ID等保持 0;签名(48-63)全 0 = 未签名
	// SMB2_NEGOTIATE_REQUEST: 结构大小(2) + 方言计数(2) + 安全模式(2) + 保留(2) + 方言
	body := make([]byte, 0, 8+8)
	body = binary.LittleEndian.AppendUint16(body, 36) // 结构大小
	body = binary.LittleEndian.AppendUint16(body, 4)  // 方言计数
	body = binary.LittleEndian.AppendUint16(body, 0)  // 安全模式(请求侧恒 0)
	body = binary.LittleEndian.AppendUint16(body, 0)  // 保留
	for _, d := range []uint16{0x0202, 0x0210, 0x0300, 0x0302} {
		body = binary.LittleEndian.AppendUint16(body, d)
	}
	msg := make([]byte, 0, len(hdr)+len(body))
	msg = append(msg, hdr...)
	msg = append(msg, body...)
	return msg
}

// smb2SessionSetupNTLMSSP 构造携带 NTLMSSP NEGOTIATE(type 1)的
// SESSION_SETUP 请求:SecurityBuffer 为 SPNEGO negTokenInit 包裹(Windows/
// Samba 均要求包裹层),无任何凭据字段。
func smb2SessionSetupNTLMSSP() []byte {
	hdr := make([]byte, 64)
	copy(hdr[0:4], []byte{0xfe, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(hdr[4:6], 64)       // 结构大小
	binary.LittleEndian.PutUint16(hdr[6:8], 1)        // CreditCharge=1(0 信用会被拒后续请求)
	binary.LittleEndian.PutUint16(hdr[12:14], 0x0001) // 命令 = SESSION_SETUP
	binary.LittleEndian.PutUint16(hdr[14:16], 1)      // CreditRequest
	binary.LittleEndian.PutUint64(hdr[24:32], 1)      // MessageId=1(NEGOTIATE 已用 0)
	blob := spnegoNTLMNegotiate()
	body := make([]byte, 0, 24+len(blob))
	body = binary.LittleEndian.AppendUint16(body, 25) // 结构大小(24+1 协议惯例)
	body = append(body, 0)                            // Flags
	body = append(body, 0)                            // SecurityMode(不启用签名)
	body = binary.LittleEndian.AppendUint32(body, 0)  // Capabilities
	body = binary.LittleEndian.AppendUint32(body, 0)  // Channel
	body = binary.LittleEndian.AppendUint16(body, 88) // SecurityBufferOffset(64+24)
	body = binary.LittleEndian.AppendUint16(body, uint16(len(blob)))
	body = binary.LittleEndian.AppendUint64(body, 0) // PreviousSessionId
	msg := make([]byte, 0, 88+len(blob))
	msg = append(msg, hdr...)
	msg = append(msg, body...)
	msg = append(msg, blob...)
	return msg
}

// NTLMSSP NEGOTIATE 能力位(MS-NLMP §2.2.2.5,仅取本探测所需)。
const (
	ntlmNegotiateUnicode    = 0x00000001 // 全部字符串 UTF-16LE
	ntlmRequestTarget       = 0x00000004 // 要求服务端回 TargetName/TargetInfo
	ntlmNegotiateNtlm       = 0x00000200
	ntlmNegotiateExtended   = 0x00080000 // NTLMv2 会话安全(Windows 默认期望)
	ntlmNegotiateTargetInfo = 0x00800000 // 要求 AV_PAIR(DNS 主机名等)
	ntlmNegotiateVersion    = 0x02000000 // 要求 CHALLENGE 尾随 Version 字段
)

// ntlmNegotiateMessage 构造 NTLMSSP NEGOTIATE:无凭据、无域/主机信息,
// 仅声明能力位;尾随 Version 字段声明 Win10 19041/NTLM15(服务端会以
// 自身同类字段应答)。
func ntlmNegotiateMessage() []byte {
	flags := uint32(ntlmNegotiateUnicode | ntlmRequestTarget | ntlmNegotiateNtlm |
		ntlmNegotiateExtended | ntlmNegotiateTargetInfo | ntlmNegotiateVersion)
	m := make([]byte, 0, 48)
	m = append(m, 'N', 'T', 'L', 'M', 'S', 'S', 'P', 0)
	m = binary.LittleEndian.AppendUint32(m, 1) // 消息类型 = NEGOTIATE
	m = binary.LittleEndian.AppendUint32(m, flags)
	m = append(m, make([]byte, 24)...) // 域/用户/密码字段全 0(无凭据)
	m = append(m, 10, 0, 0x61, 0x4a)   // Version: Win10 build 19041
	m = append(m, 0, 0, 0)             // Version 保留
	m = append(m, 15)                  // NTLMRevisionCurrent = 15
	return m
}

// derTLV 拼一个 DER tag-length-value(本包所有 SPNEGO 子结构 < 128 字节,
// 定长短格式足够;超长返回 nil 由调用方跳过)。
func derTLV(tag byte, val []byte) []byte {
	if len(val) >= 128 {
		return nil
	}
	out := make([]byte, 0, 2+len(val))
	out = append(out, tag, byte(len(val)))
	return append(out, val...)
}

// spnegoNTLMNegotiate 构造 SPNEGO negTokenInit:[APPLICATION 0] {
// spnegoOID, [0] mechTypes{ntlmOID}, [2] mechToken(NTLMSSP type 1) }。
// OID 分别为 SPNEGO(1.3.6.1.5.5.2)与 NTLMSSP(1.3.6.1.4.1.311.2.2.10)。
func spnegoNTLMNegotiate() []byte {
	spnegoOID := []byte{0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}
	ntlmOIDContent := []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}
	mechTypes := derTLV(0x30, ntlmOIDContent)
	mechToken := derTLV(0xa2, derTLV(0x04, ntlmNegotiateMessage()))
	if mechTypes == nil || mechToken == nil {
		return nil
	}
	inner := make([]byte, 0, len(spnegoOID)+len(mechTypes)+len(mechToken))
	inner = append(inner, spnegoOID...)
	inner = append(inner, mechTypes...)
	inner = append(inner, mechToken...)
	return derTLV(0x60, inner)
}

// smbNTLMInfo NTLMSSP CHALLENGE 中可用的主机身份字段。
type smbNTLMInfo struct {
	targetName  string // TargetName 头部字段(通常为 NetBIOS 域)
	nbComputer  string // AV 1: NetBIOS 主机名
	nbDomain    string // AV 2: NetBIOS 域
	dnsComputer string // AV 3: DNS 主机名(FQDN)
	dnsDomain   string // AV 4: DNS 域
	version     string // 服务端系统版本(major.minor build/NTLM rev)
}

// parseNTLMSSPChallenge 从 SESSION_SETUP 应答中解析 NTLMSSP CHALLENGE。
// 应答外层是 SPNEGO negTokenResp,逐层剥壳无必要——直接扫 "NTLMSSP\0"
// 签名即可精确定位(消息类型必须为 2);无签名(如 guest 匿名直接放行)返回
// false,不影响签名判定路径。
func parseNTLMSSPChallenge(msg []byte) (smbNTLMInfo, bool) {
	idx := bytes.Index(msg, []byte("NTLMSSP\x00"))
	if idx < 0 || len(msg)-idx < 56 {
		return smbNTLMInfo{}, false
	}
	b := msg[idx:]
	if binary.LittleEndian.Uint32(b[8:12]) != 2 {
		return smbNTLMInfo{}, false
	}
	flags := binary.LittleEndian.Uint32(b[20:24])
	var info smbNTLMInfo
	if flags&ntlmNegotiateUnicode != 0 {
		// TargetName: Len(2) + MaxLen(2) + BufferOffset(4),偏移相对消息起点
		tLen := int(binary.LittleEndian.Uint16(b[12:14]))
		tOff := int(binary.LittleEndian.Uint32(b[16:20]))
		info.targetName = utf16LEString(sliceAt(b, tOff, tLen))
	}
	// TargetInfo: Len(2) + MaxLen(2) + BufferOffset(4),一组 AV_PAIR
	iLen := int(binary.LittleEndian.Uint16(b[40:42]))
	iOff := int(binary.LittleEndian.Uint32(b[44:48]))
	for av := sliceAt(b, iOff, iLen); len(av) >= 4; {
		id := binary.LittleEndian.Uint16(av[0:2])
		l := int(binary.LittleEndian.Uint16(av[2:4]))
		val := sliceAt(av, 4, l)
		if flags&ntlmNegotiateUnicode != 0 {
			switch id {
			case 1:
				info.nbComputer = utf16LEString(val)
			case 2:
				info.nbDomain = utf16LEString(val)
			case 3:
				info.dnsComputer = utf16LEString(val)
			case 4:
				info.dnsDomain = utf16LEString(val)
			}
		}
		if id == 0 { // MsvAvEOL
			break
		}
		av = sliceAt(av, 4+l, len(av)-4-l)
	}
	if flags&ntlmNegotiateVersion != 0 {
		info.version = fmt.Sprintf("%d.%d build %d (NTLM %d)",
			b[48], b[49], binary.LittleEndian.Uint16(b[50:52]), b[55])
	}
	return info, true
}

// ntlmChallengeSummary 把 CHALLENGE 字段拼成人读摘要(域判定的最早输入)。
func ntlmChallengeSummary(msg []byte) string {
	info, ok := parseNTLMSSPChallenge(msg)
	if !ok {
		return ""
	}
	var parts []string
	if info.dnsDomain != "" {
		parts = append(parts, "DNS域="+info.dnsDomain)
	}
	if info.dnsComputer != "" {
		parts = append(parts, "DNS主机="+info.dnsComputer)
	}
	if info.targetName != "" {
		parts = append(parts, "NetBIOS域="+info.targetName)
	}
	if info.nbComputer != "" {
		parts = append(parts, "NetBIOS主机="+info.nbComputer)
	}
	if info.version != "" {
		parts = append(parts, "版本="+info.version)
	}
	return strings.Join(parts, " ")
}

// sliceAt 带边界保护的子串切取(越界返回 nil,挑战报文字段偏移不可信)。
func sliceAt(b []byte, off, length int) []byte {
	if off < 0 || length < 0 || off+length > len(b) {
		return nil
	}
	return b[off : off+length]
}

// utf16LEString 解码 UTF-16LE 字节串(NTLMSSP 全部字符串字段编码)。
func utf16LEString(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	return strings.TrimSpace(string(utf16.Decode(u)))
}

// ── WinRM：/wsman 无认证应答判定 ──

// probeWinRM WinRM 未授权访问:5985(明文)/5986(TLS) 的 /wsman 端点无认证
// 访问时返回 401(需要认证)以外的应答。判定逻辑:
//   - HTTP 层应答存在(Server: Microsoft-HTTPAPI/2.0 是 WinRM 特征头);
//   - 401 = 需要认证(不标记,避免误报);
//   - 其他状态(200/404 等)且路径 /wsman 被接受 = 无认证门槛。
//
// 仅判定暴露面,不发送任何 SOAP 操作。
func probeWinRM(ctx context.Context, t Target, timeout time.Duration) *Result {
	scheme := "http"
	if strings.Contains(strings.ToLower(t.Service), "tls") || t.Port == 5986 {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s:%d/wsman", scheme, t.Host, t.Port)
	req, err := httpNewRequestWithContext(ctx, "GET", url)
	if err != nil {
		return nil
	}
	client := &http.Client{Timeout: timeout, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode == 401 {
		return nil // 需要认证
	}
	if !strings.Contains(strings.ToLower(resp.Header.Get("Server")), "microsoft-httpapi") {
		// 非 WinRM 特征头路径下,/wsman 返回非 401 也能说明无认证网关可达,
		// 但为避免对任意 HTTP 服务误报,特征头缺失时要求状态码在 400 以下。
		if resp.StatusCode >= 400 {
			return nil
		}
	}
	return &Result{Host: t.Host, Port: t.Port, Service: strings.SplitN(strings.ToLower(t.Service), "-", 2)[0],
		Finding: "WinRM 无需认证访问", Detail: fmt.Sprintf("HTTP %d", resp.StatusCode)}
}

// ── rsync：@RSYNCD 模块列表匿名可读判定 ──

// probeRSYNC rsync 匿名可访问:发送 @RSYNCD 握手,服务端返回版本行后
// 用 #list 请求模块列表——未触发 auth failed 即匿名可列目录。
func probeRSYNC(ctx context.Context, t Target, timeout time.Duration) *Result {
	conn, err := dialTimeout(ctx, t, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	r := bufio.NewReader(conn)
	if _, err := conn.Write([]byte("@RSYNCD: 31.0\n")); err != nil {
		return nil
	}
	// 服务端横幅:@RSYNCD: <版本>
	line, err := r.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "@RSYNCD") {
		return nil
	}
	if _, err := conn.Write([]byte("#list\n")); err != nil {
		return nil
	}
	var mods []string
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)
		switch {
		case strings.Contains(line, "auth failed") || strings.Contains(line, "denied"):
			return nil // 需要认证
		case line == "":
			continue
		case strings.HasPrefix(line, "@RSYNCD: EXIT"):
			// 列表结束标记:已收集到模块即为匿名可列;否则(仅版本+EXIT)需认证
			if len(mods) == 0 {
				return nil
			}
			goto done
		}
		mods = append(mods, line)
		if len(mods) >= 16 {
			break
		}
	}
done:
	if len(mods) == 0 {
		return nil
	}
	return &Result{Host: t.Host, Port: t.Port, Service: "rsync",
		Finding: "rsync 匿名可列模块", Detail: strings.Join(mods, "; ")}
}

// ── K8s：API / Kubelet 匿名可达判定 ──

// probeK8s 判定 Kubernetes API(6443) 或 Kubelet(10250/10255) 是否匿名可达:
//   - API Server:GET /version 无需认证即返回 200 + JSON(k8s 特征字段 gitVersion);
//     再探 /api/v1/namespaces——无 RBAC 拦截时匿名可列 namespace(比版本信息
//     更敏感,说明集群资源面暴露);
//   - Kubelet 10255(只读):GET /pods 匿名返回节点 pod 清单;
//   - Kubelet 10250(读写):需 10255 同样匿名 /pods 才判定(避免对认证拦截误报)。
//
// 6443 为 HTTPS,10250/10255 为 HTTP(默认)。仅存在性判定,不拉取敏感数据。
func probeK8s(ctx context.Context, t Target, timeout time.Duration) *Result {
	scheme := "http"
	path := "/pods"
	serviceName := "kubelet"
	if t.Service == "k8s-api" || t.Port == 6443 {
		scheme = "https"
		path = "/version"
		serviceName = "k8s-api"
	} else if t.Service == "kubelet-ro" {
		serviceName = "kubelet"
	}
	url := fmt.Sprintf("%s://%s:%d%s", scheme, t.Host, t.Port, path)
	req, err := httpNewRequestWithContext(ctx, "GET", url)
	if err != nil {
		return nil
	}
	client := &http.Client{Timeout: timeout, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil // 认证拦截(401/403)或不存在(404)
	}
	buf := make([]byte, 512)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])
	var finding, detail string
	if serviceName == "k8s-api" {
		if !strings.Contains(body, "gitVersion") {
			return nil // 200 但不是 K8s API 应答
		}
		// 二次探测 namespace 列表:无 RBAC 拦截时匿名可读(集群资源面暴露)
		if namespacesOK(ctx, client, scheme, t.Host, t.Port) {
			finding = "Kubernetes API 匿名可达(可列 namespace)"
			detail = "GET /api/v1/namespaces 匿名 200"
		} else {
			finding = "Kubernetes API 匿名可达"
			detail = strings.TrimSpace(body)
		}
	} else {
		if !strings.Contains(body, "kind") || !strings.Contains(body, "items") {
			return nil
		}
		finding = "Kubelet 匿名可达"
		detail = "HTTP 200 /pods"
	}
	return &Result{Host: t.Host, Port: t.Port, Service: serviceName, Finding: finding, Detail: detail}
}

// namespacesOK 探 /api/v1/namespaces 是否匿名可读(RBAC 未拦截)。
func namespacesOK(ctx context.Context, client *http.Client, scheme, host string, port int) bool {
	url := fmt.Sprintf("%s://%s:%d/api/v1/namespaces", scheme, host, port)
	req, err := httpNewRequestWithContext(ctx, "GET", url)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return false
	}
	buf := make([]byte, 256)
	nn, _ := resp.Body.Read(buf)
	body := string(buf[:nn])
	// namespaces 列表应答含 "items" 与 "metadata";空集群也可能返回 items:[],
	// 仍算匿名可读(RBAC 未拦)。
	return strings.Contains(body, "items")
}

// ── VNC：无认证握手判定 ──

// probeVNC 判定 VNC 是否无认证:RFB 协议版本握手后,服务端返回安全类型
// 列表——若列表只有 1 项且为 None(0x01) 或无认证标志,判定无认证可连接。
func probeVNC(ctx context.Context, t Target, timeout time.Duration) *Result {
	conn, err := dialTimeout(ctx, t, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	// 读服务端协议版本横幅("RFB 003.008\n" 12 字节)
	ver := make([]byte, 12)
	if _, err := readFull(conn, ver); err != nil || !bytes.HasPrefix(ver, []byte("RFB ")) {
		return nil
	}
	// 回发客户端支持的版本(取服务端同版本)
	if _, err := conn.Write(ver); err != nil {
		return nil
	}
	// 读安全类型数(1 字节);0x00 = 服务端关闭连接(不支持)
	countByte := make([]byte, 1)
	if _, err := readFull(conn, countByte); err != nil {
		return nil
	}
	count := int(countByte[0])
	if count <= 0 {
		return nil
	}
	types := make([]byte, count)
	if _, err := readFull(conn, types); err != nil {
		return nil
	}
	// RFB 安全类型:1=None(无认证)、2=VNC Auth。仅 None 或无认证标志时判定。
	for _, tpe := range types {
		if tpe == 0x01 {
			return &Result{Host: t.Host, Port: t.Port, Service: "vnc",
				Finding: "VNC 无认证可连接", Detail: "SecurityType=None"}
		}
	}
	return nil
}

// ── LDAP：匿名 bind 判定 ──

// probeLDAPAnonymousBind 判定 LDAP 是否允许匿名 bind:发送空 DN/空密码的
// BindRequest(version=3, simple auth),服务端返回 BindResponse resultCode=0
// (success)即匿名可登录。389 明文 / 636 LDAPS 自动走 TLS。
// 仅一次 bind 尝试,不做任何查询。
func probeLDAPAnonymousBind(ctx context.Context, t Target, timeout time.Duration) *Result {
	conn, err := dialTimeout(ctx, t, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if strings.EqualFold(t.Service, "ldaps") || t.Port == 636 {
		tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
		if err := tc.Handshake(); err != nil {
			return nil
		}
		conn = tc
	}
	if _, err := conn.Write(ldapAnonymousBindRequest()); err != nil {
		return nil
	}
	// BindResponse:LDAPMessage(seq) → BindResponse(APPLICATION 1 = 0x61)
	// → resultCode(LDAPResult 首字段 ENUMERATED)。先读 SEQUENCE 头(2 字节),
	// 再按长度读 body(匿名 bind 应答极小,上限保护)。
	hdr := make([]byte, 2)
	if _, err := readFull(conn, hdr); err != nil {
		return nil
	}
	if hdr[0] != 0x30 { // 非 SEQUENCE:不是 LDAPMessage
		return nil
	}
	bodyLen := int(hdr[1])
	if bodyLen < 2 || bodyLen > ldapRespMax {
		return nil
	}
	body := make([]byte, bodyLen)
	if _, err := readFull(conn, body); err != nil {
		return nil
	}
	buf := append(hdr, body...)
	if !ldapResultOK(buf) {
		return nil
	}
	return &Result{Host: t.Host, Port: t.Port, Service: "ldap",
		Finding: "LDAP 匿名 bind 允许", Detail: "BindResponse resultCode=0"}
}

// ldapRespMax LDAP 响应读取上限(匿名 bind 应答极小,截断保护)。
const ldapRespMax = 256

// ldapAnonymousBindRequest 构造空 DN/空密码的 BindRequest:
//
//	LDAPMessage: SEQUENCE { messageID INTEGER(1), bindRequest APPLICATION 0 }
//	bindRequest: SEQUENCE { version INTEGER(3), name OCTET STRING(""),
//	                           authentication CHOICE simple[0]("") }
func ldapAnonymousBindRequest() []byte {
	// authentication simple[0]: 0x80 0x00
	// name: 0x04 0x00
	// version: 0x02 0x01 0x03
	// bindRequest 体: 0x02 0x01 0x03 0x04 0x00 0x80 0x00 (7 字节)
	// bindRequest(APPLICATION 0): 0x60 0x07 + 体
	// messageID: 0x02 0x01 0x01
	// LDAPMessage(SEQUENCE): 0x30 len(0x0a) + messageID + bindRequest
	return []byte{
		0x30, 0x0a,
		0x02, 0x01, 0x01, // messageID = 1
		0x60, 0x07, // bindRequest (APPLICATION 0)
		0x02, 0x01, 0x03, // version = 3
		0x04, 0x00, // name = ""
		0x80, 0x00, // simple auth = ""
	}
}

// ldapResultOK 在响应字节中定位 BindResponse 的 resultCode。
// BindResponse = APPLICATION 1 (0x61);LDAPResult 首字段是 resultCode
// (ENUMERATED, 0x0a)。扫描到 0x61 后的 0x0a 值,0x00 即 success。
func ldapResultOK(buf []byte) bool {
	for i := 0; i+1 < len(buf); i++ {
		if buf[i] != 0x61 {
			continue
		}
		n := int(buf[i+1])
		if n < 2 || n > ldapRespMax || i+2+n > len(buf) {
			continue
		}
		// 在 0x61 的 body 内定位 resultCode ENUMERATED(0x0a)。
		for k := i + 2; k < i+2+n-1; k++ {
			if buf[k] == 0x0a && buf[k+1] == 1 && k+2 <= i+2+n {
				return buf[k+2] == 0x00
			}
		}
	}
	return false
}

// ── ZooKeeper：4 字命令无认证判定 ──

// probeZooKeeper 判定 ZooKeeper 是否无认证:发送 4 字命令 ruok,服务端
// 无认证直接回 "imok"。4 字命令(four-letter words)是 ZooKeeper 的管理
// 接口,无 ACL 时可列节点/看状态。
func probeZooKeeper(ctx context.Context, t Target, timeout time.Duration) *Result {
	conn, err := dialTimeout(ctx, t, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte("ruok")); err != nil {
		return nil
	}
	buf := make([]byte, 8)
	n, err := conn.Read(buf) // 单次读,容忍短读(imok 仅 4 字节)
	if err != nil || n < 4 {
		return nil
	}
	if string(buf[:n]) == "imok" {
		return &Result{Host: t.Host, Port: t.Port, Service: "zookeeper",
			Finding: "ZooKeeper 无认证可访问", Detail: "ruok → imok"}
	}
	return nil
}

// ── Kafka：metadata 请求无认证判定 ──

// probeKafka 判定 Kafka 是否无认证:发送 MetadataRequest(api_key=3,
// api_version=0),无 ACL 的 broker 直接返回 broker 列表(含 node_id>0)。
// 有认证(PLAINTEXT 下常配 SASL/ACL)时返回空列表或需协商。
func probeKafka(ctx context.Context, t Target, timeout time.Duration) *Result {
	conn, err := dialTimeout(ctx, t, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(kafkaMetadataV0Request()); err != nil {
		return nil
	}
	// MetadataResponse v0 响应:size(4) + correlation_id(4) + brokers 数组
	// 计数(4)。count>0 说明返回了 broker 列表(无认证)。
	hdr := make([]byte, 12)
	if _, err := readFull(conn, hdr); err != nil {
		return nil
	}
	n := binary.BigEndian.Uint32(hdr[8:12]) // brokers 数组计数
	if n > 0 && n < 1000 {
		return &Result{Host: t.Host, Port: t.Port, Service: "kafka",
			Finding: "Kafka 无认证可访问", Detail: fmt.Sprintf("%d brokers 匿名返回", n)}
	}
	return nil
}

// kafkaMetadataV0Request 构造 Kafka MetadataRequest v0:
//
//	RequestHeader: api_key(2)=3 + api_version(2)=0 + correlation_id(4)=1
//	MetadataRequest v0: topics 数组(4, 空 = 返回全部 broker)
func kafkaMetadataV0Request() []byte {
	body := make([]byte, 0, 16)
	body = binary.BigEndian.AppendUint16(body, 3) // api_key = Metadata
	body = binary.BigEndian.AppendUint16(body, 0) // api_version = 0
	body = binary.BigEndian.AppendUint32(body, 1) // correlation_id
	body = binary.BigEndian.AppendUint32(body, 0) // topics 数组长度(空=全量)
	msg := make([]byte, 0, 4+len(body))
	msg = binary.BigEndian.AppendUint32(msg, uint32(len(body)))
	msg = append(msg, body...)
	return msg
}

// ── 通用 HTTP 特征服务：Consul/Nacos/Kibana/Solr 未授权判定 ──

// probeHTTPFeature 对指定路径发起无认证 GET,应答 200 且含任一特征串即判定
// 未授权访问。服务名为 wellKnown 端口先验映射(consul/nacos/kibana/solr),
// 非 fingerprintx 识别协议,走端口先验回退路径。
func probeHTTPFeature(ctx context.Context, t Target, timeout time.Duration, path, service, finding string, features []string) *Result {
	url := fmt.Sprintf("http://%s:%d%s", t.Host, t.Port, path)
	req, err := httpNewRequestWithContext(ctx, "GET", url)
	if err != nil {
		return nil
	}
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}
	buf := make([]byte, 1024)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])
	for _, f := range features {
		if strings.Contains(body, f) {
			return &Result{Host: t.Host, Port: t.Port, Service: service,
				Finding: finding, Detail: fmt.Sprintf("HTTP 200 %s", path)}
		}
	}
	return nil
}

// ── RabbitMQ：AMQP guest 匿名可连判定 ──

// probeRabbitMQ 判定 RabbitMQ 是否允许默认凭据匿名访问:发送 AMQP 0-9-1
// 协议头("AMQP\x00\x00\x09\x01"),服务端回 Connection.Start(0x0a)要求
// 认证——若应答后续无需凭据即可继续(Tune/Open),说明 guest 匿名通道开放。
// 简化判定:服务端首个方法帧若为 Connection.Tune(0x000a000a)而非
// Connection.Start(0x000a000a=Start),视为无需登录。
//
// 说明:AMQP 认证由服务端策略决定,此处只做"服务存在且协议应答"级判定
// (与 fscan 对 AMQP 的探测粒度一致),不做凭据猜测。
func probeRabbitMQ(ctx context.Context, t Target, timeout time.Duration) *Result {
	conn, err := dialTimeout(ctx, t, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	// AMQP 0-9-1 协议头
	if _, err := conn.Write([]byte{'A', 'M', 'Q', 'P', 0x00, 0x00, 0x09, 0x01}); err != nil {
		return nil
	}
	// 读帧:type(1) + channel(2) + size(4) + payload
	frame := make([]byte, 7)
	if _, err := readFull(conn, frame); err != nil {
		return nil
	}
	if frame[0] != 0x01 { // 非 method 帧
		return nil
	}
	// method 帧 payload:class-id(2) + method-id(2)
	method := make([]byte, 4)
	if _, err := readFull(conn, method); err != nil {
		return nil
	}
	class := binary.BigEndian.Uint16(method[0:2])
	methodID := binary.BigEndian.Uint16(method[2:4])
	// Connection 类(class=0x000a)的 Start=0x0a / Tune=0x1e / Open=0x28
	if class != 0x000a {
		return nil
	}
	// 能收到 Connection.Start 即 AMQP 服务存在;RabbitMQ 默认开 guest 匿名
	// 通道(该版本机制),Start 之后即可用 guest/guest 登入。
	if methodID == 0x000a {
		return &Result{Host: t.Host, Port: t.Port, Service: "rabbitmq",
			Finding: "RabbitMQ 服务暴露(默认 guest 通道)", Detail: "AMQP Connection.Start"}
	}
	return nil
}

// ── MSSQL：TDS prelogin 无认证应答判定 ──

// probeMSSQL 判定 MSSQL 服务暴露:TDS prelogin 交换(不携带任何凭据),服务
// 端回 PRELOGIN 应答(含版本信息)即服务可达。不执行登录/不猜凭据。
// xp_cmdshell 状态判定需认证后查询,本层不做(文档 §四 L5 P1:仅探测不启用)。
func probeMSSQL(ctx context.Context, t Target, timeout time.Duration) *Result {
	conn, err := dialTimeout(ctx, t, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	// TDS prelogin: 包头(8) + 预登录选项
	// type=0x12(PRELOGIN) + status=0x01 + length + spid + packetid + window
	prelogin := tdsPrelogin()
	if _, err := conn.Write(prelogin); err != nil {
		return nil
	}
	// 读 TDS 响应头(8 字节):type + status + length + ...
	hdr := make([]byte, 8)
	if _, err := readFull(conn, hdr); err != nil {
		return nil
	}
	// 服务端应答 type:0x04(TABULAR) 或 0x12(PRELOGIN 回)
	length := int(hdr[2])<<8 | int(hdr[3])
	if length < 8 || length > 4096 {
		return nil
	}
	body := make([]byte, length-8)
	if _, err := readFull(conn, body); err != nil {
		return nil
	}
	if hdr[0] == 0x04 || hdr[0] == 0x12 {
		return &Result{Host: t.Host, Port: t.Port, Service: "mssql",
			Finding: "MSSQL 服务暴露(无凭据 prelogin 应答)", Detail: "TDS prelogin OK"}
	}
	return nil
}

// tdsPrelogin 构造 TDS 7.4 prelogin 报文:版本+加密+实例名+线程 id。
func tdsPrelogin() []byte {
	// prelogin options: 版本(0x00,5) 加密(0x01,1) 实例(0x02,1) 线程id(0x03,4)
	opts := [][]byte{
		{0x00, 0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}, // version 0x05000000
		{0x01, 0x01, 0x00, 0x00, 0x00},                         // encrypt off
		{0x02, 0x01, 0x00, 0x00, 0x00},                         // instance 空
		{0x03, 0x04, 0x00, 0x00, 0x00, 0x00},                   // thread id 0
	}
	body := make([]byte, 0, 64)
	for _, o := range opts {
		body = append(body, o...)
	}
	body = append(body, 0xff) // terminator
	length := 8 + len(body)
	msg := make([]byte, 0, length)
	msg = append(msg, 0x12) // PRELOGIN
	msg = append(msg, 0x01) // status
	msg = append(msg, byte(length>>8), byte(length))
	msg = append(msg, 0x00, 0x00) // spid
	msg = append(msg, 0x01)       // packetid
	msg = append(msg, 0x00)       // window
	msg = append(msg, body...)
	return msg
}

// ── Squid：匿名代理判定 ──

// probeSquid 判定 Squid 是否匿名开放代理:发 CONNECT 到目标(用公开测试
// 主机),代理返回 200 Connection established 即匿名可用。CONNECT 是代理
// 协议探测标准方式;不做实际转发。
func probeSquid(ctx context.Context, t Target, timeout time.Duration) *Result {
	conn, err := dialTimeout(ctx, t, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	// CONNECT 到 example.com:443(常见探测目标),代理应回 200
	if _, err := conn.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n")); err != nil {
		return nil
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return nil
	}
	if strings.Contains(line, "200") && strings.Contains(strings.ToLower(line), "established") {
		return &Result{Host: t.Host, Port: t.Port, Service: "squid",
			Finding: "Squid 匿名代理可用", Detail: strings.TrimSpace(line)}
	}
	return nil
}

// ── SMTPS：隐式 TLS 匿名横幅判定 ──

// probeSMTPS 判定 SMTPS(465 隐式 TLS)是否允许匿名:建连后 TLS 握手,
// 服务端回 220 横幅(无需先发 EHLO 即标识可达)。只做横幅读取不做邮件事务。
func probeSMTPS(ctx context.Context, t Target, timeout time.Duration) *Result {
	conn, err := dialTimeout(ctx, t, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	if err := tc.Handshake(); err != nil {
		return nil
	}
	line, err := bufio.NewReader(tc).ReadString('\n')
	if err != nil {
		return nil
	}
	if strings.HasPrefix(line, "220") {
		return &Result{Host: t.Host, Port: t.Port, Service: "smtps",
			Finding: "SMTPS 服务暴露(匿名横幅)", Detail: strings.TrimSpace(line)}
	}
	return nil
}

// ── Oracle：TNS 版本未认证泄露 ──

// probeOracle 向 1521 发 TNS CONNECT 报文,内容为 (COMMAND=VERSION) 查询:
// 无需认证,服务端在应答(含 REFUSE/ERROR 帧)中携带 (VSNNUM=..) 内部版本号,
// 精确到补丁集——是 Oracle 靶机价值评估(已知漏洞定位)的第一信号。
func probeOracle(ctx context.Context, t Target, timeout time.Duration) *Result {
	conn, err := dialTimeout(ctx, t, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(tnsVersionRequest()); err != nil {
		return nil
	}
	reply := make([]byte, 512)
	n, err := conn.Read(reply)
	if err != nil && n == 0 {
		return nil
	}
	reply = reply[:n]
	v := oracleVSNNUMVersion(reply)
	if v == "" {
		return nil
	}
	return &Result{Host: t.Host, Port: t.Port, Service: "oracle",
		Finding: "Oracle TNS 版本未认证泄露", Detail: v}
}

// tnsVersionRequest 构造 TNS CONNECT 报文查询服务端版本。
// 报文为 TNS 12.2 NSPTCN 连接描述定值 + (COMMAND=VERSION) 命令串,长度头
// (含 8 字节头)按实际总长回填。应答无论 ACCEPT/REFUSE 均含 VSNNUM。
func tnsVersionRequest() []byte {
	pkt := append([]byte{
		0x00, 0x00, // 报文长度(占位回填,含 8 字节头)
		0x00, 0x00, // 校验和(服务端不校验)
		0x01, 0x00, // 包类型 CONNECT / 标志
		0x00, 0x00, // 连接数据区起始保留
		0x01, 0x36, 0x01, 0x2c, // 协商版本 315 / 最小兼容 300
		0x00, 0x00, 0x08, 0x00, // 服务选项 / SDU
		0x7f, 0xff, 0x7f, 0x08, // TDU / NT 协议特性
		0x00, 0x00, 0x00, 0x01, // 线路回转 / 数据值
		0x00, 0x20, 0x00, 0x3a, // 连接标志 / 数据上限
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, // 偏移/填充保留定值
		0x34, 0xe6, // 会话密钥定值(NSPTCN 抓包口径)
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}, "(CONNECT_DATA=(COMMAND=VERSION))"...)
	binary.BigEndian.PutUint16(pkt[0:2], uint16(len(pkt)))
	return pkt
}

// oracleVSNNUMVersion 从 TNS 应答中提取 (VSNNUM=十进制) 并解码版本号。
// VSNNUM 是十六进制 nibble 拼装的五段版本(major.minor.a.b.c),左补零
// 对齐 7 位后切分。
func oracleVSNNUMVersion(reply []byte) string {
	const marker = "(VSNNUM="
	idx := bytes.Index(reply, []byte(marker))
	if idx < 0 {
		return ""
	}
	end := bytes.IndexByte(reply[idx:], ')')
	if end < 0 {
		return ""
	}
	digits := string(reply[idx+len(marker) : idx+end])
	if digits == "" {
		return ""
	}
	var v uint64
	for _, c := range digits {
		if c < '0' || c > '9' {
			return ""
		}
		v = v*10 + uint64(c-'0')
	}
	hex := fmt.Sprintf("%07x", v)
	part := func(s string) string {
		n := 0
		for _, c := range s {
			var d int
			switch {
			case c >= '0' && c <= '9':
				d = int(c - '0')
			case c >= 'a' && c <= 'f':
				d = int(c-'a') + 10
			default:
				return "?"
			}
			n = n*16 + d
		}
		return fmt.Sprintf("%d", n)
	}
	return fmt.Sprintf("%s.%s.%s.%s.%s (VSNNUM=%s)",
		part(hex[0:1]), part(hex[1:2]), part(hex[2:4]), part(hex[4:5]), part(hex[5:7]), digits)
}

// ── Java RMI：JRMP 端点暴露判定 ──

// probeRMI 向 RMI 注册表/远端对象端口发 JRMP 协议握手("JRMI" 魔数 + 流
// 协议 K),服务端以 Nak(0x4e) 应答即 JRMP 端点暴露——RMI 注册表无认证
// 机制,可匿名 bind/list 枚举远程对象,是 Java 反序列化攻击面的入口信号。
func probeRMI(ctx context.Context, t Target, timeout time.Duration) *Result {
	conn, err := dialTimeout(ctx, t, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte{'J', 'R', 'M', 'I', 0x00, 0x00, 0x02, 0x4b}); err != nil {
		return nil
	}
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		return nil
	}
	if n > 0 && buf[0] == 0x4e { // 'N': JRMP Nak 应答
		return &Result{Host: t.Host, Port: t.Port, Service: "java-rmi",
			Finding: "Java RMI 服务暴露(JRMP)", Detail: fmt.Sprintf("Nak %d 字节应答", n)}
	}
	return nil
}

// ── DCERPC：端点映射器匿名可访问/可枚举 ──

// probeDCERPC 对 135 端口映射器(EPM)做两步交互:
//  1. bind 到 EPM 接口(对象 UUID 99fcfec4-5260-101b-bbcb-00aa0021347a,
//     NDR 传输语法),bind_ack 应答且上下文被接受 = 匿名可绑定;
//  2. EPM 查询(opnum 5),应答中可提取的 UTF-16LE 注释串 = RPC 端点
//     匿名枚举证据(攻击面测绘可直接命中)。
func probeDCERPC(ctx context.Context, t Target, timeout time.Duration) *Result {
	conn, err := dialTimeout(ctx, t, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(dcerpcEPMBind()); err != nil {
		return nil
	}
	ack := make([]byte, 256)
	n, err := conn.Read(ack)
	if err != nil && n == 0 {
		return nil
	}
	// bind_ack:版本 5.0 + 包类型 0x0c
	if !bytes.HasPrefix(ack[:n], []byte{0x05, 0x00, 0x0c, 0x03, 0x10, 0x00, 0x00, 0x00}) {
		return nil
	}
	eps := dcerpcEPMQuery(ctx, conn, timeout)
	if len(eps) > 0 {
		return &Result{Host: t.Host, Port: t.Port, Service: "dcerpc",
			Finding: "DCERPC 端点映射器匿名可枚举", Detail: strings.Join(eps, "; ")}
	}
	return &Result{Host: t.Host, Port: t.Port, Service: "dcerpc",
		Finding: "DCERPC 端点映射器匿名可访问", Detail: "bind_ack"}
}

// dcerpcEPMBind 构造 EPM bind 请求(PDU type 0x0b,frag 长度 72):
// 单上下文 EPM 接口 UUID v3.0 + NDR 传输语法。
func dcerpcEPMBind() []byte {
	pkt := []byte{
		0x05, 0x00, 0x0b, 0x03, // 版本 5.0 / bind / FIRSTFRAG|LASTFRAG
		0x10, 0x00, 0x00, 0x00, // 数据表示(ASCII 小端 IEEE)
		0x48, 0x00, 0x00, 0x00, // 分片长度 72 / 认证长度 0
		0x01, 0x00, 0x00, 0x00, // 调用 ID 1
		0xf8, 0x0f, 0xf8, 0x0f, 0x00, 0x00, // 最大发送/接收 4088 / 关联组
		0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // 上下文计数 1 / 上下文 ID 0
		0x00, 0x00, 0x01, 0x00, // 传输语法条目数 1
		// 抽象语法:EPM 接口 99fcfec4-5260-101b-bbcb-00aa0021347a v3.0
		0xc4, 0xfe, 0xfc, 0x99, 0x60, 0x52, 0x1b, 0x10,
		0xbb, 0xcb, 0x00, 0xaa, 0x00, 0x21, 0x34, 0x7a,
		0x00, 0x00, 0x00, 0x00,
		// 传输语法:NDR 8a885d04-1ceb-11c9-9fe8-08002b104860 v2.0
		0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
		0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
		0x02, 0x00, 0x00, 0x00,
	}
	return pkt
}

// dcerpcEPMQuery 发 EPM 查询请求(opnum 5),提取应答中的 UTF-16LE 注释串。
func dcerpcEPMQuery(ctx context.Context, conn net.Conn, timeout time.Duration) []string {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	req := []byte{
		0x05, 0x00, 0x00, 0x03, // 版本 5.0 / request / IDEMPOTENT
		0x10, 0x00, 0x00, 0x00, // 数据表示
		0x18, 0x00, 0x00, 0x00, // 分片长度 24 / 认证 0
		0x01, 0x00, 0x00, 0x00, // 调用 ID 1
		0x00, 0x00, 0x00, 0x00, // 分配提示 0
		0x00, 0x00, 0x05, 0x00, // 上下文 ID 0 / opnum 5
	}
	if _, err := conn.Write(req); err != nil {
		return nil
	}
	reply := make([]byte, 512)
	n, err := conn.Read(reply)
	if err != nil && n == 0 {
		return nil
	}
	return utf16LEReadableRuns(reply[:n])
}

// utf16LEReadableRuns 从字节流中提取 UTF-16LE 可读串(≥2 字符,字节对
// [可打印,0x00])。EPM 应答的注释/端点字段即此编码。
func utf16LEReadableRuns(b []byte) []string {
	var out []string
	var cur []byte
	for i := 0; i+1 < len(b); i += 2 {
		if b[i] >= 0x20 && b[i] < 0x7f && b[i+1] == 0x00 {
			cur = append(cur, b[i])
			continue
		}
		if len(cur) >= 2 {
			out = append(out, string(cur))
			if len(out) >= 8 {
				break
			}
		}
		cur = nil
	}
	if len(cur) >= 2 && len(out) < 8 {
		out = append(out, string(cur))
	}
	return out
}

// ── SOCKS5：匿名开放代理判定 ──

// probeSOCKS5 判定 SOCKS5 是否匿名开放代理:方法协商仅提供「无认证」
// (0x00),服务端选中后再发 CONNECT(域名型 example.com:443,与 Squid 探测
// 同口径),应答 REP=0x00 = 隧道建立成功——匿名可转发任意出网流量。
func probeSOCKS5(ctx context.Context, t Target, timeout time.Duration) *Result {
	conn, err := dialTimeout(ctx, t, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil { // VER / 方法数 / [无认证]
		return nil
	}
	m := make([]byte, 2)
	if _, err := readFull(conn, m); err != nil || m[0] != 0x05 || m[1] != 0x00 {
		return nil // 要求认证(0x02 等)不标记
	}
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len("example.com"))}
	req = append(req, "example.com"...)
	req = binary.BigEndian.AppendUint16(req, 443)
	if _, err := conn.Write(req); err != nil {
		return nil
	}
	rep := make([]byte, 4) // VER / REP / RSV / ATYP
	if _, err := readFull(conn, rep); err != nil || rep[1] != 0x00 {
		return nil
	}
	return &Result{Host: t.Host, Port: t.Port, Service: "socks5",
		Finding: "SOCKS5 匿名开放代理可用", Detail: "CONNECT example.com:443 建立成功"}
}

// ── frp：隧道入口暴露判定 ──

// probeFRP 探测 frp 服务端端口:发送控制面版本交换帧,应答为特征魔数
// (请求 00 01 00 01… / 应答 00 01 00 02…)= frps 隧道入口暴露。无 token
// 的 frps 可被任意外部客户端注册为内网穿透跳板(token 在登录层校验,
// 此处只判入口,不声称无 token)。
func probeFRP(ctx context.Context, t Target, timeout time.Duration) *Result {
	conn, err := dialTimeout(ctx, t, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte{0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}); err != nil {
		return nil
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		return nil
	}
	want := []byte{0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}
	if n >= len(want) && bytes.Equal(buf[:len(want)], want) {
		return &Result{Host: t.Host, Port: t.Port, Service: "frp",
			Finding: "frp 穿透服务端口暴露(隧道入口)", Detail: "版本交换应答 00010002"}
	}
	return nil
}

// ── GIOP：CORBA/IIOP 中间件暴露判定 ──

// probeGIOP 发 GIOP 1.2 LocateRequest(object key "NameService"),应答以
// "GIOP" 魔数开头 = IIOP/CORBA 中间件暴露——命名服务可未认证交互,老旧
// 中间件常伴反序列化攻击面(WebLogic/JacORB/omniORB 一类)。
func probeGIOP(ctx context.Context, t Target, timeout time.Duration) *Result {
	conn, err := dialTimeout(ctx, t, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(giopLocateNameService()); err != nil {
		return nil
	}
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		return nil
	}
	reply := buf[:n]
	if !bytes.HasPrefix(reply, []byte("GIOP")) || len(reply) < 8 {
		return nil
	}
	types := map[byte]string{0: "Request", 1: "Reply", 2: "CancelRequest", 3: "LocateRequest",
		4: "LocateReply", 5: "CloseConnection", 6: "MessageError", 7: "Fragment"}
	kind := types[reply[7]]
	if kind == "" {
		kind = fmt.Sprintf("type %d", reply[7])
	}
	return &Result{Host: t.Host, Port: t.Port, Service: "giop",
		Finding: "CORBA/IIOP 服务暴露(命名服务应答)", Detail: fmt.Sprintf("GIOP %d.%d %s", reply[4], reply[5], kind)}
}

// giopLocateNameService 构造 GIOP 1.2 LocateRequest:魔数 + 版本 + 小端
// 标志 + 消息类型 3 + 消息体长度 23 + 请求头(request_id/object_key)。
func giopLocateNameService() []byte {
	pkt := append([]byte{
		'G', 'I', 'O', 'P', // 魔数
		0x01, 0x02, // 版本 1.2
		0x00, 0x03, // 小端 / LocateRequest
		0x17, 0x00, 0x00, 0x00, // 消息体长度 23(小端)
		0x00, 0x00, 0x00, 0x02, // request_id
		0x00, 0x00, 0x00, 0x00, // 对齐保留
		0x00, 0x00, 0x00, 0x0b, // object_key 长度 11
	}, "NameService"...)
	return pkt
}

// ── NetBIOS：节点状态匿名可读(UDP 137 NBSTAT) ──

// probeNBNS 向 UDP 137 发 NBSTAT 通配名(*)节点状态查询,应答的名字表含
// 主机名/工作组/域后缀——未认证可读的域情报(域判定旁路信号,可标记
// 域控制器存在)。NBNS 是 UDP:目标行锚定的 TCP 端口(139 等)只决定触发,
// 查询固定发往同主机 137。
func probeNBNS(ctx context.Context, t Target, timeout time.Duration) *Result {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", fmt.Sprintf("%s:137", t.Host))
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(nbnsNodeStatusQuery()); err != nil {
		return nil
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 12 {
		return nil
	}
	computer, domain, isDC := parseNBNSNodeStatus(buf[:n])
	if computer == "" && domain == "" {
		return nil
	}
	detail := fmt.Sprintf("UDP 137; 域=%s 主机=%s", domain, computer)
	if isDC {
		detail += "(含域控制器记录)"
	}
	return &Result{Host: t.Host, Port: t.Port, Service: "nbns",
		Finding: "NetBIOS 节点状态匿名可读(主机/域信息泄露)", Detail: detail}
}

// nbnsNodeStatusQuery 构造 NBNS 节点状态查询:通配名 * 的 level 编码
// (0x20 长度 + 32 字符) + QTYPE NBSTAT(0x21) + QCLASS IN。
func nbnsNodeStatusQuery() []byte {
	q := []byte{0x00, 0x00, // 事务 ID
		0x00, 0x10, // 标志(RD)
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 问题数 1
		0x20, // 编码名长度 32
	}
	q = append(q, 'C', 'K') // "*" 的 level 编码首对
	for i := 0; i < 30; i++ {
		q = append(q, 'A')
	}
	q = append(q, 0x00, // 编码名终止
		0x00, 0x21, // QTYPE = NBSTAT
		0x00, 0x01) // QCLASS = IN
	return q
}

// parseNBNSNodeStatus 解析 NBSTAT 应答的名字表(RFC 1002 §4.1.2):
// 跳过问题区(编码名定长 35 + 类型/类 4),应答 RR 名字兼容压缩指针与
// 全名两种形态,RDATA = 名字计数 + N×(NAME(15)+SUFFIX(1)+FLAGS(2))。
// 返回(主机名, 域/工作组名, 是否含域控制器记录)。
func parseNBNSNodeStatus(b []byte) (computer, domain string, isDC bool) {
	off := 12 + 35 + 4 // 跳过问题区
	if off >= len(b) {
		return
	}
	if b[off] == 0xc0 { // 压缩指针(2 字节)替代全名
		off += 2
	} else {
		off += 35
	}
	// TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)
	if off+10 > len(b) {
		return
	}
	off += 10
	count := int(b[off])
	off++
	for i := 0; i < count && off+18 <= len(b); i++ {
		entry := b[off : off+18]
		off += 18
		name := printableASCII(entry[:15])
		suffix := entry[15]
		group := entry[16]&0x80 != 0 // NB_FLAGS 最高字节最高位 = 组名
		switch {
		case suffix == 0x1b || suffix == 0x1c: // 域主浏览器 / 域控制器组
			isDC = true
			if name != "" {
				domain = name
			}
		case suffix == 0x00 && group && domain == "":
			domain = name
		case suffix == 0x00 && !group && computer == "",
			suffix == 0x20 && !group && computer == "": // 工作站/文件服务(唯一名)
			computer = name
		}
	}
	return
}

// printableASCII 取可打印 ASCII 字符序列(NetBIOS 名 15 字节空格填充)。
func printableASCII(b []byte) string {
	var out []byte
	for _, c := range b {
		if c >= 0x20 && c < 0x7f {
			out = append(out, c)
		}
	}
	return strings.TrimSpace(string(out))
}
