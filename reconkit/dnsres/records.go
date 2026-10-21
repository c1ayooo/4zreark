// records.go DNS 记录面扩展（OneForAll dns 查询模块的对应物）：NS/MX/SOA/TXT
// 记录画像、常见 SRV 枚举（AD 域定位记录在内）、AXFR 域传送探测。
// 用 miekg/dns 原始报文实现——标准库缺 SOA/SRV/AXFR；该依赖此前在 go.mod
// 纯声明未启用，此处正式启用（启用 AXFR = 授权范围内的域传送漏洞检查）。
package dnsres

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// RecordProfile 主域的 DNS 记录画像（OneForAll 的 MX/NS/SOA/TXT 四查合一）。
type RecordProfile struct {
	NS  []string // 权威 NS（AXFR 目标也从这里取）
	MX  []string
	TXT []string
	SOA string
}

// SRVRecord 单条 SRV 命中。Name 为查询名（_ldap._tcp.example.com），
// Target 为服务主机——SRV 命中即内部服务线索（域控/邮件/会议系统）。
type SRVRecord struct {
	Name     string
	Target   string
	Port     int
	Priority int
	Weight   int
}

// CommonSRVNames 常见 SRV 服务名（OneForAll srv 列表与 AD 域定位记录合并裁剪，
// 每条 = <service>._tcp/_udp，拼主域后查询）。AD 系（ldap/kerberos/gc/kpasswd）
// 是重点——命中即域环境指纹，直接喂攻击面决策。
var CommonSRVNames = []string{
	"_ldap._tcp", "_ldap._udp",
	"_ldap._tcp.dc._msdcs", "_ldap._tcp.gc._msdcs",
	"_kerberos._tcp", "_kerberos._udp", "_kerberos._tcp.dc._msdcs",
	"_kpasswd._tcp", "_kpasswd._udp",
	"_gc._tcp", "_gc._udp",
	"_sip._tcp", "_sip._tls",
	"_xmpp-client._tcp", "_xmpp-server._tcp",
	"_imap._tcp", "_imaps._tcp", "_pop3._tcp", "_pop3s._tcp",
	"_submission._tcp", "_caldav._tcp", "_caldavs._tcp",
	"_carddav._tcp", "_carddavs._tcp",
	"_ftp._tcp", "_ssh._tcp", "_webdav._tcp",
	"_h323cs._tcp", "_h323ls._udp",
	"_stun._udp", "_turn._udp",
}

// ZoneRecord AXFR 导出的单条区记录。
type ZoneRecord struct {
	Name  string
	Type  string // A / CNAME / MX / TXT / NS / SOA / AAAA / 其他字符串化
	Value string
}

// AXFRResult 域传送结论。Vulnerable=true 时 Records 为完整区数据——
// 调用方应把其中本域 A/CNAME 记录直接回灌子域清单（命中即高危）。
type AXFRResult struct {
	Server     string
	Vulnerable bool
	Records    []ZoneRecord
}

// LookupProfile 查询主域的 NS/MX/SOA/TXT 画像。单类型失败不影响其余
// （NS 失败只置空 NS 列表）。
func (p *Pool) LookupProfile(ctx context.Context, domain string) (*RecordProfile, error) {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if domain == "" {
		return nil, fmt.Errorf("空域名")
	}
	prof := &RecordProfile{}
	var wg sync.WaitGroup
	var mu sync.Mutex
	query := func(qtype uint16, apply func(prof *RecordProfile, values []string)) {
		defer wg.Done()
		values, err := p.rawLookup(ctx, domain, qtype)
		if err != nil {
			return // 单类型失败静默降级：画像其余字段照常返回
		}
		mu.Lock()
		defer mu.Unlock()
		apply(prof, values)
	}
	wg.Add(4)
	go query(dns.TypeNS, func(pr *RecordProfile, v []string) { pr.NS = v })
	go query(dns.TypeMX, func(pr *RecordProfile, v []string) { pr.MX = v })
	go query(dns.TypeTXT, func(pr *RecordProfile, v []string) { pr.TXT = v })
	go query(dns.TypeSOA, func(pr *RecordProfile, v []string) {
		if len(v) > 0 {
			pr.SOA = v[0]
		}
	})
	wg.Wait()
	return prof, nil
}

// LookupSRV 并发枚举 SRV 记录（names 为 CommonSRVNames 的子集或全集）。
func (p *Pool) LookupSRV(ctx context.Context, domain string, names []string) []SRVRecord {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if domain == "" || len(names) == 0 {
		return nil
	}
	if len(names) > 40 {
		names = names[:40] // 防误传超大清单
	}
	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		records []SRVRecord
	)
	sem := make(chan struct{}, 8)
	for _, svc := range names {
		qname := strings.TrimSuffix(svc, ".") + "." + domain
		wg.Add(1)
		go func(qname string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			srvs, err := p.lookupSRVOnce(ctx, qname)
			if err != nil || len(srvs) == 0 {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			records = append(records, srvs...)
		}(qname)
	}
	wg.Wait()
	return records
}

func (p *Pool) lookupSRVOnce(ctx context.Context, qname string) ([]SRVRecord, error) {
	msg, err := p.exchange(ctx, dns.Fqdn(qname), dns.TypeSRV)
	if err != nil || msg == nil {
		return nil, err
	}
	var out []SRVRecord
	for _, rr := range msg.Answer {
		if srv, ok := rr.(*dns.SRV); ok {
			out = append(out, SRVRecord{
				Name:     qname,
				Target:   strings.TrimSuffix(srv.Target, "."),
				Port:     int(srv.Port),
				Priority: int(srv.Priority),
				Weight:   int(srv.Weight),
			})
		}
	}
	return out, nil
}

// TryAXFR 对主域的全部权威 NS 逐台尝试域传送（OneForAll axfr 模块语义）。
// 单台成功即返回；全部拒绝/失败返回 Vulnerable=false。
// 量级说明：只对 NS 记录返回的权威服务器（通常 ≤5 台）各发一次 AXFR，
// 属授权范围内的标准测绘动作。
func (p *Pool) TryAXFR(ctx context.Context, nsServers []string, domain string) *AXFRResult {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	for _, ns := range nsServers {
		ns = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(ns)), ".")
		if ns == "" {
			continue
		}
		recs, err := axfrOnce(ctx, ns+":53", domain, p.timeout)
		if err != nil || len(recs) == 0 {
			continue
		}
		return &AXFRResult{Server: ns, Vulnerable: true, Records: recs}
	}
	return &AXFRResult{Vulnerable: false}
}

// axfrOnce 单台服务器的 AXFR 试探，导出记录类型字符串化。
// miekg/dns v1.1.73 的 Transfer.In 不收 context：用 Dial/Read/Write 三超时
// 兜底，慢速权威服务器不会挂死整轮。
func axfrOnce(ctx context.Context, server, domain string, timeout time.Duration) ([]ZoneRecord, error) {
	tr := &dns.Transfer{
		DialTimeout:  timeout,
		ReadTimeout:  timeout,
		WriteTimeout: timeout,
	}
	m := new(dns.Msg)
	m.SetAxfr(dns.Fqdn(domain))
	env, err := tr.In(m, server)
	if err != nil {
		return nil, err
	}
	// ctx 取消感知：In 启动后监听一次取消（传输本身由 ReadTimeout 兜底）
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	var records []ZoneRecord
	for e := range env {
		if e.Error != nil {
			return nil, e.Error
		}
		for _, rr := range e.RR {
			name := strings.TrimSuffix(rr.Header().Name, ".")
			records = append(records, ZoneRecord{Name: name, Type: dns.Type(rr.Header().Rrtype).String(), Value: rrString(rr)})
		}
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("空区数据")
	}
	return records, nil
}

// rrString 各记录类型取值字符串化（A 取 IP、CNAME 取目标、MX 取 pref:host、
// TXT 取拼接文本、SRV 取 target:port，其余取 RR.String 兜底）。
func rrString(rr dns.RR) string {
	switch v := rr.(type) {
	case *dns.A:
		return v.A.String()
	case *dns.AAAA:
		return v.AAAA.String()
	case *dns.CNAME:
		return strings.TrimSuffix(v.Target, ".")
	case *dns.MX:
		return fmt.Sprintf("%d %s", v.Preference, strings.TrimSuffix(v.Mx, "."))
	case *dns.TXT:
		return strings.Join(v.Txt, "")
	case *dns.NS:
		return strings.TrimSuffix(v.Ns, ".")
	case *dns.SOA:
		return fmt.Sprintf("%s %s", strings.TrimSuffix(v.Ns, "."), strings.TrimSuffix(v.Mbox, "."))
	case *dns.SRV:
		return fmt.Sprintf("%s:%d", strings.TrimSuffix(v.Target, "."), v.Port)
	default:
		return rr.String()
	}
}

// exchange 原始报文查询：走解析池的 server 轮转，单次超时按池配置。
func (p *Pool) exchange(ctx context.Context, qname string, qtype uint16) (*dns.Msg, error) {
	server := p.nextServer()
	if !strings.Contains(server, ":") {
		server += ":53"
	}
	c := &dns.Client{Timeout: p.timeout, DialTimeout: p.timeout}
	m := new(dns.Msg)
	m.SetQuestion(qname, qtype)
	m.RecursionDesired = true
	resp, _, err := c.ExchangeContext(ctx, m, server)
	if err != nil {
		return nil, err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return resp, fmt.Errorf("DNS %s", dns.RcodeToString[resp.Rcode])
	}
	return resp, nil
}

// rawLookup 泛化记录查询：答案列表按 rrString 取值。
func (p *Pool) rawLookup(ctx context.Context, domain string, qtype uint16) ([]string, error) {
	msg, err := p.exchange(ctx, dns.Fqdn(domain), qtype)
	if err != nil || msg == nil {
		return nil, err
	}
	values := make([]string, 0, len(msg.Answer))
	for _, rr := range msg.Answer {
		if rr.Header().Rrtype == qtype {
			values = append(values, rrString(rr))
		}
	}
	return values, nil
}
