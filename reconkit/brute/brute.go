// Package brute 子域名爆破:字典 × 高并发 DNS 解析 + 泛解析基线过滤。
//
// 设计参照社区成熟实现(2026-10-16 T5 新增,非 4zreco 移植):
//   - massdns 的并发解析模型——解析池多服务器轮转 + 全局并发上限;
//   - puredns / shuffledns 的泛解析基线过滤——先随机探针探测,命中则把
//     解析到基线 IP 集的爆破命中视为泛解析噪音剔除(已知代价:与泛解析
//     同 IP 的真实子域会被一并滤掉,这与两个参照实现的行为一致);
//   - SecLists 风格的内置常用字典,偏中文 SRC 业务语境(见 builtinWords)。
//
// 限速用简单令牌桶(每秒 N 个解析请求),对权威 NS 友好;并发由 dnsres.Pool
// 的全局信号量兜底。
package brute

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/reconkit/dnsres"
)

// Options 爆破配置。
type Options struct {
	// Words 追加字典(与内置字典合并去重)。
	Words []string
	// Resolvers 自定义解析器列表(host[:port]);空 = dnsres 内置公共解析器。
	Resolvers []string
	// Concurrency 并发解析上限(0 = 32)。
	Concurrency int
	// QPS 每秒解析请求上限(令牌桶;0 = 不限速)。默认建议 200~500,
	// 对公共解析器友好;内网自建解析器可调高。
	QPS int
	// Pool 直接注入解析池(测试打桩);注入时 Resolvers/Concurrency 被忽略。
	Pool *dnsres.Pool
	// DisableWildcardFilter 关闭泛解析过滤(默认开启)。不建议:泛解析域会
	// 把整个字典判活。留着这个开关是为了疑难场景下人工对比。
	DisableWildcardFilter bool
}

// Hit 一条爆破命中。
type Hit struct {
	Name  string   `json:"name"`
	IPs   []string `json:"ips"`
	CNAME string   `json:"cname,omitempty"`
}

// Stats 爆破统计。
type Stats struct {
	Domain           string `json:"domain"`
	Probed           int    `json:"probed"`            // 发起解析的候选数
	Resolved         int    `json:"resolved"`          // 解析成功数(过滤前)
	Wildcard         bool   `json:"wildcard"`          // 检出泛解析
	WildcardFiltered int    `json:"wildcard_filtered"` // 因泛解析基线被剔除的命中数
	Hits             int    `json:"hits"`              // 最终命中
}

// builtinWords 内置字典:通用前缀 + 中文 SRC 业务高频词。覆盖面优先于体积
// (≈400 词,单域一次爆破约 400 次解析,公共解析器 QPS 300 下约 1.5s)。
const builtinWords = `
www api mail ftp smtp pop imap web web1 web2 app app1 app2 m mobile mip wap
h5 ios android admin administrator manager backend console dashboard portal
sso auth login passport id account acc user users member members vip customer
crm erp oa hr it dev test testing qa uat sit pre preprod prod production beta
demo gray inner intranet external public private open alpha staging sandbox
bbs forum community blog wiki docs doc help support faq knowledge kb search
shop store mall goods product cart order pay payment cashir billing trade
upload file files download uploads assets static cdn img images image pic
photo video media stream live news info news2 notice announce msg message
chat im talk push notify notification mail2 email webmail exmail vpn proxy
gate gateway outer entrance monitor zabbix grafana prometheus kibana elastic
es redis mysql mongo pgsql db database data warehouse bi report reports
stat stats analysis log logs trace skywalking sentry nacos consul apollo
config conf zookeeper zk kafka rabbitmq rocketmq mq mq2 nameserver ns dns
jenkins git gitlab github gitee svn nexus harbor registry docker k8s kube
rancher jumpserver bastion jms cobaltstrike cs msf metasploit awvs burp
wiki2 share pan disk nas backup bak old new tmp temp cache redis2 session
token jwt cert pki ca sso2 oauth2 cas keycloak shiro spring boot admin2
swagger openapi api2 graphql ws websocket grpc tcp udp game games pay2
funds finance settle clearing loan credit risk audit legal compliance
secure security waf ips ids honeypot scan scanner pentest redteam blue
ai llm gpt chatgpt ollama translate tts asr ocr nlp ml algorithm recommend
rec engine scheduler xxl job task flow workflow bpm oa2 approve signing
seal contract invoice tax salary attend meeting room reservation car park
visitor guard door access camera video2 surveillance monitor2 alert
third open2 partner channel agent dealer franchise supplier vendor
erp2 mes wms tms scm srm fico hr2 ehr payroll recruit training exam
study edu class course lesson live2 homework parent student teacher
hospital clinic doctor patient drug pharmacy registration appointment
estate property building house rent lease property2 parking2
energy power water gas environment weather iot sensor device edge
box tv watch band car2 vehicle charging pile station grid
`

// BuiltinWords 返回内置字典(去空去重,小写)。
func BuiltinWords() []string {
	seen := map[string]bool{}
	out := make([]string, 0, 420)
	for _, w := range strings.Fields(builtinWords) {
		w = strings.ToLower(w)
		if !seen[w] {
			seen[w] = true
			out = append(out, w)
		}
	}
	return out
}

// limiter 简单令牌桶:每 interval 补一个令牌,取不到就等。
type limiter struct {
	tokens chan struct{}
	stop   chan struct{}
}

func newLimiter(qps int) *limiter {
	if qps <= 0 {
		return nil
	}
	l := &limiter{tokens: make(chan struct{}, qps), stop: make(chan struct{})}
	interval := time.Second / time.Duration(qps)
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-l.stop:
				return
			case <-t.C:
				select {
				case l.tokens <- struct{}{}:
				default:
				}
			}
		}
	}()
	return l
}

func (l *limiter) wait(ctx context.Context) error {
	if l == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-l.tokens:
		return nil
	}
}

func (l *limiter) close() {
	if l != nil {
		close(l.stop)
	}
}

// Brute 对单个主域执行爆破。返回命中(已过滤泛解析)与统计。
// 域名有效性/泛解析探测失败不阻断爆破——探测失败按无泛解析处理并继续
// (fail-open 指漏掉过滤,不漏掉爆破)。
func Brute(ctx context.Context, domain string, opts Options) ([]Hit, *Stats, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" || !strings.Contains(domain, ".") {
		return nil, nil, fmt.Errorf("主域无效: %q", domain)
	}
	pool := opts.Pool
	if pool == nil {
		pool = dnsres.NewPool(opts.Resolvers, opts.Concurrency, 0, 0)
	}
	stats := &Stats{Domain: domain}

	// 1) 泛解析探测(基线 IP 集)。
	var baseline map[string]bool
	if !opts.DisableWildcardFilter {
		if wr, err := pool.DetectWildcard(ctx, domain, 3); err == nil && wr.IsWildcard {
			stats.Wildcard = true
			baseline = wr.IPs
		}
	}

	// 2) 候选合并(内置 + 追加,去重)。
	seenW := map[string]bool{}
	words := make([]string, 0, 512)
	for _, w := range append(BuiltinWords(), opts.Words...) {
		w = strings.ToLower(strings.TrimSpace(w))
		if w == "" || seenW[w] {
			continue
		}
		seenW[w] = true
		words = append(words, w)
	}

	// 3) 并发解析(限速 + 池信号量)。
	lm := newLimiter(opts.QPS)
	defer lm.close()
	type resolved struct {
		name string
		ans  *dnsres.Answer
	}
	var (
		mu      sync.Mutex
		results []resolved
		wg      sync.WaitGroup
	)
	for _, w := range words {
		if ctx.Err() != nil {
			break
		}
		if err := lm.wait(ctx); err != nil {
			break
		}
		stats.Probed++
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			ans, err := pool.Resolve(ctx, name)
			if err != nil || ans == nil || len(ans.IPs) == 0 {
				return
			}
			mu.Lock()
			results = append(results, resolved{name: name, ans: ans})
			mu.Unlock()
		}(w + "." + domain)
	}
	wg.Wait()

	// 4) 泛解析基线过滤:命中 IP 全部落在基线集内 → 视为泛解析噪音。
	var hits []Hit
	for _, r := range results {
		stats.Resolved++
		if baseline != nil {
			allBaseline := true
			for _, ip := range r.ans.IPs {
				if !baseline[ip] {
					allBaseline = false
					break
				}
			}
			if allBaseline {
				stats.WildcardFiltered++
				continue
			}
		}
		hits = append(hits, Hit{Name: r.name, IPs: r.ans.IPs, CNAME: r.ans.CNAME})
	}
	stats.Hits = len(hits)
	return hits, stats, nil
}
