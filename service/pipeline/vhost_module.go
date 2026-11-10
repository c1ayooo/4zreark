package pipeline

// VhostModule 虚拟主机绑定发现（对齐 ARL findvhost 思路的轻量版）。
//
// 原理：同一 IP:端口上可能绑定多个站点，DNS 指过去才能看到；本模块在端口
// 扫描产出的 web 端口上，用本任务已见的候选域名改 Host 头探测，响应与
// 「随机无效 Host」基线不同形的记为一次 vhost 绑定。
//
// 与 vhostdedup（catch-all 去噪）方向相反：那边剔假站，这边找隐藏的真绑定。
//
// 预算约束：候选域名 × web 端口组合封顶（vhostMaxProbes），只打常见 web
// 端口（80/443/8080/8443），并发 4——这是主动探测，不能随任务规模放大。
//
// 链位置：端口扫描与指纹识别之间。产物不进资产链（IP 形 URL 会污染站点
// 归并），只进结果收集器，由 executor 落 Vhost 结果页供人工确认。

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/internal/useragent"
	"github.com/c1ayooo/4zreark/scanner/scope"
)

var vhostTitleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

const (
	vhostTimeout   = 8 * time.Second
	vhostMaxProbes = 300 // 单任务探测预算
	vhostMaxCands  = 100 // 单 IP:端口 候选域名上限
	vhostConns     = 4
)

// vhostWebPorts 参与探测的常见 web 端口。
var vhostWebPorts = map[string]bool{"80": true, "443": true, "8080": true, "8443": true}

type vhostTarget struct {
	ip, port string
}

type VhostModule struct {
	BaseModule
	resultChan chan interface{}

	mu        sync.Mutex
	targets   map[string]vhostTarget
	cands     map[string]bool
	ownHostIP map[string]map[string]bool // host -> ip 集合：已是真实绑定的组合不重复报
	probes    int
	// scope 是任务授权边界（含全局黑名单）；候选域名越界/命中黑名单直接不探测。
	scope *scope.Scope
}

// SetScope 设置任务授权边界，vhost 必须继承全局禁扫黑名单。
func (m *VhostModule) SetScope(s *scope.Scope) { m.scope = s }

func NewVhostModule(ctx context.Context, nextModule ModuleRunner) *VhostModule {
	return &VhostModule{
		BaseModule: BaseModule{
			name:       "Vhost",
			ctx:        ctx,
			nextModule: nextModule,
			dupChecker: NewDuplicateChecker(),
		},
		resultChan: make(chan interface{}, 200),
		targets:    map[string]vhostTarget{},
		cands:      map[string]bool{},
		ownHostIP:  map[string]map[string]bool{},
	}
}

// ModuleRun 先透传流量保持链路，输入关闭后做 vhost 探测收尾。
func (m *VhostModule) ModuleRun() error {
	var nextModuleRun sync.WaitGroup
	resultWgDone := make(chan struct{})

	if m.nextModule != nil {
		nextModuleRun.Add(1)
		go func() {
			defer nextModuleRun.Done()
			if err := m.nextModule.ModuleRun(); err != nil {
				log.Printf("[%s] Next module error: %v", m.name, err)
			}
		}()
	}

	go func() {
		defer close(resultWgDone)
		for data := range m.resultChan {
			if m.nextModule != nil {
				select {
				case <-m.ctx.Done():
					return
				case m.nextModule.GetInput() <- data:
				}
			}
		}
		if m.nextModule != nil {
			m.nextModule.CloseInput()
		}
	}()

	m.ReportModuleStart(0)
	defer m.ReportModuleComplete()
	for {
		select {
		case <-m.ctx.Done():
			close(m.resultChan)
			<-resultWgDone
			nextModuleRun.Wait()
			return nil

		case data, ok := <-m.input:
			if !ok {
				// 输入关闭：先跑探测，再收尾链路。
				m.probeAll()
				close(m.resultChan)
				<-resultWgDone
				nextModuleRun.Wait()
				return nil
			}
			m.ReportProgress(1, 0)
			m.observe(data)
			// 透传原始数据。
			select {
			case <-m.ctx.Done():
			case m.resultChan <- data:
			}
		}
	}
}

// observe 从流里收集探测目标与候选域名。
func (m *VhostModule) observe(data interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch v := data.(type) {
	case PortAlive:
		if v.IP == "" || v.Port == "" {
			return
		}
		if m.scope != nil && !m.scope.AllowsHost(v.Host) {
			return
		}
		if vhostWebPorts[v.Port] {
			m.targets[v.IP+"|"+v.Port] = vhostTarget{ip: v.IP, port: v.Port}
		}
		m.cands[strings.ToLower(strings.TrimSuffix(v.Host, "."))] = true
		if m.ownHostIP[v.Host] == nil {
			m.ownHostIP[v.Host] = map[string]bool{}
		}
		m.ownHostIP[v.Host][v.IP] = true
	case DomainResolve:
		if m.scope != nil && !m.scope.AllowsHost(v.Domain) {
			return
		}
		for _, ip := range v.IP {
			if ip == "" {
				continue
			}
			m.cands[strings.ToLower(strings.TrimSuffix(v.Domain, "."))] = true
			if m.ownHostIP[v.Domain] == nil {
				m.ownHostIP[v.Domain] = map[string]bool{}
			}
			m.ownHostIP[v.Domain][ip] = true
		}
	case DomainSkip:
		if m.scope != nil && !m.scope.AllowsHost(v.Domain) {
			return
		}
		m.cands[strings.ToLower(strings.TrimSuffix(v.Domain, "."))] = true
	}
}

// probeAll 执行探测并产出 VhostResult。
func (m *VhostModule) probeAll() {
	m.mu.Lock()
	// 过滤：候选里去掉基线探测用的无效域名，组合封顶。
	delete(m.cands, "")
	candidates := make([]string, 0, len(m.cands))
	for c := range m.cands {
		if strings.HasSuffix(c, ".invalid") {
			continue
		}
		if m.scope != nil && !m.scope.AllowsHost(c) {
			continue
		}
		candidates = append(candidates, c)
	}
	targets := make([]vhostTarget, 0, len(m.targets))
	for _, t := range m.targets {
		targets = append(targets, t)
	}
	m.mu.Unlock()

	if len(candidates) == 0 || len(targets) == 0 {
		return
	}

	client := &http.Client{
		Timeout: vhostTimeout,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	sem := make(chan struct{}, vhostConns)
	var wg sync.WaitGroup

	for _, t := range targets {
		if m.ctx.Err() != nil {
			break
		}
		scheme := "http"
		if t.port == "443" || t.port == "8443" {
			scheme = "https"
		}
		baseline := m.probeHost(client, scheme, t, "zl-invalid.invalid")
		if baseline.status == 0 {
			continue // 服务不可达，跳过该目标
		}
		tried := 0
		for _, cand := range candidates {
			m.mu.Lock()
			overBudget := m.probes >= vhostMaxProbes
			m.mu.Unlock()
			if overBudget {
				break
			}
			m.mu.Lock()
			alreadyBound := m.ownHostIP[cand] != nil && m.ownHostIP[cand][t.ip]
			m.mu.Unlock()
			if alreadyBound {
				continue // 该域名本来就解析到这个 IP，不是隐藏绑定
			}
			m.mu.Lock()
			tried++
			m.mu.Unlock()
			if tried > vhostMaxCands {
				break
			}
			wg.Add(1)
			go func(cand string, t vhostTarget, baseline vhostResp, scheme string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				m.mu.Lock()
				m.probes++
				m.mu.Unlock()

				resp := m.probeHost(client, scheme, t, cand)
				if resp.status == 0 || !m.differs(baseline, resp) {
					return
				}
				key := cand + "|" + t.ip + "|" + t.port
				if m.dupChecker.IsURLDuplicate(key) {
					return
				}
				select {
				case <-m.ctx.Done():
				case m.resultChan <- VhostResult{
					IP:         t.ip,
					Port:       t.port,
					Domain:     cand,
					URL:        scheme + "://" + t.ip + ":" + t.port + "/",
					Title:      resp.title,
					StatusCode: resp.status,
					Length:     resp.length,
					Source:     "vhost",
				}:
				}
			}(cand, t, baseline, scheme)
		}
	}
	wg.Wait()
}

// differs 判断候选响应与基线是否不同形。
func (m *VhostModule) differs(base, resp vhostResp) bool {
	if resp.status < 200 || resp.status >= 400 {
		return false
	}
	if base.title != "" && resp.title != "" && base.title == resp.title {
		return false
	}
	diff := resp.length - base.length
	if diff < 0 {
		diff = -diff
	}
	return diff > 32
}

type vhostResp struct {
	status int
	title  string
	length int64
}

// probeHost 以指定 Host 头请求 ip:port。
func (m *VhostModule) probeHost(client *http.Client, scheme string, t vhostTarget, host string) vhostResp {
	ctx, cancel := context.WithTimeout(m.ctx, vhostTimeout)
	defer cancel()
	url := fmt.Sprintf("%s://%s:%s/", scheme, t.ip, t.port)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return vhostResp{}
	}
	req.Host = host
	req.Header.Set("Host", host)
	req.Header.Set("User-Agent", useragent.ForSite("", host).UserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return vhostResp{}
	}
	defer resp.Body.Close()
	body := make([]byte, 32*1024)
	n, _ := io.ReadFull(resp.Body, body)
	title := ""
	if sub := vhostTitleRe.FindSubmatch(body[:n]); sub != nil {
		title = strings.TrimSpace(string(sub[1]))
	}
	return vhostResp{status: resp.StatusCode, title: title, length: resp.ContentLength}
}
