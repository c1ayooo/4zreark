package service

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/internal/outbound"
	"github.com/c1ayooo/4zreark/repo"
)

// NetworkProxyService 管理平台自身出网的代理设置（app_settings: network.proxy）。
// 覆盖规则库同步、工具下载、漏洞情报、被动收集、通知等出网点；
// 面向扫描目标的请求不走全局代理（扫描任务有自己的按任务代理）。
type NetworkProxyService struct{}

func NewNetworkProxyService() *NetworkProxyService { return &NetworkProxyService{} }

func (s *NetworkProxyService) settings() (repo.SettingsRepo, error) {
	r := repo.Default()
	if r == nil {
		return nil, errors.New("数据层未初始化")
	}
	return r.Settings(), nil
}

// defaultConfig 未配置时的默认结构：全部跟随全局，全局关闭。
func defaultConfig() outbound.Config {
	cfg := outbound.Config{
		Modules: make(map[string]outbound.Override, len(outbound.Modules())),
	}
	for _, m := range outbound.Modules() {
		cfg.Modules[m] = outbound.Override{Mode: outbound.ModeGlobal}
	}
	return cfg
}

// GetConfig 读取代理配置；从未配置过时返回默认结构。
func (s *NetworkProxyService) GetConfig(ctx context.Context) (outbound.Config, error) {
	out := defaultConfig()
	st, err := s.settings()
	if err != nil {
		return out, nil // 数据层不可用时按默认展示，避免整页报错
	}
	ok, err := st.Get(ctx, outbound.SettingsKey, &out)
	if err != nil {
		return out, err
	}
	if !ok {
		return defaultConfig(), nil
	}
	// 补齐旧版本存储里缺失的模块键，前端拿到完整结构。
	for _, m := range outbound.Modules() {
		if _, exists := out.Modules[m]; !exists {
			out.Modules[m] = outbound.Override{Mode: outbound.ModeGlobal}
		}
	}
	return out, nil
}

// UpdateConfig 校验、落库并让进程级解析器立即生效（无需重启）。
func (s *NetworkProxyService) UpdateConfig(ctx context.Context, cfg outbound.Config) (outbound.Config, error) {
	norm, err := outbound.Validate(cfg)
	if err != nil {
		return norm, err
	}
	st, err := s.settings()
	if err != nil {
		return norm, err
	}
	if err := st.Set(ctx, outbound.SettingsKey, norm); err != nil {
		return norm, err
	}
	outbound.Reload()
	log.Printf("[network-proxy] 出网代理设置已更新：全局启用=%v", norm.Global.Enabled)
	return norm, nil
}

// ProxyTestResult 连通性测试结果。
type ProxyTestResult struct {
	OK        bool   `json:"ok"`
	Status    int    `json:"status,omitempty"`
	LatencyMS int64  `json:"latency_ms"`
	Target    string `json:"target"`
	Category  string `json:"category,omitempty"`
	ProxyUsed string `json:"proxy_used,omitempty"`
	Error     string `json:"error,omitempty"`
}

// api.github.com/zen 只能证明 API 域通；工具下载真正访问的是 GitHub release
// 资产（github.com → 302 到资产 CDN）。只测前者会误报「连通正常」。
const (
	proxyProbeZen   = "https://api.github.com/zen"
	proxyProbeAsset = "https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/nuclei_3.11.1_checksums.txt"
)

// TestProxy 测连通性：
//   - category 非空：按该模块「实际生效」的代理配置测真实下载链路（工具/模板资产）；
//   - url 非空：测指定代理（旧行为，测 api.github.com/zen）；
//   - 都为空：显式测直连。
func (s *NetworkProxyService) TestProxy(ctx context.Context, proxyURL, category string) ProxyTestResult {
	cat := strings.TrimSpace(category)
	probeURL := proxyProbeZen
	res := ProxyTestResult{Target: proxyProbeZen, Category: cat}
	tr := &http.Transport{
		TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
	switch {
	case cat != "":
		probeURL = proxyProbeAsset
		res.Target = proxyProbeAsset
		if !outbound.ValidModule(cat) {
			res.Error = "未知出网模块 " + cat
			return res
		}
		u, err := outbound.ProxyFor(cat)
		if err != nil {
			res.Error = "代理配置无效: " + err.Error()
			return res
		}
		switch {
		case outbound.ModeFor(cat) == outbound.ModeDirect:
			tr.Proxy = nil
			res.ProxyUsed = "直连"
		case u != nil:
			tr.Proxy = outbound.ProxyWithCDN(u)
			res.ProxyUsed = outbound.RedactProxy(u)
		default:
			tr.Proxy = outbound.EnvironmentProxyWithCDN()
			res.ProxyUsed = "环境变量 HTTP(S)_PROXY"
		}
	case strings.TrimSpace(proxyURL) != "":
		u, err := outbound.ParseProxyURL(strings.TrimSpace(proxyURL))
		if err != nil {
			res.Error = err.Error()
			return res
		}
		tr.Proxy = http.ProxyURL(u)
		res.ProxyUsed = outbound.RedactProxy(u)
	default:
		tr.Proxy = nil
		res.Target = proxyProbeZen + "（直连）"
		res.ProxyUsed = "直连"
	}
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	req.Header.Set("User-Agent", "4zreark-proxy-test")
	client := &http.Client{Timeout: 10 * time.Second, Transport: tr}
	resp, err := client.Do(req)
	res.LatencyMS = time.Since(start).Milliseconds()
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	res.Status = resp.StatusCode
	if resp.StatusCode == http.StatusOK {
		res.OK = true
	} else {
		res.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
	return res
}
