// Package directhttp 提供「服务自身出站」的统一直连 Transport。
//
// 设计约束：出站代理仅服务于渗透工具集（executor 子进程环境注入 / httpprobe /
// githubsearch 等渗透流量），大模型 API（对话/嵌入/rerank）与知识检索基础设施
// 一律直连，不随进程环境变量 http_proxy/HTTPS_PROXY 走代理——避免渗透启用代理
// 时 LLM/向量检索被代理链路单点拖垮。
package directhttp

import (
	"net/http"
	"net/url"
	"sync"
)

var (
	once      sync.Once
	transport http.RoundTripper
)

// Transport 返回克隆自 http.DefaultTransport 的直连 Transport（Proxy 恒为空，
// 忽略环境代理）。可安全作为各 HTTP 客户端的基础 transport。
func Transport() http.RoundTripper {
	once.Do(func() {
		base := http.DefaultTransport.(*http.Transport).Clone()
		base.Proxy = func(*http.Request) (*url.URL, error) { return nil, nil }
		transport = base
	})
	return transport
}

// TransportFor 按开关选择传输层：useProxy=true 使用 http.DefaultTransport
// （走环境 http_proxy/HTTPS_PROXY，供海外 API 通道）；false 返回直连 Transport。
func TransportFor(useProxy bool) http.RoundTripper {
	if useProxy {
		return http.DefaultTransport
	}
	return Transport()
}

// Client 返回携带直连 Transport 的 HTTP 客户端。
// base 非 nil 且已显式携带 Transport 时保留原 Transport（如测试注入），否则替换为直连。
func Client(base *http.Client) *http.Client {
	if base == nil {
		base = &http.Client{}
	}
	cloned := *base
	if cloned.Transport == nil {
		cloned.Transport = Transport()
	}
	return &cloned
}
