package fingerprint

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
)

// DecodeBody 导出字符集解码:gb18030/big5/windows-1252 页面转 UTF-8,
// 未知字符集直读 + 有效 UTF-8 兜底。enrich 拿到原始响应体后用本函数
// 得到可匹配文本。
func DecodeBody(raw []byte, contentType string) string {
	return decodeHTMLBody(raw, contentType)
}

// FetchIconHash 导出 favicon mmh3 哈希计算(fofa 风格 icon_hash)。
// 拉取失败返回空串——icon_hash 类规则对该观测不命中,不视为错误。
func FetchIconHash(ctx context.Context, client *http.Client, pageURL string) string {
	return fetchFaviconHash(ctx, client, pageURL)
}

// ObservationFromResponse 从一次已完成的 HTTP 探测构造观测。enrich 已持有
// 响应(不再二次请求页面),这里只做字段整理:头小写化、HeaderText 拼接、
// Set-Cookie 聚合(cookie 字段供 Wappalyzer 系指纹)、body 解码、md5。
// iconHash 由调用方按需用 FetchIconHash 补充(一次额外请求)。
func ObservationFromResponse(rawURL string, resp *http.Response, rawBody []byte, decodedBody string) Observation {
	u, _ := url.Parse(rawURL)
	obs := Observation{
		Status:      resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type"),
		Server:      resp.Header.Get("Server"),
		Body:        decodedBody,
		Headers:     make(map[string]string, len(resp.Header)),
	}
	if u != nil {
		obs.Host = u.Hostname()
		obs.Protocol = strings.ToLower(u.Scheme)
		obs.Path = u.Path
	}
	var headerParts []string
	var cookies []string
	for k, vs := range resp.Header {
		lk := strings.ToLower(k)
		for _, v := range vs {
			headerParts = append(headerParts, k+": "+v)
			if lk == "set-cookie" {
				if idx := strings.Index(v, ";"); idx > 0 {
					cookies = append(cookies, v[:idx])
				} else {
					cookies = append(cookies, v)
				}
			}
		}
		obs.Headers[lk] = strings.Join(vs, ", ")
	}
	obs.HeaderText = strings.Join(headerParts, "\r\n")
	obs.Cookie = strings.Join(cookies, "; ")
	sum := md5.Sum(rawBody)
	obs.BodyHash = hex.EncodeToString(sum[:])
	return obs
}
