package scope

import (
	"net/url"
	"strings"
)

// staticExts 是「不当作资产路径入库」的静态资源扩展名。
// JS 刻意不在此列：JS 里的接口和路由是侦察目标，必须保留；
// CSS/图片/字体/媒体只占结果表，入库前丢掉。
var staticExts = map[string]struct{}{
	"css": {}, "map": {}, "wasm": {},
	"png": {}, "jpg": {}, "jpeg": {}, "gif": {}, "svg": {}, "ico": {},
	"webp": {}, "avif": {}, "bmp": {}, "tiff": {},
	"woff": {}, "woff2": {}, "ttf": {}, "otf": {}, "eot": {},
	"mp4": {}, "mp3": {}, "wav": {}, "webm": {}, "ogg": {},
}

// IsStaticAsset 判断 URL 是否指向静态资源。
// 只看路径扩展名；查询串里的 format=jpeg 这类 CDN 参数也覆盖到，
// 因为取扩展名时会先在 '%'、'@'、'?' 处截断。
func IsStaticAsset(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}

	path := raw
	if u, err := url.Parse(raw); err == nil && u.Path != "" {
		path = u.Path
	}
	path = strings.ToLower(path)

	// 取最后一个路径段，处理 .png@format=jpeg 、.png%5c 这类变体
	if i := strings.LastIndex(path, "/"); i >= 0 {
		path = path[i+1:]
	}
	for _, sep := range []string{"?", "#", "@", "%"} {
		if i := strings.Index(path, sep); i >= 0 {
			path = path[:i]
		}
	}
	dot := strings.LastIndex(path, ".")
	if dot < 0 || dot == len(path)-1 {
		return false
	}
	_, ok := staticExts[path[dot+1:]]
	return ok
}

// IsNoisyCrawlerURL 过滤 jsluice/Katana 从 JS 字符串里抽出的明显噪声：
// 转义 HTML、内部部署路径、超长查询串。真实 API 路径不会包含这些特征。
func IsNoisyCrawlerURL(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	if len(raw) > 2048 {
		return true
	}
	lower := strings.ToLower(raw)
	for _, marker := range []string{"%5c", "\\u003", "%3c", "%3e", "%22", "%27"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	for _, marker := range []string{"/docker/", "/appdatas/", "/opt/meituan/"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// interfaceSegments 是路径里常见的接口命名段。只认完整路径段，避免把
// /restaurant、/apiary 这类普通页面误判成接口。
var interfaceSegments = map[string]struct{}{
	"api": {}, "ajax": {}, "graphql": {}, "gql": {}, "rest": {}, "rpc": {},
	"json": {}, "openapi": {}, "swagger": {}, "gateway": {},
}

// InterfaceReason 判断一条 URL 是否像接口地址，返回命中原因；空字符串表示不像。
//
// 判定刻意不依赖 /api 前缀：很多站点的接口是 /gateway/...、/graphql、/data/...，
// 或者只是一个带查询串的普通路径。缺少 content-type/tag 的历史记录，
// 仅凭 URL 也能命中查询串与路径段。
func InterfaceReason(rawURL, method, contentType, attribute string) string {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "POST", "PUT", "PATCH", "DELETE":
		return "method"
	}
	ct := strings.ToLower(contentType)
	if strings.Contains(ct, "json") || strings.Contains(ct, "xml") {
		return "content_type"
	}
	switch strings.ToLower(strings.TrimSpace(attribute)) {
	case "jsluice-fetch", "jsluice-xhr", "jsluice-ajax", "jsluice-axios":
		return "jsluice"
	}

	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return ""
	}
	if u.RawQuery != "" {
		return "query"
	}
	path := strings.ToLower(u.Path)
	if strings.HasSuffix(path, ".json") {
		return "path"
	}
	for _, seg := range strings.Split(path, "/") {
		if _, ok := interfaceSegments[seg]; ok {
			return "path"
		}
	}
	return ""
}
