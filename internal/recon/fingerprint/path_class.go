package fingerprint

import "strings"

// 路径分类扩展名清单（语义三组，见 PathKind）。清单是指纹语义的一部分，
// 不是运维参数——不做配置化，要加扩展名直接改这里。
var (
	// pathPageExts 动态页面：裸 token 不能当目标（不是域名），带 scheme 的 URL 可以探测
	// （登录页/业务页有指纹价值）
	pathPageExts = map[string]bool{
		"html": true, "htm": true, "shtml": true,
		"asp": true, "aspx": true, "jsp": true, "php": true,
		"do": true, "action": true, "cgi": true,
	}
	// pathStaticExts 静态资源：探测它们没有任何指纹价值（title/备案号/链接全空），
	// 无论裸 token 还是带 scheme 的 URL 一律不是指纹目标
	pathStaticExts = map[string]bool{
		// 样式/脚本/数据
		"css": true, "js": true, "mjs": true, "map": true, "json": true, "xml": true, "txt": true, "rss": true,
		// 图片/图标
		"png": true, "jpg": true, "jpeg": true, "gif": true, "webp": true,
		"svg": true, "ico": true, "bmp": true,
		// 字体
		"woff": true, "woff2": true, "ttf": true, "otf": true, "eot": true,
		// 媒体
		"mp4": true, "mp3": true, "webm": true, "flv": true, "wav": true,
		// 文档
		"pdf": true, "doc": true, "docx": true, "xls": true, "xlsx": true, "ppt": true, "pptx": true, "csv": true,
		// 压缩/备份
		"zip": true, "rar": true, "7z": true, "gz": true, "tar": true, "bak": true, "sql": true, "dump": true,
	}
)

// PathKind 按路径最后一段的扩展名分类：返回 "page"（动态页面）/ "static"（静态资源）/
// ""（非文件路径：无扩展名、REST 路径、以斜杠结尾）。
// 只看 path 最后一段，查询串/fragment 不参与判定（/download?file=a.css 不会误判）；
// 大小写不敏感（App.CSS 与 app.css 同判）。
func PathKind(rawPath string) string {
	p := strings.ToLower(strings.TrimSpace(rawPath))
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		p = p[i+1:]
	}
	dot := strings.LastIndexByte(p, '.')
	if dot < 0 {
		return ""
	}
	ext := p[dot+1:]
	if ext == "" {
		return ""
	}
	if pathPageExts[ext] {
		return "page"
	}
	if pathStaticExts[ext] {
		return "static"
	}
	return ""
}
