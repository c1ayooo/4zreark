// Package sourcemap 解析 JavaScript source map v3 并还原原始源码。
//
// 工程取舍：webpack/ts-loader 等主流工具产出的 map 绝大多数带
// sourcesContent（完整原始源码内嵌在 map 里），直接落盘即还原；
// 缺 sourcesContent 的 map 只能靠 mappings（位置映射表）反解出
// 「哪个生成位置对应哪个源文件的哪行」，源码内容本身不在 map 里，
// 反解不出可用文本——因此本包不做 mappings/VLQ 反解，只做
// sourcesContent 还原 + sources 路径清单（目录结构泄露同样有侦察价值）。
package sourcemap

import (
	"encoding/json"
	"fmt"
	"path"
	"strings"
)

// File 是 source map v3 的 JSON 结构（只取还原所需的字段）。
type File struct {
	Version        int      `json:"version"`
	File           string   `json:"file,omitempty"`
	SourceRoot     string   `json:"sourceRoot,omitempty"`
	Sources        []string `json:"sources"`
	SourcesContent []string `json:"sourcesContent,omitempty"`
	Names          []string `json:"names,omitempty"`
	Mappings       string   `json:"mappings,omitempty"`

	// SourcesWithContent 在 Parse 时对齐：与 Sources 同长，true 表示
	// 该下标有可还原的源码内容。
	SourcesWithContent []bool `json:"-"`
}

// Parse 解析 source map JSON。宽松校验：version 非 3 也接受（上游工具
// 偶有 3.x 或缺 version 的产物），只要能读出 sources 就算有效。
func Parse(data []byte) (*File, error) {
	var f File
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("sourcemap JSON 解析失败: %w", err)
	}
	if len(f.Sources) == 0 {
		return nil, fmt.Errorf("sourcemap 无 sources")
	}
	// 部分工具把 sourcesContent 置成等长 null 数组，归一成缺席语义。
	if len(f.SourcesContent) != len(f.Sources) {
		f.SourcesContent = nil
	}
	f.SourcesWithContent = make([]bool, len(f.Sources))
	for i, c := range f.SourcesContent {
		f.SourcesWithContent[i] = strings.TrimSpace(c) != ""
	}
	return &f, nil
}

// Restored 是一个还原出的原始源文件。
type Restored struct {
	// Path 是还原后的展示路径（sourceRoot 已拼接，webpack 前缀已清洗）。
	Path string
	// Name 是落盘用的安全文件名（展平目录、清洗分隔符）。
	Name string
	// Content 是原始源码。
	Content string
}

// Restore 返回所有带 sourcesContent 的原始源文件；没有可还原内容时返回 nil。
// 顺序与 map 里的 sources 一致。
func (f *File) Restore() []Restored {
	if f == nil {
		return nil
	}
	out := make([]Restored, 0, len(f.Sources))
	for i, c := range f.SourcesContent {
		if strings.TrimSpace(c) == "" || i >= len(f.Sources) {
			continue
		}
		p := f.SourcePath(i)
		out = append(out, Restored{
			Path:    p,
			Name:    SafeFileName(i, p),
			Content: c,
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// SourcePath 返回第 i 个 source 的展示路径：拼 sourceRoot、清洗
// webpack:// 协议前缀与 !loader 前缀（webpack://app/./src/index.js → src/index.js）。
func (f *File) SourcePath(i int) string {
	if i >= len(f.Sources) {
		return ""
	}
	s := f.Sources[i]
	if s == "" || s == "<anon>" || s == "<stdin>" {
		return fmt.Sprintf("source-%d", i)
	}
	// webpack 协议：webpack://[namespace/]path，取最后一层协议后的路径
	if idx := strings.LastIndex(s, "://"); idx >= 0 {
		s = s[idx+3:]
		// 跳过 namespace（webpack://app/./src/x.js 的 app）
		if slash := strings.Index(s, "/"); slash >= 0 {
			s = s[slash+1:]
		} else {
			s = ""
		}
	}
	// loader 链：resource 与 loader 用 ! 分隔（./src/a.vue!babel-loader 或
	// !!vue-loader!./src/a.vue），取含路径分隔符的段作为真实资源；退化取末段。
	if strings.Contains(s, "!") {
		picked := ""
		for _, seg := range strings.Split(s, "!") {
			if strings.Contains(seg, "/") {
				picked = seg
				break
			}
		}
		if picked == "" {
			segs := strings.Split(s, "!")
			picked = segs[len(segs)-1]
		}
		s = picked
	}
	// 循环剥 ../ 与 ./：展平相对深度，防路径穿越落盘
	for strings.HasPrefix(s, "../") || strings.HasPrefix(s, "./") || strings.HasPrefix(s, "/") {
		s = strings.TrimPrefix(s, "../")
		s = strings.TrimPrefix(s, "./")
		s = strings.TrimPrefix(s, "/")
	}
	if s == "" {
		return fmt.Sprintf("source-%d", i)
	}
	if f.SourceRoot != "" {
		s = path.Join(f.SourceRoot, s)
	}
	return s
}

// SourcePaths 返回全部 source 的展示路径（含无内容的——目录结构泄露
// 本身是侦察信息：暴露 src 布局、构建产物包含的后端路径等）。
func (f *File) SourcePaths() []string {
	if f == nil {
		return nil
	}
	out := make([]string, 0, len(f.Sources))
	for i := range f.Sources {
		out = append(out, f.SourcePath(i))
	}
	return out
}

// RestoredCount 返回可还原源码的文件数。
func (f *File) RestoredCount() int {
	if f == nil {
		return 0
	}
	n := 0
	for _, ok := range f.SourcesWithContent {
		if ok {
			n++
		}
	}
	return n
}

// ExtractSourceMappingURL 从 JS 内容尾部找 sourceMappingURL 注释，
// 返回注释里的引用值（可能是相对路径、绝对路径或 data URI）。
// 注释约定在文件末尾：//# sourceMappingURL=xxx 或旧式 //@ sourceMappingURL=xxx。
func ExtractSourceMappingURL(js string) string {
	// 只看尾部 4KB：bundle 的注释在最后，也避免全量扫描大文件。
	tail := js
	if len(tail) > 4096 {
		tail = tail[len(tail)-4096:]
	}
	for _, marker := range []string{"sourceMappingURL=", "//@ sourceMappingURL=", "//# sourceMappingURL="} {
		idx := strings.LastIndex(tail, marker)
		if idx < 0 {
			continue
		}
		rest := tail[idx+len(marker):]
		end := strings.IndexAny(rest, "\r\n")
		if end >= 0 {
			rest = rest[:end]
		}
		rest = strings.TrimSpace(rest)
		rest = strings.TrimSuffix(rest, "*/")
		rest = strings.TrimSpace(rest)
		if rest != "" {
			return rest
		}
	}
	return ""
}

// IsDataURI 报告 sourceMappingURL 值是否为 data URI（内联 map）。
func IsDataURI(ref string) bool {
	return strings.HasPrefix(ref, "data:application/json")
}

// SafeFileName 把 source 路径转成落盘安全文件名：序号前缀防撞名，
// 展平目录、清洗非法字符，保留原文件名便于 nuclei 命中时可读。
func SafeFileName(index int, sourcePath string) string {
	base := path.Base(sourcePath)
	if base == "" || base == "." || base == "/" {
		base = "source"
	}
	var b strings.Builder
	for _, r := range base {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	name := b.String()
	if len(name) > 64 {
		ext := path.Ext(name)
		name = name[:64-len(ext)] + ext
	}
	return fmt.Sprintf("%03d-%s", index, name)
}
