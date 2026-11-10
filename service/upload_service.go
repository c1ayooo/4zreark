package service

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/c1ayooo/4zreark/repo"
)

// 附件解析：把用户上传的文件变成「模型可读的摘要」。
//
// 设计取舍：
//   - 不解包到磁盘：zip 只做内存遍历，避免 zip-slip 与残留垃圾文件；
//   - 只抽摘要：代码库动辄几 MB，全量塞进 prompt 既超上下文也没意义，
//     真正的价值是目录结构 + 可疑点位置，让模型知道「从哪看起」；
//   - 明确标注不支持的类型：PDF/二进制镜像不假装解析成功，
//     summary 里直说「未解析」，避免模型基于空内容编造结论。

const (
	uploadMaxFiles    = 200       // zip 内最多解析的文件数
	uploadMaxFileRead = 256 << 10 // 单文件最多读 256KB
	uploadMaxSummary  = 28000     // 摘要字符上限
	uploadTextPreview = 3         // 每个代码文件抽几行可疑片段
)

var codeExts = map[string]bool{
	".java": true, ".kt": true, ".php": true, ".go": true, ".py": true,
	".js": true, ".ts": true, ".tsx": true, ".jsx": true, ".rb": true,
	".c": true, ".cc": true, ".cpp": true, ".h": true, ".hpp": true,
	".rs": true, ".lua": true, ".sh": true, ".pl": true, ".jsp": true,
	".xml": true, ".yml": true, ".yaml": true, ".json": true, ".toml": true,
	".properties": true, ".env": true, ".sql": true, ".gradle": true,
}

// 命中这些片段说明「值得优先看」，不是漏洞结论，只是检索线索。
var riskyPatterns = []string{
	"unserialize(", "ObjectInputStream", "readObject", "readResolve", "XMLDecoder",
	"Runtime.getRuntime", "ProcessBuilder", "system(", "popen(", "exec(",
	"eval(", "assert(", "memcpy(", "strcpy(", "sprintf(", "strcat(",
	"base64_decode(", "pickle.loads", "yaml.load(", "allowed_classes",
	"enableDefaultTyping", "resolveClass", "innerHTML", "document.write",
}

type UploadFileInfo struct {
	Path string `json:"path"`
	Size int64  `json:"size"`
	Note string `json:"note,omitempty"`
}

// SaveChatUpload 解析上传内容并落库。data 已在 handler 侧做过大小限制。
func SaveChatUpload(ctx context.Context, userID, filename string, data []byte) (*repo.ChatUpload, error) {
	filename = strings.TrimSpace(filepath.Base(filename))
	if filename == "" || filename == "." || filename == "/" {
		filename = "upload.bin"
	}
	if len(data) == 0 {
		return nil, errors.New("文件为空")
	}

	kind, summary, files := analyzeUpload(filename, data)
	if len([]rune(summary)) > uploadMaxSummary {
		summary = string([]rune(summary)[:uploadMaxSummary]) + "\n…（摘要已截断）"
	}
	filesJSON, _ := json.Marshal(files)

	upload := &repo.ChatUpload{
		UserID:  userID,
		Name:    filename,
		Size:    int64(len(data)),
		Kind:    kind,
		Summary: summary,
		Files:   filesJSON,
	}
	if err := repo.Default().Chat().CreateUpload(ctx, upload); err != nil {
		return nil, err
	}

	// 原文件留一份：排查「为什么模型没看到某个文件」时，能对照原始输入。
	// 失败不影响主流程（摘要已经进库）。
	if dir := uploadDir(); dir != "" {
		_ = os.MkdirAll(dir, 0o750)
		_ = os.WriteFile(filepath.Join(dir, upload.ID+"-"+filename), data, 0o640)
	}
	return upload, nil
}

func uploadDir() string {
	// 与 data/ 同级，便于备份和清理；测试环境可能没有该目录，失败即跳过。
	if wd, err := os.Getwd(); err == nil {
		return filepath.Join(wd, "data", "chat-uploads")
	}
	return ""
}

func analyzeUpload(name string, data []byte) (kind, summary string, files []UploadFileInfo) {
	ext := strings.ToLower(filepath.Ext(name))
	switch {
	case ext == ".zip":
		return analyzeZip(data)
	case ext == ".pdf":
		return "pdf", "PDF 文件已接收，但当前没有 PDF 文本抽取能力，未解析内容。" +
			"如需分析，请上传解压后的源码或相关文本。", nil
	case isMarkdownExt(ext):
		// 利用方法/复现指南常见载体：按 Markdown 章节解析，而不是只截前 2000 字符。
		return analyzeMarkdown(name, data)
	case isTextLike(ext, data):
		return analyzeText(name, data)
	default:
		return "binary", fmt.Sprintf("二进制文件（%s，%s）已接收，未做内容解析。"+
			"如需分析二进制，请上传反编译结果或 ASAN 日志。", ext, humanSize(int64(len(data)))), nil
	}
}

func isTextLike(ext string, data []byte) bool {
	if codeExts[ext] {
		return true
	}
	if ext == ".txt" || ext == ".md" || ext == ".log" || ext == ".diff" || ext == ".patch" || ext == ".csv" {
		return true
	}
	// 无扩展名或未知扩展名：用内容判断，前 4KB 无 NUL 且是合法 UTF-8 就当文本。
	probe := data
	if len(probe) > 4096 {
		probe = probe[:4096]
	}
	if bytes.IndexByte(probe, 0) >= 0 {
		return false
	}
	return utf8.Valid(probe)
}

func isMarkdownExt(ext string) bool {
	return ext == ".md" || ext == ".markdown"
}

// analyzeMarkdown 解析 Markdown 结构：章节标题、前置条件、利用/复现步骤、
// curl/HTTP 请求示例、URL 路径与 CVE。原文仍保留开头片段供模型核对写法。
func analyzeMarkdown(name string, data []byte) (string, string, []UploadFileInfo) {
	text := string(data)
	if len(text) > uploadMaxFileRead {
		text = text[:uploadMaxFileRead]
	}
	guide := parseExploitMarkdown(name, text)

	var b strings.Builder
	fmt.Fprintf(&b, "Markdown 文档 %s，%d 行，%s。\n", name,
		len(strings.Split(text, "\n")), humanSize(int64(len(data))))
	if s := guide.UploadSummary(); s != "" {
		b.WriteString("结构化解析（章节/前置条件/利用步骤/请求路径/CVE）：\n")
		b.WriteString(s)
	} else {
		b.WriteString("未识别到「利用步骤/前置条件/请求示例」等章节，按原文摘要。\n")
	}
	for i, req := range guide.Requests {
		if i >= 2 {
			break
		}
		b.WriteString("请求示例原文：\n```\n" + req + "\n```\n")
	}

	head := text
	if len(head) > 2000 {
		head = head[:2000]
	}
	b.WriteString("文件开头：\n```\n" + head + "\n```\n")
	return "markdown", b.String(), []UploadFileInfo{{Path: name, Size: int64(len(data))}}
}

func analyzeText(name string, data []byte) (string, string, []UploadFileInfo) {
	text := string(data)
	if len(text) > uploadMaxFileRead {
		text = text[:uploadMaxFileRead]
	}
	lines := strings.Split(text, "\n")

	var b strings.Builder
	fmt.Fprintf(&b, "文本文件 %s，%d 行，%s。\n", name, len(lines), humanSize(int64(len(data))))

	// 顶层声明：快速告诉模型这是什么项目
	decls := make([]string, 0, 8)
	for _, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "package ") || strings.HasPrefix(t, "import ") ||
			strings.HasPrefix(t, "using ") || strings.HasPrefix(t, "#include") ||
			strings.HasPrefix(t, "require") || strings.HasPrefix(t, "from ") {
			if len(decls) < 12 {
				decls = append(decls, t)
			}
		}
	}
	if len(decls) > 0 {
		b.WriteString("声明与依赖：\n")
		for _, d := range decls {
			b.WriteString("  " + d + "\n")
		}
	}

	hits := scanRiskyLines(lines, 20)
	if len(hits) > 0 {
		b.WriteString("可疑片段（仅检索线索，非结论）：\n")
		for _, h := range hits {
			b.WriteString(h + "\n")
		}
	} else {
		b.WriteString("未命中常见危险调用。\n")
	}

	// 头部原文：让模型看到真实写法
	head := text
	if len(head) > 2000 {
		head = head[:2000]
	}
	b.WriteString("文件开头：\n```\n" + head + "\n```\n")

	return "text", b.String(), []UploadFileInfo{{Path: name, Size: int64(len(data))}}
}

func analyzeZip(data []byte) (string, string, []UploadFileInfo) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "zip", "ZIP 文件已接收，但解包失败（可能损坏或加密）：" + err.Error(), nil
	}

	var b strings.Builder
	fmt.Fprintf(&b, "ZIP 包，共 %d 个条目（%s）。\n", len(zr.File), humanSize(int64(len(data))))

	files := make([]UploadFileInfo, 0, 16)
	codeFiles := make([]*zip.File, 0, 16)
	mdFiles := make([]*zip.File, 0, 8)
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if len(files) >= uploadMaxFiles {
			break
		}
		files = append(files, UploadFileInfo{Path: f.Name, Size: int64(f.UncompressedSize64)})
		ext := strings.ToLower(filepath.Ext(f.Name))
		if codeExts[ext] {
			codeFiles = append(codeFiles, f)
		} else if isMarkdownExt(ext) {
			mdFiles = append(mdFiles, f)
		}
	}

	// 目录树（只列目录，文件太多时列文件会淹没重点）
	dirs := make(map[string]bool)
	for _, f := range files {
		d := filepath.Dir(f.Path)
		if d != "." && d != "" {
			dirs[d] = true
		}
	}
	if len(dirs) > 0 {
		b.WriteString("目录结构：\n")
		n := 0
		for d := range dirs {
			if n >= 30 {
				b.WriteString("  …\n")
				break
			}
			b.WriteString("  " + d + "/\n")
			n++
		}
	}

	b.WriteString("关键文件与可疑片段：\n")
	shown := 0
	for _, f := range codeFiles {
		if shown >= 12 {
			b.WriteString("  …（其余代码文件省略）\n")
			break
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		content, err := io.ReadAll(io.LimitReader(rc, uploadMaxFileRead))
		_ = rc.Close()
		if err != nil {
			continue
		}
		if bytes.IndexByte(content, 0) >= 0 {
			continue // 二进制，跳过
		}
		lines := strings.Split(string(content), "\n")
		hits := scanRiskyLines(lines, uploadTextPreview)
		if len(hits) == 0 {
			continue
		}
		b.WriteString("  " + f.Name + ":\n")
		for _, h := range hits {
			b.WriteString("  " + h + "\n")
		}
		shown++
	}
	if shown == 0 {
		b.WriteString("  未在代码文件中命中常见危险调用。\n")
	}

	// Markdown 文档：以前只在目录列表出现、内容从不读取；利用方法/复现指南
	// 常常恰好放在 README.md / exploit.md 里，这里按章节解析后写进摘要。
	if len(mdFiles) > 0 {
		b.WriteString("Markdown 文档（已解析利用方法/复现步骤）：\n")
		mdShown := 0
		for _, f := range mdFiles {
			if mdShown >= 8 {
				b.WriteString("  …（其余 Markdown 文档省略）\n")
				break
			}
			rc, err := f.Open()
			if err != nil {
				continue
			}
			content, err := io.ReadAll(io.LimitReader(rc, uploadMaxFileRead))
			_ = rc.Close()
			if err != nil || bytes.IndexByte(content, 0) >= 0 {
				continue
			}
			guide := parseExploitMarkdown(f.Name, string(content))
			b.WriteString("  " + f.Name + "：\n")
			if guide.IsEmpty() {
				b.WriteString("    未识别到「利用步骤/前置条件/请求示例」等章节。\n")
			} else {
				summary := strings.TrimRight(guide.UploadSummary(), "\n")
				for _, line := range strings.Split(summary, "\n") {
					b.WriteString("    " + line + "\n")
				}
			}
			mdShown++
		}
	}

	fmt.Fprintf(&b, "（解析上限：%d 个文件、单文件 %s）\n", uploadMaxFiles, humanSize(uploadMaxFileRead))
	return "zip", b.String(), files
}

// scanRiskyLines 返回带行号的可疑行，最多 limit 条。
func scanRiskyLines(lines []string, limit int) []string {
	out := make([]string, 0, limit)
	for i, line := range lines {
		lower := strings.ToLower(line)
		for _, p := range riskyPatterns {
			if strings.Contains(lower, strings.ToLower(p)) {
				trimmed := strings.TrimSpace(line)
				if len([]rune(trimmed)) > 200 {
					trimmed = string([]rune(trimmed)[:200]) + "…"
				}
				out = append(out, fmt.Sprintf("L%d: %s", i+1, trimmed))
				break
			}
		}
		if len(out) >= limit {
			break
		}
	}
	return out
}
