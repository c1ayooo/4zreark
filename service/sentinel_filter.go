package service

import (
	"fmt"
	"sort"
	"strings"

	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/internal/llm"
	"github.com/c1ayooo/4zreark/repo"
)

// CommitSentinel 过滤与装箱（v0.3 §7.2 / §7.3）。
//
// 原则：规则只判断「值不值得看」，从不判断「是不是安全修复」——
// 判定权只属于模型，规则漏掉的成本远高于多看几眼的成本。

// ShouldSkip 返回是否需要跳过，以及跳过原因（bot/empty/non-code/format）。
func ShouldSkip(c *repo.GitCommit, files []FileChange) (bool, string) {
	if c == nil {
		return true, "empty"
	}
	if isBotAuthor(c.AuthorName, c.AuthorEmail) {
		return true, "bot"
	}
	if c.FilesChanged == 0 || len(files) == 0 {
		return true, "empty"
	}
	if onlyNonCodePaths(files) {
		return true, "non-code"
	}
	if whitespaceOnly(files) {
		return true, "format"
	}
	return false, ""
}

func isBotAuthor(name, email string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	e := strings.ToLower(strings.TrimSpace(email))
	if strings.Contains(n, "[bot]") || strings.HasSuffix(e, "@bots.noreply.github.com") {
		return true
	}
	for _, prefix := range []string{"dependabot", "renovate-bot", "github-actions", "gitlab-ci"} {
		if strings.HasPrefix(n, prefix) || strings.HasPrefix(e, prefix) {
			return true
		}
	}
	return false
}

// 非代码路径：文档、锁文件、依赖目录、测试数据、翻译文件。
var nonCodePrefixes = []string{"docs/", "vendor/", "third_party/", "testdata/", "node_modules/"}
var nonCodeSuffixes = []string{".md", ".markdown", ".lock", ".po", ".pot", ".sum"}

func onlyNonCodePaths(files []FileChange) bool {
	for _, f := range files {
		p := strings.ToLower(f.Path)
		matched := false
		for _, pre := range nonCodePrefixes {
			if strings.HasPrefix(p, pre) {
				matched = true
				break
			}
		}
		if !matched {
			for _, suf := range nonCodeSuffixes {
				if strings.HasSuffix(p, suf) {
					matched = true
					break
				}
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func whitespaceOnly(files []FileChange) bool {
	changed := 0
	for _, f := range files {
		for _, h := range f.Hunks {
			for _, line := range h.Lines {
				if !strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "-") {
					continue
				}
				if strings.HasPrefix(line, "+++") || strings.HasPrefix(line, "---") {
					continue
				}
				changed++
				if strings.TrimSpace(line[1:]) != "" {
					return false
				}
			}
		}
	}
	return changed > 0
}

// pathScore 是路径敏感度打分（0~100），决定装箱顺序。
func pathScore(path string) int {
	p := strings.ToLower(path)
	type rule struct {
		keys  []string
		score int
	}
	rules := []rule{
		{[]string{"crypto/", "tls/", "ssl/", "auth/", "oauth/", "jwt/"}, 100},
		{[]string{"parser/", "decode/", "encode/", "codec/", "proto/", "serial/"}, 90},
		{[]string{"archive/", "zip/", "tar/", "gzip/", "xml/", "json/", "yaml/"}, 85},
		{[]string{"net/", "http/", "http2/", "socket/", "dns/"}, 80},
		{[]string{"vm/", "interp/", "eval/", "compile/", "bytecode/"}, 75},
		{[]string{"mem/", "alloc/", "heap/", "gc/"}, 70},
		{[]string{"vendor/", "third_party/"}, 0},
		{[]string{"_test.go", "tests/", "testdata/"}, 10},
	}
	for _, r := range rules {
		for _, k := range r.keys {
			if strings.Contains(p, k) {
				return r.score
			}
		}
	}
	for _, ext := range []string{".c", ".h", ".cc", ".cpp", ".go", ".rs", ".py", ".php", ".java", ".js", ".ts"} {
		if strings.HasSuffix(p, ext) {
			return 50
		}
	}
	return 20
}

// PrepPack 是送给模型的装箱结果。
type PrepPack struct {
	Files         []FileChange
	Prompt        string
	TokenEstimate int
	TrimmedHunks  int
}

// BuildPack 按敏感度排序装箱：单 hunk 超限只保留变更点前后各 15 行，
// 预算用尽即停，但文件清单与增删行数始终完整保留。
func BuildPack(c *repo.GitCommit, files []FileChange, cfg config.SentinelConfig) *PrepPack {
	cfg.Normalize()

	sorted := make([]FileChange, len(files))
	copy(sorted, files)
	sort.SliceStable(sorted, func(i, j int) bool {
		return pathScore(sorted[i].Path) > pathScore(sorted[j].Path)
	})

	var body strings.Builder
	budget := cfg.TokenBudget
	used := 0
	trimmed := 0
	for _, f := range sorted {
		header := fmt.Sprintf("### %s (+%d -%d)\n", f.Path, f.Additions, f.Deletions)
		if used+llm.EstimateTokens(header) > budget {
			trimmed++
			break
		}
		body.WriteString(header)
		used += llm.EstimateTokens(header)

		for _, h := range f.Hunks {
			snippet := trimHunk(h, cfg.MaxHunkLines)
			if used+llm.EstimateTokens(snippet) > budget {
				trimmed++
				break
			}
			body.WriteString(snippet)
			body.WriteString("\n")
			used += llm.EstimateTokens(snippet)
		}
	}

	manifest := buildManifest(c, files)
	prompt := manifest + "\n## 差异片段\n" + body.String()
	return &PrepPack{
		Files:         sorted,
		Prompt:        prompt,
		TokenEstimate: llm.EstimateTokens(prompt),
		TrimmedHunks:  trimmed,
	}
}

// buildManifest 生成始终完整的文件清单与规模统计。
func buildManifest(c *repo.GitCommit, files []FileChange) string {
	var b strings.Builder
	sha := ""
	subject := ""
	if c != nil {
		sha = shortSHA(c.SHA)
		subject = c.Subject
	}
	fmt.Fprintf(&b, "## 提交 %s %s\n", sha, subject)
	fmt.Fprintf(&b, "文件数 %d，新增 %d 行，删除 %d 行\n", len(files), c.Additions, c.Deletions)
	b.WriteString("## 文件清单\n")
	limit := len(files)
	if limit > 80 {
		limit = 80
	}
	for _, f := range files[:limit] {
		flag := ""
		if f.IsNew {
			flag = " [new]"
		} else if f.IsDeleted {
			flag = " [deleted]"
		}
		fmt.Fprintf(&b, "- %s (+%d -%d)%s\n", f.Path, f.Additions, f.Deletions, flag)
	}
	if len(files) > limit {
		fmt.Fprintf(&b, "- ...其余 %d 个文件省略\n", len(files)-limit)
	}
	return b.String()
}

// trimHunk 把过长的 hunk 裁到变更点前后各 15 行。
func trimHunk(h DiffHunk, maxLines int) string {
	if maxLines <= 0 || len(h.Lines) <= maxLines {
		return h.Header + "\n" + strings.Join(h.Lines, "\n")
	}
	first, last := -1, -1
	for i, line := range h.Lines {
		if (strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++")) ||
			(strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---")) {
			if first < 0 {
				first = i
			}
			last = i
		}
	}
	if first < 0 {
		return h.Header + "\n" + strings.Join(h.Lines[:maxLines], "\n")
	}
	start := first - 15
	if start < 0 {
		start = 0
	}
	end := last + 16
	if end > len(h.Lines) {
		end = len(h.Lines)
	}
	kept := h.Lines[start:end]
	return h.Header + "\n" + strings.Join(kept, "\n")
}
