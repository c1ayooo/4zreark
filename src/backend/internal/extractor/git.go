package extractor

// git 提取器：nuclei 命中 git-config 模板（/.git/config 泄露）后，解析 ini 配置里的
// [remote] url（常内嵌 https://user:pass@host 凭据）与 [credentials] 条目，并尝试
// 下载 .git/HEAD + .git/config 归档（「克隆」的轻量版：抓头部文件而非全量 objects）。

import (
	"context"
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"
)

// gitExtractor 处理模板 id git-config / exposed-gitmodules / exposed-credentials 等
// .git 系配置泄露（gitmodules 含子模块 url，同样可嵌入凭据）。
type gitExtractor struct{}

var (
	// gitURLRe 匹配 url = https://... 行。
	gitURLRe = regexp.MustCompile(`(?m)^\s*url\s*=\s*"?([^"\s]+)"?\s*$`)
	// gitCredentialRe 匹配 [credential] / [credentials] 段的行对。
	gitCredentialRe = regexp.MustCompile(`(?m)^\s*(username|password|helper)\s*=\s*(.+?)\s*$`)
)

func (gitExtractor) Supports(templateID string) bool {
	switch templateID {
	case "git-config", "exposed-gitmodules", "exposed-gitignore", "exposed-svn", "exposed-vscode":
		return true
	}
	return false
}

// gitRepoInfo 提取出的仓库配置与内嵌凭据。
type gitRepoInfo struct {
	RemoteURL     string `json:"remote_url,omitempty"`
	HasCredential bool   `json:"has_credential"`
	Credential    string `json:"credential,omitempty"` // 内嵌在 URL 里的 user:pass（data 字段明文保留，产品决策）
	Username      string `json:"username,omitempty"`
	Password      string `json:"password,omitempty"`
	RepoPath      string `json:"repo_path,omitempty"` // .git 相对根路径（/…/）
}

func (gitExtractor) Extract(ctx context.Context, c *Ctx) (*Finding, error) {
	if c.TemplateID != "git-config" {
		// 其他 .git 系模板目前只做检测标记，无统一 ini 结构可解析。
		return nil, nil
	}
	body := bodyFromResponse(c.Response)
	out := gitRepoInfo{}
	// 模板自带 extractor 提取的片段（url 内嵌凭据 / basic auth / pass =）优先。
	for _, ex := range c.Extracted {
		ex = strings.TrimSpace(ex)
		if ex == "" {
			continue
		}
		if strings.HasPrefix(ex, "url ") || strings.Contains(ex, "://") && strings.Contains(ex, "@") {
			out.RemoteURL = ex
			out.HasCredential = true
			break
		}
		if strings.Contains(ex, "://") {
			out.RemoteURL = ex
		}
	}
	// 从 config body 解析 [remote] url（Extracted 为空时的兜底）。
	if out.RemoteURL == "" && strings.Contains(body, "[remote") {
		if m := gitURLRe.FindStringSubmatch(body); len(m) > 1 {
			out.RemoteURL = m[1]
		}
	}
	// [remote] url 内嵌凭据剥离：url 即 https://user:pass@host/repo
	if i := strings.Index(out.RemoteURL, "://"); i >= 0 {
		rest := out.RemoteURL[i+3:]
		if at := strings.Index(rest, "@"); at >= 0 {
			out.Credential = rest[:at]
			out.HasCredential = true
		}
	}
	// [credential] 段：username/password 行（模板提取组 signal）
	for _, m := range gitCredentialRe.FindAllStringSubmatch(body, -1) {
		switch strings.ToLower(m[1]) {
		case "username":
			out.Username = m[2]
		case "password":
			out.Password = m[2]
		}
		if out.Username != "" || out.Password != "" {
			out.HasCredential = true
		}
	}
	out.RepoPath = gitRepoBase(c.MatchURL)
	if out.RemoteURL == "" && !out.HasCredential && out.RepoPath == "" {
		return nil, nil // 命中但无可用信息（配置空/非 git 内容）
	}
	// 归档 .git/HEAD + config（export 目录不存在时跳过，不报错）。
	archived := ""
	if c.DownloadDir != "" && c.HTTPClient != nil && c.MatchURL != "" {
		archived = gitArchiveFiles(ctx, c)
	}
	data, _ := json.Marshal(out)
	return &Finding{
		ProjectID:   c.ProjectID,
		Domain:      c.Domain,
		Target:      firstNonEmpty(c.MatchURL, c.Target),
		Category:    "git_repo",
		Kind:        "git_config",
		Data:        string(data),
		RawEvidence: gitEvidence(body, out),
		FilePath:    archived,
	}, nil
}

// gitRepoBase 从命中 URL 提取 /.git 仓库根（如 https://h/x/.git/... → x）。
func gitRepoBase(matchURL string) string {
	if matchURL == "" {
		return ""
	}
	idx := strings.Index(matchURL, "/.git/")
	if idx < 0 {
		return ""
	}
	base := matchURL[:idx]
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	return base
}

// gitArchiveFiles 归档 .git 关键索引文件到 <DownloadDir>/git/<repo>/：
// HEAD + config + packed-refs + refs 首层（master/main 分支头）+ objects 索引。
// 轻量版「克隆」：抓索引与引用文件而非全量 objects（全量 git clone 超出纯 Go 单发
// 下载的合理边界，需要完整 objects 时可由人工/后续工具基于已归档 refs 精准拉取）。
func gitArchiveFiles(ctx context.Context, c *Ctx) string {
	baseURL := c.MatchURL
	if !strings.HasSuffix(baseURL, "/.git/config") {
		return ""
	}
	root := strings.TrimSuffix(baseURL, ".git/config")
	dir := filepath.Join(c.DownloadDir, "git", gitRepoBase(c.MatchURL))
	files := []string{
		"HEAD",
		"config",
		"packed-refs",
		"info/packs",
		"refs/heads/master",
		"refs/heads/main",
		"objects/info/packs",
	}
	ok := false
	for _, p := range files {
		raw := root + ".git/" + p
		if _, _, _, err := downloadAndArchive(ctx, c.HTTPClient, raw, dir); err == nil {
			ok = true
		}
	}
	if !ok {
		return ""
	}
	return dir
}

func gitEvidence(body string, out gitRepoInfo) string {
	var b strings.Builder
	b.WriteString(".git/config 命中")
	if out.RemoteURL != "" {
		b.WriteString(" → " + out.RemoteURL)
	}
	if out.HasCredential {
		b.WriteString("（含凭据）")
	}
	if out.RepoPath != "" {
		b.WriteString(" repo=" + out.RepoPath)
	}
	return b.String()
}
