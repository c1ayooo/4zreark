package service

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/c1ayooo/4zreark/internal/useragent"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/repo"
)

// GitHub 仓库种子展开（P1b）：
//   URL → owner/repo → 默认分支文件树 → 少量文本文件 → 提取域名 → 复用域名展开。
//
// 只调用固定主机 api.github.com / raw.githubusercontent.com；token 只发给 api.github.com，
// 不随 raw 文件请求泄露。仓库私有时 raw 取不到，会给出 warning 而不是静默空目标。

const (
	repoMaxFiles   = 40
	repoMaxDomains = 300
	repoMaxFileKB  = 512
)

var (
	repoURLPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	// 文本里出现的主机名；末尾 TLD 再做文件扩展名过滤。
	domainInTextPattern = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b`)

	// 允许扫描的文本文件扩展名。
	repoTextExt = map[string]bool{
		".md": true, ".txt": true, ".yml": true, ".yaml": true, ".json": true,
		".toml": true, ".ini": true, ".cfg": true, ".conf": true, ".env": true,
		".xml": true, ".html": true, ".htm": true, ".js": true, ".ts": true,
		".go": true, ".py": true, ".sh": true, ".properties": true,
	}

	// 正则会把 config.yaml 这类文件名识别成域名，这里过滤掉常见文件后缀。
	notTLD = map[string]bool{
		"md": true, "txt": true, "yml": true, "yaml": true, "json": true,
		"toml": true, "ini": true, "cfg": true, "conf": true, "env": true,
		"xml": true, "html": true, "htm": true, "js": true, "ts": true,
		"go": true, "py": true, "sh": true, "properties": true, "lock": true,
		"sum": true, "mod": true, "png": true, "jpg": true, "jpeg": true,
		"gif": true, "svg": true, "ico": true, "css": true, "map": true,
	}

	repoDomainsFetch = fetchGitHubRepoDomains
	repoGitLabFetch  = fetchGitLabRepoDomains
)

type repoRef struct {
	Owner string
	Name  string
	Host  string
	Kind  string // github / gitlab
}

func parseRepoRef(raw string) (*repoRef, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return nil, invalidSeed("仓库地址必填")
	}
	if !strings.Contains(v, "://") {
		v = "https://" + v
	}
	u, err := url.Parse(v)
	if err != nil {
		return nil, invalidSeed("仓库地址不合法: %s", raw)
	}
	host := strings.ToLower(u.Hostname())
	kind := ""
	switch {
	case host == "github.com" || host == "www.github.com":
		kind = "github"
	case host == "gitlab.com" || host == "www.gitlab.com" || strings.Contains(host, "gitlab"):
		// 自建 GitLab 需要 capability.api_base 指定 API 根地址。
		kind = "gitlab"
	default:
		return nil, invalidSeed("仓库地址只支持 GitHub / GitLab，收到 %s", host)
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 2 {
		return nil, invalidSeed("仓库地址需要包含 owner/repo")
	}
	owner := parts[0]
	name := strings.TrimSuffix(parts[1], ".git")
	if !repoURLPattern.MatchString(owner) || !repoURLPattern.MatchString(name) {
		return nil, invalidSeed("仓库 owner/repo 不合法")
	}
	return &repoRef{Owner: owner, Name: name, Host: host, Kind: kind}, nil
}

func (s *CycleService) expandRepoLive(ctx context.Context, projectID int64, raw string, capability map[string]any, maxTargets int) ([]repo.TargetInput, []string, error) {
	ref, err := parseRepoRef(raw)
	if err != nil {
		return nil, nil, err
	}
	warnings := []string{}
	provider := "github"
	if ref.Kind == "gitlab" {
		provider = "gitlab"
	}
	token := NewSourceService().EngineKey(ctx, provider)
	if token == "" {
		warnings = append(warnings, fmt.Sprintf(
			"未配置 %s Token，仓库展开可能在匿名限流处失败；可在「数据源」页补充 %s 凭据",
			strings.ToUpper(provider), provider))
	}

	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()

	limit := capabilityInt(capability["max_domains"])
	if limit <= 0 {
		limit = repoMaxDomains
	}
	if limit > repoMaxDomains {
		limit = repoMaxDomains
	}

	var domains []string
	if ref.Kind == "gitlab" {
		apiBase := ""
		if v, ok := capability["api_base"].(string); ok {
			apiBase = strings.TrimRight(strings.TrimSpace(v), "/")
		}
		if apiBase == "" && (ref.Host == "gitlab.com" || ref.Host == "www.gitlab.com") {
			apiBase = "https://gitlab.com/api/v4"
		}
		if apiBase == "" {
			warnings = append(warnings, "自建 GitLab 需要在 capability.api_base 指定 API 根地址（如 https://git.example.com/api/v4）")
			return nil, warnings, nil
		}
		domains, err = repoGitLabFetch(ctx, apiBase, token, ref.Owner, ref.Name, limit)
	} else {
		domains, err = repoDomainsFetch(ctx, token, ref.Owner, ref.Name, limit)
	}
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("读取仓库 %s/%s 失败：%v", ref.Owner, ref.Name, err))
		return nil, warnings, nil
	}
	if len(domains) == 0 {
		warnings = append(warnings, "仓库文本里没有提取到域名")
		return nil, warnings, nil
	}
	sort.Strings(domains)
	if len(domains) > limit {
		domains = domains[:limit]
		warnings = append(warnings, fmt.Sprintf("提取域名超过上限 %d，已截断", limit))
	}

	targets, targetWarnings := s.expandDomainList(ctx, projectID, domains, "repo", maxTargets)
	warnings = append(warnings, targetWarnings...)
	warnings = append(warnings, fmt.Sprintf("从仓库 %s/%s 提取 %d 个域名", ref.Owner, ref.Name, len(domains)))
	return targets, warnings, nil
}

type githubRepoMeta struct {
	DefaultBranch string `json:"default_branch"`
	Private       bool   `json:"private"`
}

type githubTreeEntry struct {
	Path string `json:"path"`
	Type string `json:"type"`
	Size int64  `json:"size"`
}

type githubTree struct {
	Tree      []githubTreeEntry `json:"tree"`
	Truncated bool              `json:"truncated"`
}

// fetchGitHubRepoDomains 读元数据、默认分支文件树，再抓少量文本文件提取域名。
func fetchGitHubRepoDomains(ctx context.Context, token, owner, name string, limit int) ([]string, error) {
	api := "https://api.github.com/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(name)
	var meta githubRepoMeta
	if err := githubJSON(ctx, api, token, &meta); err != nil {
		return nil, err
	}
	branch := meta.DefaultBranch
	if branch == "" {
		branch = "main"
	}
	var tree githubTree
	if err := githubJSON(ctx, api+"/git/trees/"+url.PathEscape(branch)+"?recursive=1", token, &tree); err != nil {
		return nil, err
	}

	files := make([]githubTreeEntry, 0, repoMaxFiles)
	for _, entry := range tree.Tree {
		if entry.Type != "blob" || entry.Size <= 0 || entry.Size > repoMaxFileKB*1024 {
			continue
		}
		if !repoTextFile(entry.Path) {
			continue
		}
		files = append(files, entry)
		if len(files) >= repoMaxFiles {
			break
		}
	}

	seen := map[string]bool{}
	out := make([]string, 0, limit)
	for _, file := range files {
		rawURL := "https://raw.githubusercontent.com/" + url.PathEscape(owner) + "/" +
			url.PathEscape(name) + "/" + url.PathEscape(branch) + "/" + escapePath(file.Path)
		body, err := githubRaw(ctx, rawURL)
		if err != nil {
			continue
		}
		for _, d := range extractDomains(string(body)) {
			if seen[d] {
				continue
			}
			seen[d] = true
			out = append(out, d)
			if len(out) >= limit {
				return out, nil
			}
		}
	}
	return out, nil
}

func repoTextFile(path string) bool {
	lower := strings.ToLower(path)
	for _, skip := range []string{"vendor/", "node_modules/", "dist/", "/third_party/"} {
		if strings.Contains(lower, skip) {
			return false
		}
	}
	dot := strings.LastIndex(lower, ".")
	if dot < 0 {
		return false
	}
	return repoTextExt[lower[dot:]]
}

func escapePath(p string) string {
	parts := strings.Split(p, "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	return strings.Join(parts, "/")
}

type gitlabProject struct {
	DefaultBranch     string `json:"default_branch"`
	PathWithNamespace string `json:"path_with_namespace"`
}

type gitlabTreeEntry struct {
	Path string `json:"path"`
	Type string `json:"type"`
}

// fetchGitLabRepoDomains 读取 GitLab（gitlab.com 或自建）默认分支的文本文件并提取域名。
func fetchGitLabRepoDomains(ctx context.Context, apiBase, token, owner, name string, limit int) ([]string, error) {
	apiBase = strings.TrimRight(strings.TrimSpace(apiBase), "/")
	project := url.PathEscape(owner + "/" + name)
	var meta gitlabProject
	if err := gitlabJSON(ctx, apiBase+"/projects/"+project, token, &meta); err != nil {
		return nil, err
	}
	branch := meta.DefaultBranch
	if branch == "" {
		branch = "main"
	}
	var tree []gitlabTreeEntry
	treeURL := fmt.Sprintf("%s/projects/%s/repository/tree?recursive=true&per_page=100&ref=%s",
		apiBase, project, url.QueryEscape(branch))
	if err := gitlabJSON(ctx, treeURL, token, &tree); err != nil {
		return nil, err
	}

	files := make([]gitlabTreeEntry, 0, repoMaxFiles)
	for _, entry := range tree {
		if entry.Type != "blob" || !repoTextFile(entry.Path) {
			continue
		}
		files = append(files, entry)
		if len(files) >= repoMaxFiles {
			break
		}
	}

	seen := map[string]bool{}
	out := make([]string, 0, limit)
	for _, file := range files {
		rawURL := fmt.Sprintf("%s/projects/%s/repository/files/%s/raw?ref=%s",
			apiBase, project, url.PathEscape(file.Path), url.QueryEscape(branch))
		body, err := gitlabRaw(ctx, rawURL, token)
		if err != nil {
			continue
		}
		for _, d := range extractDomains(string(body)) {
			if seen[d] {
				continue
			}
			seen[d] = true
			out = append(out, d)
			if len(out) >= limit {
				return out, nil
			}
		}
	}
	return out, nil
}

func gitlabJSON(ctx context.Context, endpoint, token string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", useragent.Pick())
	if token != "" {
		req.Header.Set("PRIVATE-TOKEN", token)
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("GitLab HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(out)
}

func gitlabRaw(ctx context.Context, endpoint, token string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", useragent.Pick())
	if token != "" {
		req.Header.Set("PRIVATE-TOKEN", token)
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, repoMaxFileKB*1024))
}

func githubJSON(ctx context.Context, endpoint, token string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", useragent.Pick())
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("GitHub HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(out)
}

func githubRaw(ctx context.Context, endpoint string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", useragent.Pick())
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, repoMaxFileKB*1024))
}

func extractDomains(text string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, raw := range domainInTextPattern.FindAllString(text, -1) {
		d := strings.ToLower(strings.TrimSuffix(raw, "."))
		labels := strings.Split(d, ".")
		if len(labels) < 2 {
			continue
		}
		tld := labels[len(labels)-1]
		if notTLD[tld] || tld == "local" || tld == "localhost" {
			continue
		}
		if d == "github.com" || d == "raw.githubusercontent.com" || d == "api.github.com" {
			continue
		}
		if seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out
}
