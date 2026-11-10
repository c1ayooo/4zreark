package toolruntime

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/internal/outbound"
	"github.com/c1ayooo/4zreark/internal/useragent"
)

const (
	// ghAPITokenEnv 可选；GitHub API 匿名限额 60 req/h，配 token 提到 5000。
	ghAPITokenEnv = "ZRE_GITHUB_TOKEN"
	// ghMirrorEnv 下载镜像前缀（如 https://ghproxy.net/），拼在 release 资产 URL 前。
	ghMirrorEnv = "ZRE_GH_MIRROR"
	// ghProxyEnv 下载/查询代理 URL；空则遵循环境变量。
	ghProxyEnv = "ZRE_TOOL_PROXY"
)

type ghRelease struct {
	TagName    string    `json:"tag_name"`
	Prerelease bool      `json:"prerelease"`
	CreatedAt  time.Time `json:"created_at"`
	Assets     []ghAsset `json:"assets"`
	parsedVer  version
}

type ghAsset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
}

// listReleases 拉取仓库的 release 列表（含 pre-release；是否采用由 pickLatest 决定）。
func (m *Manager) listReleases(ctx context.Context, repo string) ([]ghRelease, error) {
	api := fmt.Sprintf("https://api.github.com/repos/%s/releases?per_page=30", repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, api, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	useragent.Apply(req)
	if tok := strings.TrimSpace(os.Getenv(ghAPITokenEnv)); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := m.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("访问 GitHub API 失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API %s 返回 %d", repo, resp.StatusCode)
	}
	var releases []ghRelease
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&releases); err != nil {
		return nil, fmt.Errorf("解析 release 列表失败: %w", err)
	}
	return releases, nil
}

// pickLatest 在 release 列表里按 semver 取最大正式版（默认排除 pre-release）。
// 不信任列表顺序：spray 的 release 按 created_at 排序时 latest 是 v0.3.2，
// 但 semver 最大是 v1.3.2，盲取第一个会把版本降下去。
func pickLatest(releases []ghRelease, minVersion string) (ghRelease, bool) {
	var best ghRelease
	var bestVer version
	found := false
	for _, r := range releases {
		v, err := parseVersion(r.TagName)
		if err != nil {
			continue
		}
		if r.Prerelease {
			continue
		}
		if minVersion != "" {
			if mv, err := parseVersion(minVersion); err == nil && v.less(mv) {
				continue
			}
		}
		if !found || bestVer.less(v) {
			best, bestVer, found = r, v, true
		}
	}
	return best, found
}

// findAsset 在 release 资产里按名字精确匹配。
func findAsset(r ghRelease, name string) (ghAsset, bool) {
	for _, a := range r.Assets {
		if a.Name == name {
			return a, true
		}
	}
	return ghAsset{}, false
}

// mirrorCandidates 返回下载候选 URL 序列。显式设置 ZRE_GH_MIRROR 时镜像优先
// （用户配镜像通常意味着直连不通），直连放最后兜底；否则直连优先、内置镜像兜底。
func mirrorCandidates(direct string) []string {
	out := make([]string, 0, 4)
	seen := map[string]bool{}
	add := func(u string) {
		if u != "" && !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	if raw := strings.TrimSpace(os.Getenv(ghMirrorEnv)); raw != "" {
		for _, m := range strings.Split(raw, ",") {
			if m = strings.TrimRight(strings.TrimSpace(m), "/"); m != "" {
				add(m + "/" + direct)
			}
		}
		add(direct)
		return out
	}
	add(direct)
	for _, m := range defaultMirrors {
		add(m + "/" + direct)
	}
	return out
}

// 实测 gh-proxy.com 在直连/代理下均可用，放内置镜像首位；
// ghfast.top 经部分代理 TLS 不稳，ghproxy.net 的 h2 流会被中途打断。
var defaultMirrors = []string{
	"https://gh-proxy.com",
	"https://ghfast.top",
	"https://ghproxy.net",
}

// downloadToFile 下载 release 资产到本地文件；每个候选独立限时，失败立刻换源，
// 避免直连卡住时把 15 分钟的 client 超时耗光、镜像一个都轮不到。
func (m *Manager) downloadToFile(ctx context.Context, repo, tag, asset string, dstPath string) error {
	direct := fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", repo, tag, asset)
	var lastErr error
	for _, u := range mirrorCandidates(direct) {
		attemptCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		err := m.downloadURL(attemptCtx, u, dstPath)
		cancel()
		if err == nil {
			return nil
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	if lastErr == nil {
		lastErr = errors.New("没有可用的下载地址")
	}
	return fmt.Errorf("下载 %s 失败: %w", asset, lastErr)
}

func (m *Manager) downloadURL(ctx context.Context, rawURL, dstPath string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	useragent.Apply(req)
	resp, err := m.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d (%s)", resp.StatusCode, rawURL)
	}
	f, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	n, copyErr := io.Copy(f, io.LimitReader(resp.Body, downloadLimit+1))
	closeErr := f.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if n == 0 {
		return fmt.Errorf("下载内容为空")
	}
	if n > downloadLimit {
		return fmt.Errorf("资产超过 %d MB 上限", downloadLimit>>20)
	}
	return nil
}

// parseChecksums 解析 `sha256  filename` 格式的清单，返回 文件名 → hex。
func parseChecksums(data []byte) map[string]string {
	m := make(map[string]string)
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && len(fields[0]) == 64 {
			m[fields[len(fields)-1]] = fields[0]
		}
	}
	return m
}

// httpClient 每次按代理设置构造；release 资产 302 到的 CDN 在部分代理下
// TLS 握手不兼容，沿 nucleiruntime 的经验只对资产 CDN 直连。
// 下载 Transport 显式禁用 HTTP/2（TLSNextProto 置空表）：
// 实测部分 gh 镜像的 h2 流会被对端中途打断（INTERNAL_ERROR）。
//
// 代理优先级：代理设置页 DB 配置 > ZRE_TOOL_PROXY > 环境变量 HTTP(S)_PROXY。
func (m *Manager) httpClient() *http.Client {
	c := *m.client
	tr := &http.Transport{
		Proxy:                 outbound.EnvironmentProxyWithCDN(),
		ResponseHeaderTimeout: 60 * time.Second,
		TLSNextProto:          map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
	if u, err := outbound.ProxyFor("tool_download"); err != nil {
		log.Printf("[toolruntime] 工具下载代理配置无效，回退环境变量: %v", err)
	} else if u != nil {
		tr.Proxy = outbound.ProxyWithCDN(u)
	} else if outbound.ModeFor("tool_download") == outbound.ModeDirect {
		tr.Proxy = nil // 设置页显式直连，压过 ZRE_TOOL_PROXY / HTTP(S)_PROXY
	} else if p := strings.TrimSpace(os.Getenv(ghProxyEnv)); p != "" {
		if u, err := url.Parse(p); err == nil && u.Host != "" {
			tr.Proxy = outbound.ProxyWithCDN(u)
		} else {
			log.Printf("[toolruntime] %s 不是合法代理地址: %q", ghProxyEnv, p)
		}
	}
	c.Transport = tr
	return &c
}

// assetCDNDirectProxy 保留旧入口；CDN 直连只在 ZRE_GH_CDN_DIRECT=1 时生效。
func assetCDNDirectProxy(u *url.URL) func(*http.Request) (*url.URL, error) {
	return outbound.ProxyWithCDN(u)
}
