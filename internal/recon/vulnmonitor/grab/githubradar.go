package grab

// GitHub 威胁雷达另外两路（与 githubcve.go 同一框架）：
//   - GithubToolsCrawler：安全工具（武器库）仓库的 Release 监听——新版本发布
//     通常意味着新的利用面或新的检测对抗，值得跟进。
//   - GithubHackersCrawler：研究员用户新建仓库监听——0day/PoC 首发常出现在
//     已知研究员的个人仓库里。
//
// 两路都产出「情报」形态的条目进 vuln_intel（severity 记中危：事件本身无评级），
// unique_key 自带版本/仓库名，由 Store upsert 天然去重。

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/internal/recon/vulnmonitor/util"
)

const (
	githubAPIBase      = "https://api.github.com"
	githubRadarCreated = 24 * time.Hour
)

// githubRadarGet 请求 GitHub API 并反序列化。429/403 视为限流直接报错，
// 单次轮询不重试（下一轮自然续上），避免拖垮整个轮询窗口。
func githubRadarGet(ctx context.Context, tokenFn func(ctx context.Context) string, url string, out any) error {
	client := util.NewHttpClient()
	r := client.R().SetContext(ctx).
		SetHeader("Accept", "application/vnd.github+json").
		SetHeader("X-GitHub-Api-Version", "2022-11-28")
	if tokenFn != nil {
		if tok := strings.TrimSpace(tokenFn(ctx)); tok != "" {
			r = r.SetHeader("Authorization", "Bearer "+tok)
		}
	}
	resp, err := r.SetSuccessResult(out).Get(url)
	if err != nil {
		return err
	}
	if resp.StatusCode == httpStatusRateLimited || resp.StatusCode == httpStatusForbidden {
		return fmt.Errorf("github api 被限流（HTTP %d）", resp.StatusCode)
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("github api 异常（HTTP %d）", resp.StatusCode)
	}
	return nil
}

// githubRadarClient 是两路雷达共享的 API 访问器。
type githubRadarClient struct {
	tokenFn func(ctx context.Context) string
}

func (c *githubRadarClient) do(ctx context.Context, path string, out any) error {
	return githubRadarGet(ctx, c.tokenFn, githubAPIBase+path, out)
}

// --- 安全工具 Release 雷达 ---

type GithubToolsCrawler struct {
	client  *githubRadarClient
	targets func() []string
}

// NewGithubToolsCrawler 创建武器库 Release 雷达。targets 返回要监听的
// "owner/repo" 列表（来自平台设置，运行时可改）。
func NewGithubToolsCrawler(targets func() []string) *GithubToolsCrawler {
	return &GithubToolsCrawler{client: &githubRadarClient{}, targets: targets}
}

func (c *GithubToolsCrawler) WithTokenFn(fn func(ctx context.Context) string) *GithubToolsCrawler {
	c.client.tokenFn = fn
	return c
}

func (c *GithubToolsCrawler) ProviderInfo() *Provider {
	return &Provider{
		Name:        "github-tools-radar",
		DisplayName: "GitHub 安全工具雷达",
		Link:        "https://github.com",
	}
}

type githubRelease struct {
	TagName     string    `json:"tag_name"`
	Name        string    `json:"name"`
	HTMLURL     string    `json:"html_url"`
	PublishedAt time.Time `json:"published_at"`
	Body        string    `json:"body"`
}

func (c *GithubToolsCrawler) GetUpdate(ctx context.Context, pageLimit int) ([]*VulnInfo, error) {
	var infos []*VulnInfo
	now := time.Now().UTC()
	for _, repo := range c.targets() {
		repo = strings.TrimPrefix(strings.TrimSpace(repo), "https://github.com/")
		if repo == "" || !strings.Contains(repo, "/") {
			continue
		}
		var rel githubRelease
		if err := c.client.do(ctx, "/repos/"+repo+"/releases/latest", &rel); err != nil {
			continue // 单个仓库失败不拖垮整轮
		}
		if rel.TagName == "" || rel.HTMLURL == "" {
			continue
		}
		// 只收最近 24h 内发布的版本，避免每轮重复报旧版本。
		if rel.PublishedAt.IsZero() || now.Sub(rel.PublishedAt.UTC()) > githubRadarCreated {
			continue
		}
		infos = append(infos, &VulnInfo{
			UniqueKey:  "github-release:" + repo + "@" + rel.TagName,
			Title:      fmt.Sprintf("[工具雷达] %s 发布 %s", repo, rel.TagName),
			Severity:   Medium,
			Disclosure: rel.PublishedAt.UTC().Format("2006-01-02"),
			From:       rel.HTMLURL,
			Tags:       []string{"github", "tool-radar", repo},
			Reason:     []string{ReasonTagUpdated},
		})
		infos[len(infos)-1].Creator = c
	}
	return infos, nil
}

func (c *GithubToolsCrawler) IsValuable(info *VulnInfo) bool {
	return info != nil && strings.HasPrefix(info.UniqueKey, "github-release:")
}

// --- 研究员新仓库雷达 ---

type GithubHackersCrawler struct {
	client  *githubRadarClient
	targets func() []string
}

// NewGithubHackersCrawler 创建研究员仓库雷达。targets 返回要监听的 GitHub 用户名。
func NewGithubHackersCrawler(targets func() []string) *GithubHackersCrawler {
	return &GithubHackersCrawler{client: &githubRadarClient{}, targets: targets}
}

func (c *GithubHackersCrawler) WithTokenFn(fn func(ctx context.Context) string) *GithubHackersCrawler {
	c.client.tokenFn = fn
	return c
}

func (c *GithubHackersCrawler) ProviderInfo() *Provider {
	return &Provider{
		Name:        "github-hackers-radar",
		DisplayName: "GitHub 研究员雷达",
		Link:        "https://github.com",
	}
}

type githubRepoBrief struct {
	FullName    string    `json:"full_name"`
	HTMLURL     string    `json:"html_url"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	Stars       int       `json:"stargazers_count"`
}

func (c *GithubHackersCrawler) GetUpdate(ctx context.Context, pageLimit int) ([]*VulnInfo, error) {
	var infos []*VulnInfo
	now := time.Now().UTC()
	for _, user := range c.targets() {
		user = strings.TrimSpace(user)
		if user == "" || strings.Contains(user, "/") {
			continue
		}
		var repos []githubRepoBrief
		if err := c.client.do(ctx, "/users/"+user+"/repos?sort=created&direction=desc&per_page=10", &repos); err != nil {
			continue
		}
		for _, r := range repos {
			if r.CreatedAt.IsZero() || now.Sub(r.CreatedAt.UTC()) > githubRadarCreated {
				continue
			}
			infos = append(infos, &VulnInfo{
				UniqueKey:  "github-hacker:" + r.FullName,
				Title:      fmt.Sprintf("[研究员雷达] %s 新建仓库 %s", user, r.FullName),
				Severity:   Medium,
				Disclosure: r.CreatedAt.UTC().Format("2006-01-02"),
				From:       r.HTMLURL,
				Tags:       []string{"github", "hacker-radar", user},
				Reason:     []string{ReasonNewCreated},
			})
			infos[len(infos)-1].Creator = c
		}
	}
	return infos, nil
}

func (c *GithubHackersCrawler) IsValuable(info *VulnInfo) bool {
	return info != nil && strings.HasPrefix(info.UniqueKey, "github-hacker:")
}
