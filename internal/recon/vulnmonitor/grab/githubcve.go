package grab

// GitHub CVE 雷达：轮询 GitHub 上新出现的 CVE 相关仓库（对齐 ARL-Next 的
// github_threat CVE 监听思路），作为 vulnmonitor 的第 10 个情报源。
//
// 与各爬虫源的差异：GitHub 仓库本身不带严重级别，这里统一记「中危」——
// 刚出现 PoC/分析文章的 CVE 值得关注，但没有依据拔成高危。去重交给 Store：
// unique_key 用 CVE 编号，同一 CVE 后续新增仓库不会重复入库。

import (
	"context"
	"fmt"
	"log"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/internal/recon/vulnmonitor/util"
	"github.com/imroc/req/v3"
)

const githubSearchURL = "https://api.github.com/search/repositories"

// cvePattern 从仓库名/描述里提取 CVE 编号。
var cvePattern = regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,}`)

// GithubCVECrawler 监听 GitHub 上当日新创建的 CVE 相关仓库。
type GithubCVECrawler struct {
	client  *req.Client
	log     *log.Logger
	tokenFn func(ctx context.Context) string
}

// NewGithubCVECrawler 创建雷达。未配置 tokenFn 时走匿名搜索（10 次/分钟配额）。
func NewGithubCVECrawler() *GithubCVECrawler {
	c := &GithubCVECrawler{
		log: log.New(os.Stderr, "[github-cve] ", log.LstdFlags),
	}
	c.client = util.NewHttpClient()
	return c
}

// WithTokenFn 注入 GitHub 凭据解析（环境变量/sources 表/token 池由调用方决定）。
func (c *GithubCVECrawler) WithTokenFn(fn func(ctx context.Context) string) *GithubCVECrawler {
	c.tokenFn = fn
	return c
}

func (c *GithubCVECrawler) ProviderInfo() *Provider {
	return &Provider{
		Name:        "github-cve-radar",
		DisplayName: "GitHub CVE 雷达",
		Link:        "https://github.com/search?q=CVE",
	}
}

type githubRepoItem struct {
	FullName    string `json:"full_name"`
	HTMLURL     string `json:"html_url"`
	Description string `json:"description"`
	CreatedAt   string `json:"created_at"`
	PushedAt    string `json:"pushed_at"`
	Stars       int    `json:"stargazers_count"`
}

type githubSearchResp struct {
	TotalCount int              `json:"total_count"`
	Items      []githubRepoItem `json:"items"`
}

func (c *GithubCVECrawler) GetUpdate(ctx context.Context, pageLimit int) ([]*VulnInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// 只看最近 24h 创建的仓库，轮询间隔 30 分钟量级，一页 100 条足够覆盖。
	since := time.Now().UTC().Add(-24 * time.Hour).Format("2006-01-02T15:04:05Z")
	year := time.Now().UTC().Format("2006")
	query := fmt.Sprintf("CVE-%s created:>=%s", year, since)

	var result githubSearchResp
	req2 := c.client.R().SetContext(ctx).
		SetHeader("Accept", "application/vnd.github+json").
		SetHeader("X-GitHub-Api-Version", "2022-11-28").
		SetQueryParam("q", query).
		SetQueryParam("sort", "created").
		SetQueryParam("order", "desc").
		SetQueryParam("per_page", "100")
	if c.tokenFn != nil {
		if tok := strings.TrimSpace(c.tokenFn(ctx)); tok != "" {
			req2 = req2.SetHeader("Authorization", "Bearer "+tok)
		}
	}
	resp, err := req2.SetSuccessResult(&result).Get(githubSearchURL)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == httpStatusRateLimited || resp.StatusCode == httpStatusForbidden {
		return nil, fmt.Errorf("github search 被限流（HTTP %d）", resp.StatusCode)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("github search 异常（HTTP %d）", resp.StatusCode)
	}

	// 按 CVE 聚合：一个 CVE 可能有多个仓库（PoC/分析/复现）。
	byCVE := map[string][]githubRepoItem{}
	var order []string
	for _, item := range result.Items {
		m := cvePattern.FindString(item.FullName + " " + item.Description)
		if m == "" {
			continue
		}
		cve := strings.ToUpper(m)
		if _, ok := byCVE[cve]; !ok {
			order = append(order, cve)
		}
		byCVE[cve] = append(byCVE[cve], item)
	}
	sort.Strings(order)

	today := time.Now().UTC().Format("2006-01-02")
	var infos []*VulnInfo
	for _, cve := range order {
		repos := byCVE[cve]
		info := &VulnInfo{
			UniqueKey:  cve + "_github",
			Title:      fmt.Sprintf("%s（GitHub 新增 %d 个相关仓库）", cve, len(repos)),
			Severity:   Medium, // 仓库情报无评级：值得关注但无依据拔高
			CVE:        cve,
			Disclosure: today,
			From:       repos[0].HTMLURL,
			Tags:       []string{"github", "cve-radar", year},
			Reason:     []string{ReasonNewCreated},
		}
		var desc strings.Builder
		for i, r := range repos {
			if i >= maxGithubCVEReferences {
				break
			}
			info.References = append(info.References, r.HTMLURL)
			if i > 0 {
				desc.WriteString("\n")
			}
			desc.WriteString(fmt.Sprintf("- %s（★%d）%s", r.FullName, r.Stars, strings.TrimSpace(r.Description)))
		}
		info.Description = desc.String()
		info.Creator = c
		infos = append(infos, info)
	}
	return infos, nil
}

// IsValuable 只收带 CVE 编号的条目（本源聚合后必带，防御式保留接口）。
func (c *GithubCVECrawler) IsValuable(info *VulnInfo) bool {
	return info != nil && cveIDRegexp.MatchString(strings.ToUpper(info.CVE))
}

const (
	maxGithubCVEReferences = 10

	httpStatusRateLimited = 429
	httpStatusForbidden   = 403
)
