package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/internal/githubleak"
	"github.com/c1ayooo/4zreark/internal/recon/githubsearch"
)

// GithubLeakService 用 GitHub Code Search 拉候选文件，再用本地检测器做密钥识别。
// 只返回脱敏后的候选（SecretValue 不序列化）；不落库、不通知。
type GithubLeakService struct{}

func NewGithubLeakService() *GithubLeakService { return &GithubLeakService{} }

// Dork 一条检索模板。
type Dork struct {
	ID       string `json:"id"`
	Category string `json:"category"`
	Title    string `json:"title"`
	Query    string `json:"query"`
	Note     string `json:"note,omitempty"`
}

// Dorks 返回内置 dork 模板。
func (s *GithubLeakService) Dorks() []Dork {
	tpls := githubsearch.Templates()
	out := make([]Dork, 0, len(tpls))
	for _, t := range tpls {
		out = append(out, Dork{ID: t.ID, Category: t.Category, Title: t.Title, Query: t.Query, Note: t.Note})
	}
	return out
}

// LeakScanInput 一次 GitHub 泄露检索。
type LeakScanInput struct {
	Query      string `json:"query"`
	DorkID     string `json:"dork_id"`
	Org        string `json:"org"`
	Domain     string `json:"domain"`
	MaxResults int    `json:"max_results"`
}

// LeakScanResult 检索与检测结果。
type LeakScanResult struct {
	Query      string                 `json:"query"`
	Items      int                    `json:"items"`
	Candidates []githubleak.Candidate `json:"candidates"`
	Truncated  bool                   `json:"truncated"`
	Errors     []string               `json:"errors,omitempty"`
}

// Scan 执行一次检索 + 检测。GITHUB_TOKEN 未配置时返回明确错误。
func (s *GithubLeakService) Scan(ctx context.Context, in LeakScanInput) (*LeakScanResult, error) {
	query := strings.TrimSpace(in.Query)
	if in.DorkID != "" {
		tpl, ok := githubsearch.TemplateByID(in.DorkID)
		if !ok {
			return nil, errors.New("dork 模板不存在: " + in.DorkID)
		}
		query = githubsearch.BuildQuery(tpl, in.Org, in.Domain)
	}
	if query == "" {
		return nil, errors.New("query 与 dork_id 至少给一个")
	}
	maxResults := in.MaxResults
	if maxResults <= 0 {
		maxResults = 30
	}
	if maxResults > 300 {
		maxResults = 300
	}

	client := githubsearch.NewClientFromEnv()
	detector, err := githubleak.NewDetector(githubleak.Settings{
		Enabled:              true,
		FingerprintKey:       leakFingerprintKey(),
		MaxResultsPerKeyword: 100,
	})
	if err != nil {
		return nil, err
	}

	out := &LeakScanResult{Query: query}
	perPage := 100
	page := 1
	for len(out.Candidates) < maxResults && page*perPage <= 1000 {
		res, serr := client.Search(ctx, query, page, perPage)
		if serr != nil {
			if page == 1 {
				return nil, serr
			}
			out.Errors = append(out.Errors, serr.Error())
			break
		}
		out.Truncated = res.Truncated
		for _, m := range res.Items {
			item := githubleak.SearchItem{
				Repository:   m.Repo,
				Path:         m.Path,
				HTMLURL:      m.FileURL,
				Fragments:    m.Fragments,
				RepoStars:    m.RepoStars,
				RepoFork:     m.IsFork,
				RepoPushedAt: parseGithubTime(m.PushedAt),
			}
			out.Items++
			out.Candidates = append(out.Candidates, detector.Detect(query, item)...)
			if len(out.Candidates) >= maxResults {
				break
			}
		}
		if len(res.Items) < perPage {
			break
		}
		page++
	}
	if len(out.Candidates) > maxResults {
		out.Candidates = out.Candidates[:maxResults]
		out.Truncated = true
	}
	return out, nil
}

func leakFingerprintKey() string {
	// 指纹 key 只影响同一密钥的稳定去重标识，不影响检测本身。
	return "4zreark-github-leak-v1"
}

func parseGithubTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05Z", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}
