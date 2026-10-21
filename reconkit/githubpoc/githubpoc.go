// Package githubpoc implements the GitHub proof-of-concept (PoC) search flow:
//
//  1. search GitHub repositories for a CVE (stars desc, top N);
//  2. fetch the GitHub Security Advisory (GHSA) for CVSS/CWE/affected packages;
//  3. triage every repository with the pure-rule `triage` package;
//  4. drop malicious/noise/lab-only repositories and return the remaining POCs.
//
// It is extracted from 4zrec's vulnintel enrichment chain and has no database,
// agent, or EPSS/KEV/NVD dependency. Callers that already have those signals can
// pass them through triage.CVEMeta (InKEV/EPSS fields).
package githubpoc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/reconkit/triage"
)

const (
	// DefaultBaseURL is the public GitHub API.
	DefaultBaseURL = "https://api.github.com"
	// DefaultMinGap protects the account-level 30/min search quota.
	DefaultMinGap = 2200 * time.Millisecond
	// DefaultPerPage is the number of repositories fetched per search.
	DefaultPerPage = 5
)

// Repo is one GitHub repository search hit.
type Repo struct {
	FullName    string `json:"full_name"`
	HTMLURL     string `json:"html_url"`
	Description string `json:"description"`
	Stars       int    `json:"stargazers_count"`
	Forks       int    `json:"forks_count"`
	CreatedAt   string `json:"created_at"`
	PushedAt    string `json:"pushed_at"`
	IsFork      bool   `json:"fork"`
	Archived    bool   `json:"archived"`
}

// Advisory is the subset of a GitHub Security Advisory used by the flow.
type Advisory struct {
	Summary  string `json:"summary"`
	Severity string `json:"severity"`
	CVSS     struct {
		VectorString string  `json:"vector_string"`
		Score        float64 `json:"score"`
	} `json:"cvss"`
	CWEs []struct {
		CWEID string `json:"cwe_id"`
	} `json:"cwes"`
	Vulnerabilities []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		VulnerableVersionRange string `json:"vulnerable_version_range"`
		FirstPatched           struct {
			Identifier string `json:"identifier"`
		} `json:"first_patched"`
	} `json:"vulnerabilities"`
}

// POC is one triaged repository that survived filtering.
type POC struct {
	FullName    string   `json:"full_name"`
	URL         string   `json:"url"`
	Description string   `json:"description"`
	Stars       int      `json:"stars"`
	Forks       int      `json:"forks"`
	PushedAt    string   `json:"pushed_at"`
	Verdict     string   `json:"verdict"`
	TriageScore int      `json:"triage_score"`
	Reasons     []string `json:"reasons,omitempty"`
}

// Result is the complete output of one CVE lookup.
type Result struct {
	CVE             string    `json:"cve"`
	Repos           []Repo    `json:"repos"`
	POCs            []POC     `json:"pocs"`
	Advisory        *Advisory `json:"advisory,omitempty"`
	CVSSScore       float64   `json:"cvss_score"`
	CVSSVector      string    `json:"cvss_vector,omitempty"`
	CWEs            []string  `json:"cwes,omitempty"`
	Affected        []string  `json:"affected,omitempty"`
	LabOnly         bool      `json:"lab_only"`
	SupplementTitle string    `json:"supplement_title,omitempty"`
}

// Client calls the GitHub REST API. Zero-value fields fall back to defaults.
type Client struct {
	// Token returns the current token; empty means "search disabled". It is
	// called per request so token rotation takes effect without rebuilding.
	Token func() string
	// HTTPClient is optional; a 15s client is used when nil.
	HTTPClient *http.Client
	// Proxy returns an optional egress proxy URL per request.
	Proxy func() string
	// BaseURL defaults to DefaultBaseURL (useful for tests/GitHub Enterprise).
	BaseURL string
	// MinGap is the minimum interval between search requests.
	MinGap time.Duration
	// PerPage is the number of repositories fetched (max 100).
	PerPage int

	mu         sync.Mutex
	lastSearch time.Time
}

// NewClient creates a client with the supplied token provider.
func NewClient(tokenFn func() string) *Client {
	return &Client{
		Token:      tokenFn,
		HTTPClient: &http.Client{Timeout: 15 * time.Second},
		BaseURL:    DefaultBaseURL,
		MinGap:     DefaultMinGap,
		PerPage:    DefaultPerPage,
	}
}

// NewClientFromEnv reads GITHUB_TOKEN on each request.
func NewClientFromEnv() *Client {
	return NewClient(func() string { return strings.TrimSpace(os.Getenv("GITHUB_TOKEN")) })
}

func (c *Client) baseURL() string {
	if b := strings.TrimSpace(c.BaseURL); b != "" {
		return strings.TrimRight(b, "/")
	}
	return DefaultBaseURL
}

func (c *Client) minGap() time.Duration {
	if c.MinGap > 0 {
		return c.MinGap
	}
	return DefaultMinGap
}

func (c *Client) perPage() int {
	if c.PerPage > 0 && c.PerPage <= 100 {
		return c.PerPage
	}
	return DefaultPerPage
}

func (c *Client) token() string {
	if c.Token == nil {
		return ""
	}
	return strings.TrimSpace(c.Token())
}

// waitSearchQuota enforces the minimum gap between search calls.
func (c *Client) waitSearchQuota(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if gap := c.minGap() - time.Since(c.lastSearch); gap > 0 {
		select {
		case <-time.After(gap):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	c.lastSearch = time.Now()
	return nil
}

func (c *Client) httpClient() *http.Client {
	base := c.HTTPClient
	if base == nil {
		base = &http.Client{Timeout: 15 * time.Second}
	}
	if c.Proxy == nil {
		return base
	}
	raw := strings.TrimSpace(c.Proxy())
	if raw == "" {
		return base
	}
	pu, err := url.Parse(raw)
	if err != nil || pu.Scheme == "" || pu.Host == "" {
		return base
	}
	return &http.Client{
		Timeout:   base.Timeout,
		Transport: &http.Transport{Proxy: http.ProxyURL(pu)},
	}
}

func (c *Client) getJSON(ctx context.Context, endpoint, token string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "reconkit-githubpoc/1.0")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GitHub API %s: %s", resp.Status, apiMessage(body))
	}
	return json.Unmarshal(body, out)
}

func apiMessage(body []byte) string {
	var e struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &e) == nil && strings.TrimSpace(e.Message) != "" {
		return e.Message
	}
	return strings.TrimSpace(string(body))
}

// SearchRepos searches GitHub for repositories matching cve (stars desc).
// An empty token returns (nil, nil): the flow is skipped, not failed.
func (c *Client) SearchRepos(ctx context.Context, cve string) ([]Repo, error) {
	token := c.token()
	if token == "" {
		return nil, nil
	}
	if err := c.waitSearchQuota(ctx); err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("%s/search/repositories?q=%s&sort=stars&order=desc&per_page=%d",
		c.baseURL(), url.QueryEscape(cve), c.perPage())
	var resp struct {
		Items []Repo `json:"items"`
	}
	if err := c.getJSON(ctx, endpoint, token, &resp); err != nil {
		return nil, err
	}
	return resp.Items, nil
}

// FetchAdvisory fetches the GitHub Security Advisory for cve. An empty token
// returns (nil, nil).
func (c *Client) FetchAdvisory(ctx context.Context, cve string) (*Advisory, error) {
	token := c.token()
	if token == "" {
		return nil, nil
	}
	endpoint := fmt.Sprintf("%s/advisories?cve_id=%s&per_page=1",
		c.baseURL(), url.QueryEscape(cve))
	var resp []Advisory
	if err := c.getJSON(ctx, endpoint, token, &resp); err != nil {
		return nil, err
	}
	if len(resp) == 0 {
		return nil, nil
	}
	return &resp[0], nil
}

// Enrich runs the whole flow: search, advisory, triage, filtering and sorting.
//
// meta supplies the CVE-level signals used by triage (CVSS, CWE, description,
// KEV/EPSS when available). Advisory CVSS/CWE/affected values take precedence
// over meta, mirroring the original 4zrec enrichment order.
func (c *Client) Enrich(ctx context.Context, meta triage.CVEMeta) (*Result, error) {
	cve := strings.TrimSpace(meta.CVEID)
	if cve == "" {
		return nil, fmt.Errorf("CVEID 不能为空")
	}

	repos, err := c.SearchRepos(ctx, cve)
	if err != nil {
		return nil, fmt.Errorf("poc search: %w", err)
	}

	adv, _ := c.FetchAdvisory(ctx, cve)

	cvssScore := meta.CVSSScore
	cvssVector := meta.CVSSVector
	cwes := append([]int{}, meta.CWE...)
	var affected []string
	supplementTitle := ""
	if adv != nil {
		if adv.CVSS.Score > 0 {
			cvssScore = adv.CVSS.Score
			cvssVector = adv.CVSS.VectorString
		}
		for _, cwe := range adv.CWEs {
			var n int
			if _, err := fmt.Sscanf(cwe.CWEID, "CWE-%d", &n); err == nil && n > 0 {
				cwes = append(cwes, n)
			}
		}
		for _, v := range adv.Vulnerabilities {
			affected = append(affected, v.Package.Ecosystem+"/"+v.Package.Name)
		}
		if s := strings.TrimSpace(adv.Summary); len(s) >= 8 {
			supplementTitle = s
		}
	}
	cwes = dedupeInts(cwes)

	triageMeta := meta
	triageMeta.CVSSScore = cvssScore
	triageMeta.CVSSVector = cvssVector
	triageMeta.CWE = cwes

	pocs := make([]POC, 0, len(repos))
	labOnly := false
	for _, r := range repos {
		isFork := r.IsFork
		archived := r.Archived
		repoMeta := triage.RepoMeta{
			FullName:    r.FullName,
			Description: r.Description,
			Stars:       r.Stars,
			Forks:       r.Forks,
			CreatedAt:   r.CreatedAt,
			PushedAt:    r.PushedAt,
			IsFork:      &isFork,
			Archived:    &archived,
		}
		verdict, score, reasons := triage.Triage(triageMeta, repoMeta)
		switch verdict {
		case triage.VerdictMalicious:
			continue // never surface malicious repositories
		case triage.VerdictNoise:
			continue
		case triage.VerdictLabOnly:
			labOnly = true
			continue
		}
		if len(reasons) > 3 {
			reasons = reasons[:3]
		}
		pocs = append(pocs, POC{
			FullName:    r.FullName,
			URL:         r.HTMLURL,
			Description: r.Description,
			Stars:       r.Stars,
			Forks:       r.Forks,
			PushedAt:    r.PushedAt,
			Verdict:     string(verdict),
			TriageScore: score,
			Reasons:     reasons,
		})
	}
	sort.SliceStable(pocs, func(i, j int) bool { return pocs[i].Stars > pocs[j].Stars })

	return &Result{
		CVE:             cve,
		Repos:           repos,
		POCs:            pocs,
		Advisory:        adv,
		CVSSScore:       cvssScore,
		CVSSVector:      cvssVector,
		CWEs:            cweStrings(cwes),
		Affected:        dedupeStrings(affected),
		LabOnly:         labOnly,
		SupplementTitle: supplementTitle,
	}, nil
}

func dedupeInts(in []int) []int {
	seen := map[int]bool{}
	out := make([]int, 0, len(in))
	for _, n := range in {
		if n > 0 && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}

func cweStrings(in []int) []string {
	out := make([]string, 0, len(in))
	for _, n := range in {
		out = append(out, fmt.Sprintf("CWE-%d", n))
	}
	return out
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
