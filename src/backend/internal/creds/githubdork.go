// Package githubsearch 提供 GitHub Code Search 泄露检索（dork）能力：
// 内置 dork 模板库（云密钥/文件名定向/服务指纹/私钥块/org 定向），
// 带 token 的 Search API 客户端、10 次/分钟配额排队与 1000 条截断提示。
//
// 语法注意（与 Web 搜索不同）：
//   - Code Search 不支持 pushed:/created: 时间限定符（会被静默忽略），增量靠应用层记录
//   - 排除用减号前缀（-extension:md），不支持 NOT 关键字
//   - 限定符值区分大小写，统一小写；filename: 是子串匹配
//   - 只搜默认分支；历史泄露需 gitleaks 深扫，不在本包范围
package creds

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// DorkTemplate 一条可复用的泄露检索模板。{org} 占位符在定向搜索时替换。
type DorkTemplate struct {
	ID       string `json:"id"`
	Category string `json:"category"`
	Title    string `json:"title"`
	Query    string `json:"query"`
	Note     string `json:"note,omitempty"`
}

// CodeMatch 单条代码命中
type CodeMatch struct {
	Repo       string   `json:"repo"`        // 仓库 full_name
	RepoStars  int      `json:"repo_stars"`  // 仓库 star 数（活跃度参考）
	RepoURL    string   `json:"repo_url"`    // 仓库链接
	Path       string   `json:"path"`        // 命中文件路径
	FileURL    string   `json:"file_url"`    // 文件 html_url（跳转 GitHub）
	Fragments  []string `json:"fragments"`   // 命中片段（text-match）
	OwnerLogin string   `json:"owner_login"` // 所有者（人名/org 反查线索）
	PushedAt   string   `json:"pushed_at"`   // 仓库最近推送时间
	IsFork     bool     `json:"is_fork"`     // fork 仓库多为搬运，降权线索
}

// SearchResult 检索结果与配额元信息
type SearchResult struct {
	TotalCount int         `json:"total_count"` // GitHub 报告的总量（>1000 时不可再翻页）
	Incomplete bool        `json:"incomplete"`  // GitHub 说明结果不完整（超时/超量）
	Items      []CodeMatch `json:"items"`
	Query      string      `json:"query"`
	Page       int         `json:"page"`
	PerPage    int         `json:"per_page"`
	Truncated  bool        `json:"truncated"` // page*per_page ≥ 1000，达到 API 截断
}

// dorkLibrary 内置模板库（按用户实战清单整理，语法已纠正为 Code Search 合法形式）
var dorkLibrary = []DorkTemplate{
	// ── 云厂商密钥（前缀词直接搜） ──
	{ID: "aws-key-env", Category: "云厂商密钥", Title: "AWS Access Key（env/yaml 文件）", Query: `AKIA extension:env`, Note: "AWK 前缀本身够特异，加文件类型减少噪音；可叠加 -extension:md"},
	{ID: "aws-key-yaml", Category: "云厂商密钥", Title: "AWS Access Key（yaml 文件）", Query: `AKIA extension:yaml`},
	{ID: "aliyun-key", Category: "云厂商密钥", Title: "阿里云 AccessKey", Query: `LTAI`},
	{ID: "tencent-key", Category: "云厂商密钥", Title: "腾讯云 SecretId", Query: `AKID`},
	{ID: "ks3-key", Category: "云厂商密钥", Title: "金山云 KS3", Query: `AKLT extension:yaml`},
	{ID: "qiniu-key", Category: "云厂商密钥", Title: "七牛密钥", Query: `QiNiuSecKey extension:toml`},
	{ID: "aws-key-pair", Category: "云厂商密钥", Title: "AWS 密钥对同现", Query: `AKIA "secret_access_key"`, Note: "代码里通常写成一对，命中即高危"},
	{ID: "aws-key-clean", Category: "云厂商密钥", Title: "AWS 密钥对（降噪）", Query: `AKIA "aws_secret_access_key" -extension:po -extension:md`, Note: "密钥对同现 + 排除翻译/文档，信噪比远高于裸 AKIA"},

	// ── 文件名定向（命中率最高） ──
	{ID: "config-toml-password", Category: "文件名定向", Title: "config.toml 中的密码", Query: `filename:config.toml password`},
	{ID: "config-toml-redis", Category: "文件名定向", Title: "config.toml 中的 Redis 配置", Query: `filename:config.toml redis`},
	{ID: "config-yml-secret", Category: "文件名定向", Title: "config.yml 中的 secret", Query: `filename:config.yml secret`},
	{ID: "config-yaml-apikey", Category: "文件名定向", Title: "config.yaml 中的 api_key", Query: `filename:config.yaml "api_key"`},
	{ID: "spring-datasource", Category: "文件名定向", Title: "Spring 数据源密码", Query: `filename:application.yml "datasource" password`, Note: "Java Spring 配置常堆密码"},
	{ID: "django-secret", Category: "文件名定向", Title: "Django SECRET_KEY", Query: `filename:settings.py SECRET_KEY`, Note: "Django 经典泄露"},
	{ID: "env-db-password", Category: "文件名定向", Title: ".env 数据库密码", Query: `filename:.env DB_PASSWORD`},
	{ID: "npmrc-token", Category: "文件名定向", Title: ".npmrc 发布 token", Query: `filename:.npmrc _authToken`},
	{ID: "pypirc-password", Category: "文件名定向", Title: ".pypirc 密码", Query: `filename:.pypirc password`},
	{ID: "gcp-credentials", Category: "文件名定向", Title: "GCP 服务账号", Query: `filename:credentials.json`, Note: "命中即高危"},
	{ID: "id-rsa", Category: "文件名定向", Title: "SSH 私钥入库", Query: `filename:id_rsa`},
	{ID: "config-json-secret", Category: "文件名定向", Title: "config.json 客户端密钥", Query: `filename:config.json "client_secret"`},

	// ── 服务指纹 ──
	{ID: "etcd-endpoint", Category: "服务指纹", Title: "etcd 端点泄露", Query: `filename:config.toml etcd_endpoint`},
	{ID: "redis-requirepass", Category: "服务指纹", Title: "Redis 密码", Query: `extension:conf requirepass`},
	{ID: "mongodb-conn", Category: "服务指纹", Title: "MongoDB 连接串", Query: `extension:yaml "mongodb://" password`},
	{ID: "ftp-password", Category: "服务指纹", Title: "FTP 密码", Query: `filename:config "ftp" password`, Note: "filename: 是子串匹配，config* 无需星号"},
	{ID: "smtp-password", Category: "服务指纹", Title: "SMTP 密码", Query: `extension:yaml smtp_password`},
	{ID: "jwt-secret", Category: "服务指纹", Title: "JWT secret", Query: `extension:yaml "jwt" secret`},
	{ID: "mysql-conn-js", Category: "服务指纹", Title: "MySQL 连接（JS）", Query: `extension:js "mysql://" password`},
	{ID: "mysqli-php", Category: "服务指纹", Title: "MySQL 连接（PHP）", Query: `extension:php "mysqli_connect" password`},
	{ID: "intranet-etcd", Category: "服务指纹", Title: "内网 IP 特征（etcd）", Query: `extension:toml "etcd" "10.1"`},
	{ID: "intranet-redis", Category: "服务指纹", Title: "内网 IP 特征（Redis）", Query: `extension:yaml "redis" "172.16"`},

	// ── 私钥块（内容指纹） ──
	{ID: "rsa-key", Category: "私钥块", Title: "RSA 私钥", Query: `"BEGIN RSA PRIVATE KEY" -extension:md`, Note: "md 里多是演示"},
	{ID: "openssh-key", Category: "私钥块", Title: "OpenSSH 私钥", Query: `"BEGIN OPENSSH PRIVATE KEY"`},
	{ID: "ec-key", Category: "私钥块", Title: "EC 私钥", Query: `"BEGIN EC PRIVATE KEY"`},
	{ID: "pem-key", Category: "私钥块", Title: "PEM 私钥", Query: `extension:pem "PRIVATE KEY"`},

	// ── org 定向（{org} 占位） ──
	{ID: "org-aws", Category: "org 定向", Title: "目标 org 的 AWS 密钥", Query: `org:{org} AKIA`},
	{ID: "org-env", Category: "org 定向", Title: "目标 org 的 .env", Query: `org:{org} filename:.env`},
	{ID: "org-apikey", Category: "org 定向", Title: "目标 org 的 api_key", Query: `org:{org} "api_key"`},
	{ID: "org-secret-json", Category: "org 定向", Title: "目标域名 secret_key（JSON）", Query: `"{domain}" "secret_key" extension:json`},
	{ID: "org-config-php", Category: "org 定向", Title: "目标域名 config.php", Query: `"{domain}" filename:config.php`},
}

// Templates 返回模板库（按分类原序）
func Templates() []DorkTemplate {
	out := make([]DorkTemplate, len(dorkLibrary))
	copy(out, dorkLibrary)
	return out
}

// TemplateByID 按 ID 取模板
func TemplateByID(id string) (DorkTemplate, bool) {
	for _, t := range dorkLibrary {
		if t.ID == id {
			return t, true
		}
	}
	return DorkTemplate{}, false
}

// BuildQuery 由模板 + 参数构造查询：org/domain 替换占位符
func BuildQuery(t DorkTemplate, org, domain string) string {
	q := t.Query
	if org != "" {
		q = strings.ReplaceAll(q, "{org}", org)
	}
	if domain != "" {
		q = strings.ReplaceAll(q, "{domain}", domain)
	}
	return q
}

// Client GitHub Code Search 客户端（token 通过闭包获取，支持设置页热更新）
type Client struct {
	// BaseURL API 端点覆盖(测试注入;空=https://api.github.com)。
	BaseURL string
	token   func() string
	http    *http.Client
	proxy   func() string // 出站代理（空=直连；每次请求时取，热更新生效）

	// GitHub Code Search 配额：已验证用户 10 次/分钟。滑动窗口排队，
	// 超过窗口的请求按到达顺序等待，避免 403 secondary rate limit。
	mu     sync.Mutex
	callTs []time.Time
}

// NewClient 创建客户端；tokenFn 每次调用时取最新 token（可为空 = 未配置）；
// proxyFn 每次请求时取代理地址（可空，热更新生效）
func NewClient(tokenFn func() string, proxyFn ...func() string) *Client {
	c := &Client{
		token: tokenFn,
		http:  &http.Client{Timeout: 20 * time.Second},
	}
	if len(proxyFn) > 0 {
		c.proxy = proxyFn[0]
	}
	return c
}

const (
	rateWindow   = time.Minute
	rateMaxCalls = 10
	maxResultCap = 1000 // GitHub Search API 结果绝对上限：page*per_page ≤ 1000
)

// waitQuota 滑动窗口限流，等到有配额或 ctx 取消
func (c *Client) waitQuota(ctx context.Context) error {
	for {
		c.mu.Lock()
		now := time.Now()
		// 清理过期时间戳
		valid := c.callTs[:0]
		for _, ts := range c.callTs {
			if now.Sub(ts) < rateWindow {
				valid = append(valid, ts)
			}
		}
		c.callTs = valid
		if len(c.callTs) < rateMaxCalls {
			c.callTs = append(c.callTs, now)
			c.mu.Unlock()
			return nil
		}
		// 窗口满：等最早一次调用滑出窗口
		wait := rateWindow - now.Sub(c.callTs[0]) + 50*time.Millisecond
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

type githubCodeItem struct {
	Name       string `json:"name"`
	Path       string `json:"path"`
	HTMLURL    string `json:"html_url"`
	Repository struct {
		FullName        string `json:"full_name"`
		HTMLURL         string `json:"html_url"`
		StargazersCount int    `json:"stargazers_count"`
		PushedAt        string `json:"pushed_at"`
		Fork            bool   `json:"fork"`
		Owner           struct {
			Login string `json:"login"`
		} `json:"owner"`
	} `json:"repository"`
	TextMatches []struct {
		Fragment string `json:"fragment"`
	} `json:"text_matches"`
}

type githubCodeResponse struct {
	TotalCount int              `json:"total_count"`
	Incomplete bool             `json:"incomplete_results"`
	Items      []githubCodeItem `json:"items"`
	Message    string           `json:"message"`
}

// Search 执行 Code Search。page 从 1 开始；perPage ≤ 100。
// 只报“疑似泄露 + 证据位置”，不验证密钥有效性（验证他人凭据是独立的高风险动作，应走 HITL）。
func (c *Client) Search(ctx context.Context, query string, page, perPage int) (*SearchResult, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, fmt.Errorf("查询不能为空")
	}
	if c.token == nil || c.token() == "" {
		return nil, fmt.Errorf("未配置 GitHub Token（系统设置 → 空间测绘同页的 GitHub 泄露搜索区,或 GITHUB_TOKEN 环境变量）")
	}
	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 100 {
		perPage = 30
	}

	if err := c.waitQuota(ctx); err != nil {
		return nil, fmt.Errorf("等待配额时被取消: %w", err)
	}

	base := strings.TrimSpace(c.BaseURL)
	if base == "" {
		base = "https://api.github.com"
	}
	u := fmt.Sprintf("%s/search/code?q=%s&page=%d&per_page=%d",
		base, url.QueryEscape(query), page, perPage)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json, application/vnd.github.text-match+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36")
	req.Header.Set("Authorization", "Bearer "+c.token())

	client := c.http
	if c.proxy != nil {
		if pu, perr := url.Parse(strings.TrimSpace(c.proxy())); perr == nil && pu.Scheme != "" && pu.Host != "" {
			client = &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound {
		// 403 多为配额（含 secondary limit）；code search 404 常见于 token 无 code search 权限
		msg := ghMessage(body)
		if msg == "" {
			msg = resp.Status
		}
		return nil, fmt.Errorf("GitHub API 拒绝（%d）: %s", resp.StatusCode, msg)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API %s: %s", resp.Status, ghMessage(body))
	}

	var gr githubCodeResponse
	if err := json.Unmarshal(body, &gr); err != nil {
		return nil, fmt.Errorf("解析 GitHub 响应失败: %w", err)
	}

	out := &SearchResult{
		TotalCount: gr.TotalCount,
		Incomplete: gr.Incomplete,
		Query:      query,
		Page:       page,
		PerPage:    perPage,
		Truncated:  page*perPage >= maxResultCap,
		Items:      make([]CodeMatch, 0, len(gr.Items)),
	}
	for _, it := range gr.Items {
		m := CodeMatch{
			Repo:       it.Repository.FullName,
			RepoStars:  it.Repository.StargazersCount,
			RepoURL:    it.Repository.HTMLURL,
			Path:       it.Path,
			FileURL:    it.HTMLURL,
			OwnerLogin: it.Repository.Owner.Login,
			PushedAt:   it.Repository.PushedAt,
			IsFork:     it.Repository.Fork,
			Fragments:  make([]string, 0, len(it.TextMatches)),
		}
		for _, tm := range it.TextMatches {
			frag := strings.TrimSpace(tm.Fragment)
			if frag != "" && len(frag) > 240 {
				frag = frag[:240] + "…"
			}
			m.Fragments = append(m.Fragments, frag)
		}
		out.Items = append(out.Items, m)
	}
	return out, nil
}

func ghMessage(body []byte) string {
	var e struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &e); err != nil {
		log.Printf("[githubsearch] 解析 GitHub 错误响应失败(按空 message 处理): %v", err)
	}
	return e.Message
}
