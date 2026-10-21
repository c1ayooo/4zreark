package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/c1ayooo/4zreark/internal/useragent"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	reconfp "github.com/c1ayooo/4zreark/internal/recon/fingerprint"
	"github.com/c1ayooo/4zreark/repo"
)

// 指纹上游同步：wappalyzergo / webanalyze / dddd 三个来源，24 小时一轮。
//
// 与 T10 的内置快照同步（FingerprintSyncService.SyncEmbedded）分工：
//   - 内置快照保证离线开箱可用；
//   - 上游同步在内容哈希变化时才重导，只动同 source 的规则；
//   - 上游全部不可达时 dddd 回落到内置快照，其余来源保留旧规则并记账。
//
// 翻译器直接复用 internal/recon/fingerprint 里已被单测覆盖的三个 Parser，
// 后端只负责拉取、哈希、来源隔离与调度。

const (
	fpUpstreamTimeout  = 45 * time.Second
	fpUpstreamMaxBody  = 64 << 20
	fpUpstreamInterval = 24 * time.Hour
)

// FpUpstreamSource 是一个上游来源（测试可注入）。
type FpUpstreamSource struct {
	Name          string
	URLs          []string
	CategoriesURL string
	Parse         func([]byte, map[string]string) ([]reconfp.Rule, reconfp.WappalyzerImportStats, error)
	Snapshot      []reconfp.Rule // 可选：上游全部不可达时的兜底
}

// FpUpstreamOutcome 是单源同步结果。
type FpUpstreamOutcome struct {
	Source   string `json:"source"`
	Changed  bool   `json:"changed"`
	Imported int    `json:"imported"`
	Reason   string `json:"reason"` // imported / unchanged / snapshot / failed
	Hash     string `json:"content_hash,omitempty"`
	Error    string `json:"error,omitempty"`
}

// FingerprintUpstreamService 负责拉取上游规则并写入 fingerprint_rules。
type FingerprintUpstreamService struct {
	sources []FpUpstreamSource
	client  *http.Client
	now     func() time.Time

	stop chan struct{}
	once sync.Once
}

func NewFingerprintUpstreamService() *FingerprintUpstreamService {
	return &FingerprintUpstreamService{
		sources: defaultFpUpstreamSources(),
		client:  &http.Client{Timeout: fpUpstreamTimeout},
		now:     time.Now,
		stop:    make(chan struct{}),
	}
}

func defaultFpUpstreamSources() []FpUpstreamSource {
	return []FpUpstreamSource{
		{
			Name: reconfp.SourceWappalyzergo,
			URLs: []string{
				"https://raw.githubusercontent.com/projectdiscovery/wappalyzergo/master/fingerprints_data.json",
				"https://raw.githubusercontent.com/projectdiscovery/wappalyzergo/main/fingerprints_data.json",
				"https://cdn.jsdelivr.net/gh/projectdiscovery/wappalyzergo@master/fingerprints_data.json",
			},
			CategoriesURL: "https://raw.githubusercontent.com/projectdiscovery/wappalyzergo/master/categories_data.json",
			Parse:         reconfp.ParseWappalyzergoFingerprints,
		},
		{
			Name: reconfp.SourceWebanalyze,
			URLs: []string{
				"https://raw.githubusercontent.com/rverton/webanalyze/master/technologies.json",
				"https://raw.githubusercontent.com/rverton/webanalyze/main/technologies.json",
				"https://cdn.jsdelivr.net/gh/rverton/webanalyze@master/technologies.json",
			},
			Parse: func(data []byte, _ map[string]string) ([]reconfp.Rule, reconfp.WappalyzerImportStats, error) {
				return reconfp.ParseWappalyzerTechnologies(data)
			},
		},
		{
			Name: reconfp.SourceDddd,
			URLs: []string{
				"https://raw.githubusercontent.com/SleepingBag945/dddd/main/common/config/finger.yaml",
				"https://cdn.jsdelivr.net/gh/SleepingBag945/dddd@main/common/config/finger.yaml",
			},
			Parse: func(data []byte, _ map[string]string) ([]reconfp.Rule, reconfp.WappalyzerImportStats, error) {
				return reconfp.ParseDdddFinger(data)
			},
			Snapshot: embeddedDdddRules(),
		},
	}
}

// embeddedDdddRules 只取内置规则集里的 dddd 快照，不含种子规则。
func embeddedDdddRules() []reconfp.Rule {
	all := reconfp.DefaultRuleSet()
	out := make([]reconfp.Rule, 0, len(all))
	for _, r := range all {
		if r.Source == reconfp.SourceDddd {
			out = append(out, r)
		}
	}
	return out
}

func (s *FingerprintUpstreamService) syncRepo() (repo.FingerprintSyncRepo, error) {
	if repo.Default() == nil {
		return nil, fmt.Errorf("数据层未初始化")
	}
	return repo.Default().FingerprintSync(), nil
}

// SyncUpstream 同步全部来源；force=true 时内容哈希相同也重导。
func (s *FingerprintUpstreamService) SyncUpstream(ctx context.Context, force bool) ([]FpUpstreamOutcome, error) {
	syncRepo, err := s.syncRepo()
	if err != nil {
		return nil, err
	}
	metas, err := syncRepo.ListSources(ctx)
	if err != nil {
		return nil, err
	}
	bySource := make(map[string]repo.FpSourceMeta, len(metas))
	for _, m := range metas {
		bySource[m.Name] = m
	}

	out := make([]FpUpstreamOutcome, 0, len(s.sources))
	token := NewSourceService().GitHubToken(ctx)
	for _, src := range s.sources {
		out = append(out, s.runSource(ctx, syncRepo, src, bySource[src.Name], force, token))
	}
	NewFingerprintService().Invalidate()
	return out, nil
}

func (s *FingerprintUpstreamService) runSource(ctx context.Context, syncRepo repo.FingerprintSyncRepo, src FpUpstreamSource, meta repo.FpSourceMeta, force bool, token string) FpUpstreamOutcome {
	out := FpUpstreamOutcome{Source: src.Name, Reason: "failed"}
	client := s.client
	if client == nil {
		client = &http.Client{Timeout: fpUpstreamTimeout}
	}

	var lastErr error
	for _, rawURL := range src.URLs {
		data, err := fetchFpUpstream(ctx, client, rawURL, token)
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", shortFpURL(rawURL), err)
			continue
		}
		sum := sha256.Sum256(data)
		hash := hex.EncodeToString(sum[:])
		out.Hash = hash
		if !force && meta.ContentHash != "" && meta.ContentHash == hash {
			out.Reason = "unchanged"
			return out
		}

		var catNames map[string]string
		if src.CategoriesURL != "" {
			if catData, cerr := fetchFpUpstream(ctx, client, src.CategoriesURL, token); cerr == nil {
				catNames = reconfp.WappalyzergoCategories(catData)
			}
		}
		rawRules, stats, perr := src.Parse(data, catNames)
		if perr != nil {
			out.Error = "翻译失败: " + perr.Error()
			return out
		}
		rules, merged, skipped := mergeUpstreamRules(rawRules)
		skipped += stats.PatternsSkipped
		if len(rules) == 0 {
			out.Error = "上游解析结果为空，保留现有规则"
			return out
		}
		imported, ierr := syncRepo.ImportUpstream(ctx, src.Name, rawURL, hash, rules, skipped+merged)
		if ierr != nil {
			out.Error = ierr.Error()
			return out
		}
		out.Changed = meta.ContentHash != ""
		out.Imported = imported
		out.Reason = "imported"
		return out
	}

	// 上游全部不可达：有内置快照的来源兜底，其余保留旧规则。
	if len(src.Snapshot) > 0 {
		return s.importSnapshot(ctx, syncRepo, src, meta)
	}
	if lastErr != nil {
		out.Error = lastErr.Error()
	}
	return out
}

func (s *FingerprintUpstreamService) importSnapshot(ctx context.Context, syncRepo repo.FingerprintSyncRepo, src FpUpstreamSource, meta repo.FpSourceMeta) FpUpstreamOutcome {
	out := FpUpstreamOutcome{Source: src.Name}
	rules, merged, skipped := mergeUpstreamRules(src.Snapshot)
	if len(rules) == 0 {
		out.Reason = "failed"
		out.Error = "内置快照为空"
		return out
	}
	hash := fpContentHash(rules)
	out.Hash = hash
	if meta.ContentHash == hash {
		out.Reason = "unchanged"
		return out
	}
	imported, err := syncRepo.ImportUpstream(ctx, src.Name, "builtin:snapshot", hash, rules, skipped+merged)
	if err != nil {
		out.Reason = "failed"
		out.Error = err.Error()
		return out
	}
	out.Changed = true
	out.Imported = imported
	out.Reason = "snapshot"
	return out
}

// mergeUpstreamRules 按 name 合并同名规则（OR 表达式），并丢弃空名/空表达式。
func mergeUpstreamRules(raw []reconfp.Rule) (rules []repo.FpSyncRule, merged, skipped int) {
	index := map[string]int{}
	for _, r := range raw {
		name := strings.TrimSpace(r.Name)
		expr := strings.TrimSpace(r.Expression)
		if name == "" || expr == "" {
			skipped++
			continue
		}
		// rule_hash 对 name 小写归一，分组也必须大小写不敏感。
		key := strings.ToLower(name)
		if i, ok := index[key]; ok {
			rules[i].Expression = "(" + rules[i].Expression + ") || (" + expr + ")"
			rules[i].RuleHash = fpRuleHash(rules[i].Name, rules[i].Expression)
			merged++
			continue
		}
		index[key] = len(rules)
		rules = append(rules, repo.FpSyncRule{
			Name: name, Category: r.Category, Expression: expr,
			RuleHash: fpRuleHash(name, expr),
		})
	}
	return rules, merged, skipped
}

func fetchFpUpstream(ctx context.Context, client *http.Client, rawURL, token string) ([]byte, error) {
	reqCtx, cancel := context.WithTimeout(ctx, fpUpstreamTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	if token = strings.TrimSpace(token); token != "" {
		// token 只发给 GitHub 自己的域名，避免泄漏到 jsdelivr 这类 CDN。
		host := strings.ToLower(req.URL.Host)
		if strings.HasSuffix(host, "github.com") || strings.HasSuffix(host, "githubusercontent.com") {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	}
	req.Header.Set("User-Agent", useragent.Pick())
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, fpUpstreamMaxBody))
	if err != nil {
		return nil, err
	}
	if len(data) >= fpUpstreamMaxBody {
		return nil, fmt.Errorf("响应超过 %dMB 上限", fpUpstreamMaxBody>>20)
	}
	return data, nil
}

func shortFpURL(raw string) string {
	raw = strings.TrimPrefix(strings.TrimPrefix(raw, "https://"), "http://")
	if len(raw) > 80 {
		raw = raw[:80] + "…"
	}
	return raw
}

// freshEnough 判断三个来源是否都在 24 小时内同步过。
func (s *FingerprintUpstreamService) freshEnough(ctx context.Context) bool {
	syncRepo, err := s.syncRepo()
	if err != nil {
		return false
	}
	metas, err := syncRepo.ListSources(ctx)
	if err != nil {
		return false
	}
	bySource := make(map[string]time.Time, len(metas))
	for _, m := range metas {
		// 内置快照落库（embedded://）只说明离线兜底跑过，不代表上游拉取过；
		// 否则启动时 SyncEmbedded 会让 dddd 永远显示「新鲜」，上游永远不拉。
		if strings.HasPrefix(m.UpstreamURL, "embedded://") {
			continue
		}
		bySource[m.Name] = m.FetchedAt
	}
	now := s.now()
	for _, src := range s.sources {
		at, ok := bySource[src.Name]
		if !ok || now.Sub(at) >= fpUpstreamInterval {
			return false
		}
	}
	return true
}

// Start 启动每日同步：2 分钟手动窗口后先补一轮，之后每 24 小时。
// 不再在启动时调用 SyncEmbedded：那会用内置 dddd 快照覆盖已从上游更新的同源规则。
func (s *FingerprintUpstreamService) Start() {
	s.once.Do(func() {
		go func() {
			select {
			case <-s.stop:
				return
			case <-time.After(2 * time.Minute):
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			if !s.freshEnough(ctx) {
				if outcomes, err := s.SyncUpstream(ctx, false); err != nil {
					log.Printf("[Fingerprint] 上游同步失败: %v", err)
				} else {
					for _, o := range outcomes {
						log.Printf("[Fingerprint] 上游 %s: %s imported=%d err=%s", o.Source, o.Reason, o.Imported, o.Error)
					}
				}
			}
			cancel()
			timer := time.NewTimer(fpUpstreamInterval)
			defer timer.Stop()
			for {
				select {
				case <-s.stop:
					return
				case <-timer.C:
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
					if _, err := s.SyncUpstream(ctx, false); err != nil {
						log.Printf("[Fingerprint] 上游同步失败: %v", err)
					}
					cancel()
					timer.Reset(fpUpstreamInterval)
				}
			}
		}()
	})
}

func (s *FingerprintUpstreamService) Stop() {
	select {
	case <-s.stop:
	default:
		close(s.stop)
	}
}
