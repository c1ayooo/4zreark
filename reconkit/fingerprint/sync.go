package fingerprint

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// 指纹库自动同步:周期拉取上游指纹库,SHA-256 内容哈希与本地记录不一致时
// 重新翻译导入;各来源独立追踪,新集合之外的旧 source 规则删除,custom 种子
// 不受影响。上游全部候选不可达时用内置快照兜底(离线开箱即用)。移植自老
// 4zreco update.go,裁掉 token 池与结构化日志(匿名 raw + 可选单 token)。
//
// 来源:
//   - wappalyzergo: projectdiscovery/wappalyzergo fingerprints_data.json(国际主源)
//   - webanalyze:   rverton/webanalyze technologies.json(历史源保鲜)
//   - dddd:         SleepingBag945/dddd finger.yaml(国内覆盖,7835 条,含内置快照)

const (
	upstreamFetchTimeout = 90 * time.Second
	maxUpstreamBody      = 64 << 20 // 64MB;上游全量 JSON 约 2-4MB,留余量
	syncInterval         = 24 * time.Hour
)

// Store 指纹规则的 PG 存储。持有 *sql.DB(database/sql 标准句柄),与宿主
// 的 db.DB 兼容(其内嵌 *sql.DB)。
type Store struct{ db *sql.DB }

// NewStore 建表并返回存储。
func NewStore(db *sql.DB) (*Store, error) {
	s := &Store{db: db}
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS fingerprint_rules(
 id TEXT PRIMARY KEY,
 name TEXT NOT NULL,
 category TEXT NOT NULL DEFAULT '',
 expression TEXT NOT NULL,
 enabled BOOLEAN NOT NULL DEFAULT TRUE,
 source TEXT NOT NULL DEFAULT 'custom',
 rule_hash TEXT NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now());
 CREATE UNIQUE INDEX IF NOT EXISTS uniq_fingerprint_rules_hash ON fingerprint_rules(rule_hash);
 CREATE INDEX IF NOT EXISTS idx_fingerprint_rules_enabled ON fingerprint_rules(enabled);
 CREATE TABLE IF NOT EXISTS fingerprint_sources(
 name TEXT PRIMARY KEY,
 upstream_url TEXT NOT NULL DEFAULT '',
 content_hash TEXT NOT NULL DEFAULT '',
 rule_count INT NOT NULL DEFAULT 0,
 skipped_count INT NOT NULL DEFAULT 0,
 fetched_at TIMESTAMPTZ NOT NULL DEFAULT now());`)
	return s, err
}

// SourceMeta 来源元数据。
type SourceMeta struct {
	Name        string
	UpstreamURL string
	ContentHash string
	RuleCount   int
	Skipped     int
	FetchedAt   string
}

// GetSourceMeta 读来源元数据;不存在返回 (zero, false, nil)。
func (s *Store) GetSourceMeta(ctx context.Context, name string) (SourceMeta, bool, error) {
	var m SourceMeta
	var fetched sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT name, upstream_url, content_hash, rule_count, skipped_count, fetched_at
		FROM fingerprint_sources WHERE name=$1`, name,
	).Scan(&m.Name, &m.UpstreamURL, &m.ContentHash, &m.RuleCount, &m.Skipped, &fetched)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return SourceMeta{}, false, nil
		}
		return SourceMeta{}, false, err
	}
	m.FetchedAt = fetched.String
	return m, true, nil
}

func ruleHash(name, expression string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(name)) + "\x00" + strings.TrimSpace(expression)))
	return hex.EncodeToString(sum[:])
}

// ImportUpstream 事务内:来源规则按 rule_hash 全量 upsert、新集合之外的旧
// source 规则删除、来源元数据更新。custom 规则不受影响。
func (s *Store) ImportUpstream(ctx context.Context, sourceName, upstreamURL, contentHash string, rules []Rule, skipped int) (int, error) {
	if len(rules) == 0 {
		return 0, fmt.Errorf("导入集合为空,拒绝导入(疑似上游异常)")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	hashes := make([]string, 0, len(rules))
	for i := range rules {
		r := &rules[i]
		r.Source = sourceName
		r.RuleHash = ruleHash(r.Name, r.Expression)
		hashes = append(hashes, r.RuleHash)
		if _, err := tx.ExecContext(ctx, `INSERT INTO fingerprint_rules(id,name,category,expression,enabled,source,rule_hash,created_at,updated_at)
			VALUES('fp_'||md5(random()::text||clock_timestamp()::text),$1,$2,$3,TRUE,$4,$5,now(),now())
			ON CONFLICT (rule_hash) DO UPDATE SET name=EXCLUDED.name, category=EXCLUDED.category,
				expression=EXCLUDED.expression, enabled=TRUE, updated_at=now()`,
			r.Name, r.Category, r.Expression, sourceName, r.RuleHash); err != nil {
			return 0, fmt.Errorf("upsert 规则 %s: %w", r.Name, err)
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM fingerprint_rules WHERE source=$1 AND NOT (rule_hash = ANY($2))`,
		sourceName, hashes); err != nil {
		return 0, fmt.Errorf("清理失效规则: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO fingerprint_sources(name, upstream_url, content_hash, rule_count, skipped_count, fetched_at)
		VALUES($1,$2,$3,$4,$5,now())
		ON CONFLICT (name) DO UPDATE SET upstream_url=EXCLUDED.upstream_url, content_hash=EXCLUDED.content_hash,
			rule_count=EXCLUDED.rule_count, skipped_count=EXCLUDED.skipped_count, fetched_at=now()`,
		sourceName, upstreamURL, contentHash, len(rules), skipped); err != nil {
		return 0, fmt.Errorf("更新来源元数据: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	CacheInvalidate()
	return len(rules), nil
}

// OldestFetchUnix 返回各来源中最早一次成功同步的 Unix 时间；无记录返回 0。
func (s *Store) OldestFetchUnix(ctx context.Context) int64 {
	var ts sql.NullInt64
	_ = s.db.QueryRowContext(ctx,
		`SELECT EXTRACT(EPOCH FROM MIN(fetched_at))::bigint FROM fingerprint_sources`).Scan(&ts)
	if !ts.Valid {
		return 0
	}
	return ts.Int64
}

// signature 规则库签名(条数+最新更新时间):不变即复用编译缓存。
func (s *Store) signature(ctx context.Context) string {
	var n int64
	var latest sql.NullString
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*), MAX(updated_at)::text FROM fingerprint_rules`).Scan(&n, &latest)
	return fmt.Sprintf("%d|%s", n, latest.String)
}

// EnabledRules 编译启用的规则(供匹配)。
func (s *Store) EnabledRules(ctx context.Context) ([]CompiledRule, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, COALESCE(category,''), expression FROM fingerprint_rules WHERE enabled`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]CompiledRule, 0, 256)
	for rows.Next() {
		var r CompiledRule
		if err := rows.Scan(&r.ID, &r.Name, &r.Category, &r.Expression); err != nil {
			return nil, err
		}
		expr, err := ParseExpression(r.Expression)
		if err != nil {
			continue // 单条畸形不拖垮整个规则集
		}
		r.Expr = expr
		out = append(out, r)
	}
	return out, rows.Err()
}

// ActiveRules 匹配用的当前规则集:store 有规则走 store(带编译缓存),
// store 为空(首次同步未完成)回退内置快照——保证任何时刻都有规则可用。
func ActiveRules(db *sql.DB) []CompiledRule {
	if db == nil {
		return DefaultRules()
	}
	s := &Store{db: db}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sig := s.signature(ctx)
	if rules, ok := CacheGet(sig); ok {
		return rules
	}
	rules, err := s.EnabledRules(ctx)
	if err != nil || len(rules) == 0 {
		return DefaultRules()
	}
	CachePut(sig, rules)
	return rules
}

// ---- Updater ----

// SourceOutcome 单一来源的同步结果。
type SourceOutcome struct {
	Source   string `json:"source"`
	Changed  bool   `json:"changed"`
	Hash     string `json:"content_hash,omitempty"`
	Imported int    `json:"imported,omitempty"`
	Reason   string `json:"reason"` // unchanged/imported/failed
	Error    string `json:"error,omitempty"`
}

// Progress 是一次同步的阶段进度，供前端进度条展示。
type Progress struct {
	Phase   string `json:"phase"`
	Percent int    `json:"percent"`
	Message string `json:"message,omitempty"`
}

type upstreamSource struct {
	Name       string
	Candidates []string
	Categories string
	Snapshot   []byte
	Parse      func(data []byte, catNames map[string]string) ([]Rule, WappalyzerImportStats, error)
}

var builtinSources = []upstreamSource{
	{
		Name:       SourceWappalyzergo,
		Candidates: []string{"https://raw.githubusercontent.com/projectdiscovery/wappalyzergo/master/fingerprints_data.json", "https://raw.githubusercontent.com/projectdiscovery/wappalyzergo/main/fingerprints_data.json", "https://cdn.jsdelivr.net/gh/projectdiscovery/wappalyzergo@master/fingerprints_data.json"},
		Categories: "https://raw.githubusercontent.com/projectdiscovery/wappalyzergo/master/categories_data.json",
		Parse:      ParseWappalyzergoFingerprints,
	},
	{
		Name:       SourceWebanalyze,
		Candidates: []string{"https://raw.githubusercontent.com/rverton/webanalyze/master/technologies.json", "https://raw.githubusercontent.com/rverton/webanalyze/main/technologies.json", "https://cdn.jsdelivr.net/gh/rverton/webanalyze@master/technologies.json"},
		Parse: func(data []byte, _ map[string]string) ([]Rule, WappalyzerImportStats, error) {
			return ParseWappalyzerTechnologies(data)
		},
	},
	{
		Name:       SourceDddd,
		Candidates: []string{"https://raw.githubusercontent.com/SleepingBag945/dddd/main/common/config/finger.yaml", "https://cdn.jsdelivr.net/gh/SleepingBag945/dddd@main/common/config/finger.yaml"},
		Snapshot:   ddddSnapshotYAML,
		Parse: func(data []byte, _ map[string]string) ([]Rule, WappalyzerImportStats, error) {
			return ParseDdddFinger(data)
		},
	},
}

// Updater 周期同步器;tokenFn / proxyFn 可为空。
type Updater struct {
	store   *Store
	tokenFn func() string
	proxyFn func() string

	mu      sync.Mutex
	syncing bool
	stop    chan struct{}
}

// NewUpdater 构造;tokenFn 返回 GitHub token(可选,加速/提额用);
// proxyFn 返回当前同步出口代理(空=直连/跟随环境变量)。
func NewUpdater(store *Store, tokenFn, proxyFn func() string) *Updater {
	return &Updater{store: store, tokenFn: tokenFn, proxyFn: proxyFn, stop: make(chan struct{})}
}

// Start 启动：先留 2 分钟手动更新窗口；之后若数据不新鲜（任一来源超过
// 24h）再自动同步，此后每 24 小时。
func (u *Updater) Start() {
	go func() {
		select {
		case <-u.stop:
			return
		case <-time.After(2 * time.Minute):
		}
		if !u.freshEnough() {
			u.SyncAll(context.Background())
		}
		timer := time.NewTimer(syncInterval)
		defer timer.Stop()
		for {
			select {
			case <-u.stop:
				return
			case <-timer.C:
				u.SyncAll(context.Background())
				timer.Reset(syncInterval)
			}
		}
	}()
}

func (u *Updater) freshEnough() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	oldest := u.store.OldestFetchUnix(ctx)
	return oldest > 0 && time.Since(time.Unix(oldest, 0)) < syncInterval
}

// Syncing 是否同步进行中。
func (u *Updater) Syncing() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.syncing
}

// SyncAll 逐来源「拉取→哈希比对→变更才导入」;单源失败不影响其他源。
func (u *Updater) SyncAll(ctx context.Context) []SourceOutcome {
	return u.SyncAllWithProgress(ctx, nil)
}

// SyncAllWithProgress 与 SyncAll 相同，但按来源报告阶段进度。
func (u *Updater) SyncAllWithProgress(ctx context.Context, progress func(Progress)) []SourceOutcome {
	u.mu.Lock()
	if u.syncing {
		u.mu.Unlock()
		return nil
	}
	u.syncing = true
	u.mu.Unlock()
	defer func() {
		u.mu.Lock()
		u.syncing = false
		u.mu.Unlock()
	}()

	token := ""
	if u.tokenFn != nil {
		token = strings.TrimSpace(u.tokenFn())
	}
	total := len(builtinSources)
	outcomes := make([]SourceOutcome, 0, total)
	for i, src := range builtinSources {
		reportProgress(progress, "同步 "+src.Name, i*100/total, "拉取上游…")
		runCtx, cancel := context.WithTimeout(ctx, upstreamFetchTimeout*3+30*time.Second)
		so := u.runSource(runCtx, src, token)
		cancel()
		outcomes = append(outcomes, so)
		msg := so.Reason
		if so.Error != "" {
			msg = "失败: " + so.Error
			log.Printf("[fingerprint] 同步 %s 失败: %s", so.Source, so.Error)
		} else {
			log.Printf("[fingerprint] 同步 %s: %s (导入 %d 条)", so.Source, so.Reason, so.Imported)
		}
		reportProgress(progress, "同步 "+src.Name, (i+1)*100/total, msg)
	}
	reportProgress(progress, "完成", 100, "")
	return outcomes
}

func reportProgress(progress func(Progress), phase string, percent int, message string) {
	if progress == nil {
		return
	}
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}
	progress(Progress{Phase: phase, Percent: percent, Message: message})
}

func (u *Updater) runSource(ctx context.Context, src upstreamSource, token string) SourceOutcome {
	so := SourceOutcome{Source: src.Name, Reason: "failed"}
	meta, _, _ := u.store.GetSourceMeta(ctx, src.Name)
	client := u.httpClient()

	var lastErr error
	for _, candidate := range src.Candidates {
		data, err := fetchUpstream(ctx, candidate, token, client)
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", shortURL(candidate), err)
			continue
		}
		sum := sha256.Sum256(data)
		hash := hex.EncodeToString(sum[:])
		if meta.ContentHash != "" && meta.ContentHash == hash {
			so.Reason = "unchanged"
			so.Hash = hash
			return so
		}
		var catNames map[string]string
		if src.Categories != "" {
			if catData, cerr := fetchUpstream(ctx, src.Categories, token, client); cerr == nil {
				catNames = wappalyzergoCategories(catData)
			}
		}
		rules, stats, perr := src.Parse(data, catNames)
		if perr != nil {
			so.Error = fmt.Sprintf("翻译失败: %v", perr)
			return so
		}
		imported, ierr := u.store.ImportUpstream(ctx, src.Name, candidate, hash, rules, stats.PatternsSkipped)
		if ierr != nil {
			so.Error = ierr.Error()
			return so
		}
		so.Changed = meta.ContentHash != ""
		so.Hash = hash
		so.Imported = imported
		so.Reason = "imported"
		return so
	}
	// 上游全部不可达(离线常态):有快照的来源兜底导入,保证开箱即用。
	if lastErr != nil && len(src.Snapshot) > 0 {
		return u.importSnapshot(ctx, src)
	}
	if lastErr != nil {
		so.Error = lastErr.Error()
	}
	return so
}

func (u *Updater) importSnapshot(ctx context.Context, src upstreamSource) SourceOutcome {
	so := SourceOutcome{Source: src.Name}
	sum := sha256.Sum256(src.Snapshot)
	hash := hex.EncodeToString(sum[:])
	so.Hash = hash
	meta, _, _ := u.store.GetSourceMeta(ctx, src.Name)
	if meta.ContentHash == hash {
		so.Reason = "unchanged"
		return so
	}
	rules, stats, err := src.Parse(src.Snapshot, nil)
	if err != nil {
		so.Reason = "failed"
		so.Error = fmt.Sprintf("内置快照翻译失败: %v", err)
		return so
	}
	imported, ierr := u.store.ImportUpstream(ctx, src.Name, "builtin:snapshot", hash, rules, stats.PatternsSkipped)
	if ierr != nil {
		so.Reason = "failed"
		so.Error = ierr.Error()
		return so
	}
	so.Changed = meta.ContentHash != ""
	so.Imported = imported
	so.Reason = "imported"
	return so
}

func shortURL(raw string) string {
	raw = strings.TrimPrefix(strings.TrimPrefix(raw, "https://"), "http://")
	if i := strings.IndexByte(raw, '?'); i >= 0 {
		raw = raw[:i]
	}
	if len(raw) > 80 {
		raw = raw[:80] + "…"
	}
	return raw
}

// httpClient 每次同步按当前代理设置构造客户端，设置改动无需重启。
func (u *Updater) httpClient() *http.Client {
	tr := &http.Transport{Proxy: http.ProxyFromEnvironment}
	if u.proxyFn != nil {
		if p := strings.TrimSpace(u.proxyFn()); p != "" {
			if parsed, err := url.Parse(p); err == nil && parsed.Host != "" {
				tr.Proxy = http.ProxyURL(parsed)
			}
		}
	}
	return &http.Client{Timeout: upstreamFetchTimeout, Transport: tr}
}

// fetchUpstream 拉取上游文件;token 非空附带凭据(api.github.com 用 raw Accept)。
func fetchUpstream(ctx context.Context, rawURL, token string, client *http.Client) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, upstreamFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
		if strings.HasPrefix(rawURL, "https://api.github.com/") {
			req.Header.Set("Accept", "application/vnd.github.raw")
		}
	}
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxUpstreamBody))
	if err != nil {
		return nil, err
	}
	if len(data) >= maxUpstreamBody {
		return nil, fmt.Errorf("body 超过 %dMB 上限", maxUpstreamBody>>20)
	}
	return data, nil
}

// FingerprintRuleRow 规则库列表行(前端指纹规则库页)。
type FingerprintRuleRow struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Category   string `json:"category"`
	Expression string `json:"expression"`
	Source     string `json:"source"`
	Enabled    bool   `json:"enabled"`
}

// FingerprintSourceRow 数据源同步状态行。
type FingerprintSourceRow struct {
	Name        string `json:"name"`
	UpstreamURL string `json:"upstream_url"`
	RuleCount   int    `json:"rule_count"`
	FetchedAt   string `json:"fetched_at"`
}

// ListRulesPage 规则分页(名称/类别/来源模糊搜索)。
func (s *Store) ListRulesPage(ctx context.Context, query, source string, limit, offset int) ([]FingerprintRuleRow, int, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	where := "TRUE"
	args := []any{}
	if query != "" {
		args = append(args, "%"+query+"%")
		where += fmt.Sprintf(" AND (name ILIKE $%d OR category ILIKE $%d OR expression ILIKE $%d)", len(args), len(args), len(args))
	}
	if source != "" {
		args = append(args, source)
		where += fmt.Sprintf(" AND source=$%d", len(args))
	}
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM fingerprint_rules WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, limit, offset)
	rows, err := s.db.QueryContext(ctx, `
SELECT id, name, category, expression, source, enabled FROM fingerprint_rules WHERE `+where+`
ORDER BY source, name LIMIT `+fmt.Sprintf("$%d OFFSET $%d", len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := make([]FingerprintRuleRow, 0, limit)
	for rows.Next() {
		var r FingerprintRuleRow
		if err := rows.Scan(&r.ID, &r.Name, &r.Category, &r.Expression, &r.Source, &r.Enabled); err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}

// ListSources 数据源同步状态(含规则计数)。
func (s *Store) ListSources(ctx context.Context) ([]FingerprintSourceRow, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT name, upstream_url, rule_count, fetched_at FROM fingerprint_sources ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []FingerprintSourceRow{}
	for rows.Next() {
		var r FingerprintSourceRow
		if err := rows.Scan(&r.Name, &r.UpstreamURL, &r.RuleCount, &r.FetchedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
