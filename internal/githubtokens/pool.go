// Package githubtokens GitHub API Token 池：多账号额度管理与轮换。
// GitHub 免费额度 5000 次/日/号，单号打满会阻塞泄露监控/PoC 富化等消费方；
// 池按剩余配额轮换选择 token，并缓存各号 rate_limit 供仪表盘展示。
package githubtokens

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Token 池中一条账号记录。Token 明文仅服务端持有：API 只回显 Masked。
type Token struct {
	ID            string     `json:"id"`
	Label         string     `json:"label"`
	Token         string     `json:"-"`
	Masked        string     `json:"masked"`
	Enabled       bool       `json:"enabled"`
	RateLimit     int        `json:"rate_limit"`
	RateRemaining int        `json:"rate_remaining"` // -1=未采集
	RateUsed      int        `json:"rate_used"`
	RateResetAt   *time.Time `json:"rate_reset_at"`
	LastCheckedAt *time.Time `json:"last_checked_at"`
	CreatedAt     time.Time  `json:"created_at"`
}

type DB interface {
	Exec(string, ...any) (sql.Result, error)
	Query(string, ...any) (*sql.Rows, error)
	QueryRow(string, ...any) *sql.Row
}

type Store struct {
	db *sql.DB
}

func NewStore(db *sql.DB) (*Store, error) {
	s := &Store{db: db}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS github_token_pool (
		id TEXT PRIMARY KEY,
		label TEXT NOT NULL DEFAULT '',
		token TEXT NOT NULL,
		enabled INTEGER NOT NULL DEFAULT 1,
		rate_limit INTEGER NOT NULL DEFAULT 0,
		rate_remaining INTEGER NOT NULL DEFAULT -1,
		rate_used INTEGER NOT NULL DEFAULT 0,
		rate_reset_at TIMESTAMPTZ,
		last_checked_at TIMESTAMPTZ,
		created_at TIMESTAMPTZ NOT NULL,
		updated_at TIMESTAMPTZ NOT NULL)`); err != nil {
		return nil, fmt.Errorf("初始化 GitHub Token 池表失败: %w", err)
	}
	return s, nil
}

func maskToken(token string) string {
	if len(token) <= 8 {
		return "****"
	}
	return token[:4] + "…" + token[len(token)-4:]
}

// LooksLikePlaceholderToken 判定配置里拿到的是"占位/说明值"而非真实 PAT。
//
// 背景（2026-09-16 用户实报）：config.yaml 模板里写的是 `token: YOUR_GITHUB_TOKEN`，
// 播种逻辑照单入池 → 仪表盘"GitHub Token 额度"卡片出现一行 "YOUR…" 的假额度，
// 用户明明没配 token 却看不到"未配置"。占位值必须在**配置装载后**就按未配置归一。
//
// 判据（宁可漏判不可误杀真 token）：
//  1. 形如真实 PAT（ghp_/gho_/ghu_/ghs_/ghr_/github_pat_ + 足够长的随机主体，
//     且主体非"同一字符重复"）→ 直接判为真实，放行；
//  2. 否则，含占位限定词（your/example/sample/placeholder/replace/changeme/…）
//     或含尖括号/空格 → 判为占位；
//  3. 其余未知形状 → 放行（可能是企业/自定义格式的真实 token，不能猜）。
func LooksLikePlaceholderToken(token string) bool {
	t := strings.TrimSpace(token)
	if t == "" {
		return true
	}
	if realPATShape.MatchString(t) && !degenerateTokenBody(t) {
		return false
	}
	if strings.ContainsAny(t, "<> \t\n") {
		return true
	}
	compact := strings.ToLower(t)
	compact = strings.NewReplacer("_", "", "-", "", ".", "", " ", "").Replace(compact)
	for _, q := range []string{
		"your", "example", "sample", "placeholder", "replace", "insert", "paste",
		"changeme", "fillme", "dummy", "fake", "redacted", "notconfigured", "notset",
		"todo", "tbd", "here", "xxxx",
	} {
		if strings.Contains(compact, q) {
			return true
		}
	}
	return false
}

var realPATShape = regexp.MustCompile(`^(gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{16,})$`)

// degenerateTokenBody 主体是否为"同一字符重复"（ghp_xxxx… 这类占位惯用写法）。
func degenerateTokenBody(token string) bool {
	body := token
	if i := strings.LastIndex(token, "_"); i >= 0 {
		body = token[i+1:]
	}
	if len(body) < 8 {
		return false
	}
	for _, r := range body[1:] {
		if byte(r) != body[0] {
			return false
		}
	}
	return true
}

// validateNewToken 入池前校验：占位/示例值拒绝；同一 token 重复拒绝
// （同号两次入池会被轮换逻辑当成两个独立额度号，实为同一账号的 5000/日配额）。
// 抽成纯函数便于单测（Add 负责取现有行后调用）。
func validateNewToken(token string, existing []Token) error {
	if LooksLikePlaceholderToken(token) {
		return errors.New("这看起来是占位/示例值（如 YOUR_GITHUB_TOKEN），不是真实 PAT；请填写 ghp_… 开头的 Personal Access Token")
	}
	for _, t := range existing {
		if strings.TrimSpace(t.Token) == token {
			return fmt.Errorf("该 Token 已在池中（备注名「%s」），无需重复添加；不同账号请分别填写各自的 PAT", t.Label)
		}
	}
	return nil
}

func (s *Store) Add(ctx context.Context, label, token string) (Token, error) {
	label = strings.TrimSpace(label)
	token = strings.TrimSpace(token)
	if token == "" {
		return Token{}, errors.New("token 不能为空")
	}
	if len(token) > 200 {
		return Token{}, errors.New("token 过长")
	}
	existing, err := s.List(ctx)
	if err != nil {
		return Token{}, fmt.Errorf("读取 Token 池失败（拒绝在状态不可知时写入）: %w", err)
	}
	if err := validateNewToken(token, existing); err != nil {
		return Token{}, err
	}
	// 校验用的 List 结果复用于后续流程（避免二次查询）
	if label == "" {
		label = maskToken(token)
	}
	now := time.Now().UTC()
	id, err := randomID()
	if err != nil {
		return Token{}, err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO github_token_pool (id,label,token,created_at,updated_at) VALUES ($1,$2,$3,$4,$5)`,
		id, label, token, now, now)
	if err != nil {
		return Token{}, err
	}
	return s.Get(ctx, id)
}

// PrunePlaceholders 删除池中所有"占位/示例值"行（历史版本把 config.yaml 模板值播种进来的遗留），
// 返回被删行的标签用于日志。幂等：无占位行时不做任何写入。
func (s *Store) PrunePlaceholders(ctx context.Context) ([]string, error) {
	rows, err := s.List(ctx)
	if err != nil {
		return nil, err
	}
	var removed []string
	for _, t := range rows {
		if !LooksLikePlaceholderToken(t.Token) {
			continue
		}
		if err := s.Delete(ctx, t.ID); err != nil {
			return removed, fmt.Errorf("清理占位 token（%s）失败: %w", t.Label, err)
		}
		removed = append(removed, t.Label)
	}
	return removed, nil
}

func (s *Store) List(ctx context.Context) ([]Token, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,label,token,enabled,rate_limit,rate_remaining,rate_used,rate_reset_at,last_checked_at,created_at FROM github_token_pool ORDER BY enabled DESC, created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Token{}
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) Get(ctx context.Context, id string) (Token, error) {
	t, err := scanToken(s.db.QueryRowContext(ctx, `SELECT id,label,token,enabled,rate_limit,rate_remaining,rate_used,rate_reset_at,last_checked_at,created_at FROM github_token_pool WHERE id=$1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Token{}, errors.New("token 不存在")
	}
	return t, err
}

func scanToken(row interface{ Scan(...any) error }) (Token, error) {
	var t Token
	var enabled int
	var resetAt, checkedAt sql.NullTime
	if err := row.Scan(&t.ID, &t.Label, &t.Token, &enabled, &t.RateLimit, &t.RateRemaining, &t.RateUsed, &resetAt, &checkedAt, &t.CreatedAt); err != nil {
		return Token{}, err
	}
	t.Enabled = enabled != 0
	t.Masked = maskToken(t.Token)
	if resetAt.Valid {
		t.RateResetAt = &resetAt.Time
	}
	if checkedAt.Valid {
		t.LastCheckedAt = &checkedAt.Time
	}
	return t, nil
}

func (s *Store) Delete(ctx context.Context, id string) error {
	r, err := s.db.ExecContext(ctx, `DELETE FROM github_token_pool WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if n, _ := r.RowsAffected(); n == 0 {
		return errors.New("token 不存在")
	}
	return nil
}

func (s *Store) SetEnabled(ctx context.Context, id string, enabled bool) error {
	_, err := s.db.ExecContext(ctx, `UPDATE github_token_pool SET enabled=$2, updated_at=now() WHERE id=$1`, id, boolInt(enabled))
	return err
}

// UpdateRate 写入一次额度采集结果。
func (s *Store) UpdateRate(ctx context.Context, id string, limit, remaining, used int, reset time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE github_token_pool SET rate_limit=$2, rate_remaining=$3, rate_used=$4, rate_reset_at=$5, last_checked_at=now(), updated_at=now() WHERE id=$1`,
		id, limit, remaining, used, reset)
	return err
}

// Refresh 单号额度采集：rate_limit 端点本身不计入配额。
func (s *Store) Refresh(ctx context.Context, id string, client *http.Client) error {
	t, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	rate, err := FetchRateLimit(ctx, client, t.Token)
	if err != nil {
		return err
	}
	return s.UpdateRate(ctx, id, rate.Limit, rate.Remaining, rate.Used, rate.Reset)
}

// RefreshAll 全池额度采集（调用方节流）。
func (s *Store) RefreshAll(ctx context.Context, client *http.Client) []error {
	tokens, err := s.List(ctx)
	if err != nil {
		return []error{err}
	}
	var errs []error
	for _, t := range tokens {
		if err := s.Refresh(ctx, t.ID, client); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", t.Label, err))
		}
	}
	return errs
}

type RateInfo struct {
	Limit     int
	Remaining int
	Used      int
	Reset     time.Time
}

// FetchRateLimit GET /rate_limit（不计数）。响应取 core 桶（search 桶额度另计）。
func FetchRateLimit(ctx context.Context, client *http.Client, token string) (RateInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/rate_limit", nil)
	if err != nil {
		return RateInfo{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return RateInfo{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return RateInfo{}, fmt.Errorf("token 无效或被拒绝 (HTTP %d)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return RateInfo{}, fmt.Errorf("rate_limit 查询失败 (HTTP %d)", resp.StatusCode)
	}
	var payload struct {
		Resources struct {
			Core struct {
				Limit     int   `json:"limit"`
				Remaining int   `json:"remaining"`
				Used      int   `json:"used"`
				Reset     int64 `json:"reset"`
			} `json:"core"`
		} `json:"resources"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return RateInfo{}, err
	}
	return RateInfo{Limit: payload.Resources.Core.Limit, Remaining: payload.Resources.Core.Remaining,
		Used: payload.Resources.Core.Used, Reset: time.Unix(payload.Resources.Core.Reset, 0)}, nil
}

// poolStore 池所需的存储能力（*Store 实现；测试可注入 fake）。
type poolStore interface {
	List(context.Context) ([]Token, error)
	RefreshAll(context.Context, *http.Client) []error
}

// Pool 轮换器（内存态，DB 为权威存储；操作后同步）。
type Pool struct {
	store poolStore
	http  *http.Client
	mu    sync.Mutex
	rr    int
}

func NewPool(store *Store) *Pool {
	return &Pool{store: store, http: &http.Client{Timeout: 15 * time.Second}}
}

// HTTPClient 供外部额度采集共用。
func (p *Pool) HTTPClient() *http.Client { return p.http }

// RefreshRates 采集全池额度（rate_limit 端点不计配额）。调用方负责节流：
// 泄露监控在每轮巡查开始时调用一次，Token 池面板另有手动刷新。
func (p *Pool) RefreshRates(ctx context.Context) []error {
	return p.store.RefreshAll(ctx, p.http)
}

// Pick 选下一个可用 token：优先剩余配额最多的号；额度未知或并列时按 rr 轮转，
// 避免额度未采集（或两号额度持平）时永远只用一个号。无可用时返回空。
func (p *Pool) Pick(ctx context.Context) string {
	tokens, err := p.store.List(ctx)
	if err != nil || len(tokens) == 0 {
		return ""
	}
	eligible := make([]Token, 0, len(tokens))
	for _, t := range tokens {
		if !t.Enabled {
			continue
		}
		if t.RateRemaining >= 0 && t.RateRemaining <= 0 {
			continue // 明确打满
		}
		eligible = append(eligible, t)
	}
	if len(eligible) == 0 {
		return ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	// 已知额度里取最大值；有已知额度时优先用已知号（避免误用可能已打满的未知号）。
	bestKnown := -1
	for _, t := range eligible {
		if t.RateRemaining > bestKnown {
			bestKnown = t.RateRemaining
		}
	}
	if bestKnown < 0 {
		// 全部未知：轮转
		idx := p.rr % len(eligible)
		if idx < 0 {
			idx = 0
		}
		p.rr = idx + 1
		return eligible[idx].Token
	}
	// 在额度最大的号之间轮转
	start := p.rr % len(eligible)
	if start < 0 {
		start = 0
	}
	for i := 0; i < len(eligible); i++ {
		idx := (start + i) % len(eligible)
		if eligible[idx].RateRemaining == bestKnown {
			p.rr = idx + 1
			return eligible[idx].Token
		}
	}
	p.rr = start + 1
	return eligible[start].Token
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func randomID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}
