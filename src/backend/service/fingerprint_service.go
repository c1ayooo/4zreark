package service

import (
	"context"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/repo"
)

// ResponseSnapshot 是指纹匹配需要的响应快照（探测时顺手采集，不额外发请求）。
type ResponseSnapshot struct {
	StatusCode int
	Title      string
	Server     string
	Headers    map[string]string
	Body       string
}

// FingerprintService 负责「规则 → 站点」的匹配与落库。
//
// 规则来源是数据库的 fingerprint_rules，两种形态一起跑：
//   - dsl_version=1：扁平数组，读的时候折算成等价的 AND 树
//   - dsl_version=2：condition_tree，支持 and / or / not 嵌套
//
// 规则缓存 60 秒，写入规则时主动失效。
type FingerprintService struct {
	mu       sync.RWMutex
	rules    []*repo.FpRule
	loadedAt time.Time
	ttl      time.Duration
}

func NewFingerprintService() *FingerprintService {
	return &FingerprintService{ttl: 60 * time.Second}
}

// Invalidate 让下一次匹配重新读规则（规则变更后调用）。
func (s *FingerprintService) Invalidate() {
	s.mu.Lock()
	s.rules = nil
	s.loadedAt = time.Time{}
	s.mu.Unlock()
}

func (s *FingerprintService) fpRepo() (repo.FingerprintRepo, error) {
	if repo.Default() == nil {
		return nil, errors.New("数据层未初始化")
	}
	return repo.Default().Fingerprints(), nil
}

// LoadRules 返回启用的规则，带 60 秒缓存。
func (s *FingerprintService) LoadRules(ctx context.Context) ([]*repo.FpRule, error) {
	s.mu.RLock()
	if s.rules != nil && time.Since(s.loadedAt) < s.ttl {
		out := s.rules
		s.mu.RUnlock()
		return out, nil
	}
	s.mu.RUnlock()

	fp, err := s.fpRepo()
	if err != nil {
		return nil, err
	}
	rules, err := fp.ListRules(ctx, true)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.rules, s.loadedAt = rules, time.Now()
	s.mu.Unlock()
	return rules, nil
}

// Match 对快照跑一遍规则，返回命中的规则 ID 与技术栈名。
func (s *FingerprintService) Match(ctx context.Context, snap ResponseSnapshot) ([]string, []string, error) {
	rules, err := s.LoadRules(ctx)
	if err != nil {
		return nil, nil, err
	}
	var (
		ids  []string
		tech []string
		seen = map[string]bool{}
	)
	for _, rule := range rules {
		tree := rule.Condition
		if tree == nil || rule.DSLVersion < 2 {
			tree = legacyTree(rule.Legacy)
		}
		if tree == nil {
			continue
		}
		if evalCondition(tree, snap) {
			ids = append(ids, rule.ID)
			if rule.Name != "" && !seen[rule.Name] {
				seen[rule.Name] = true
				tech = append(tech, rule.Name)
			}
		}
	}
	return ids, tech, nil
}

// ApplyToSite 匹配并把结果写回：命中表、站点技术栈、标题。
// 命中集合以本次为准，没再命中的旧命中会被清掉。
func (s *FingerprintService) ApplyToSite(ctx context.Context, siteID int64, snap ResponseSnapshot, recordID *int64) ([]string, []string, error) {
	ids, tech, err := s.Match(ctx, snap)
	if err != nil {
		return nil, nil, err
	}
	fp, err := s.fpRepo()
	if err != nil {
		return nil, nil, err
	}
	if err := fp.SaveHits(ctx, siteID, ids, recordID, map[string]any{
		"title":       snap.Title,
		"server":      snap.Server,
		"status_code": snap.StatusCode,
	}); err != nil {
		return nil, nil, err
	}
	if _, err := fp.PruneHits(ctx, siteID, ids); err != nil {
		return nil, nil, err
	}
	if err := fp.UpdateSiteProfile(ctx, siteID, snap.Title, snap.Server, tech); err != nil {
		return nil, nil, err
	}
	return ids, tech, nil
}

// --- 条件树求值 ---

var regexCache sync.Map // pattern → *regexp.Regexp

func evalCondition(c *repo.Condition, snap ResponseSnapshot) bool {
	if c == nil {
		return false
	}
	switch {
	case len(c.And) > 0:
		for _, sub := range c.And {
			if !evalCondition(sub, snap) {
				return false
			}
		}
		return true
	case len(c.Or) > 0:
		for _, sub := range c.Or {
			if evalCondition(sub, snap) {
				return true
			}
		}
		return false
	case c.Not != nil:
		return !evalCondition(c.Not, snap)
	}
	return evalLeaf(c, snap)
}

func evalLeaf(c *repo.Condition, snap ResponseSnapshot) bool {
	var subject string
	switch strings.ToLower(c.Type) {
	case "header":
		subject = lookupHeader(snap.Headers, c.Key)
	case "body":
		subject = snap.Body
	case "title":
		subject = snap.Title
	case "server":
		subject = snap.Server
	case "status":
		// 状态码只做等值比较
		n, err := strconv.Atoi(strings.TrimSpace(c.Value))
		return err == nil && snap.StatusCode == n
	case "icon_hash":
		// 图标指纹要等图标库接上（G3 后续），现在一律不命中，避免误报
		return false
	default:
		return false
	}
	if subject == "" || c.Value == "" {
		return false
	}
	return matchOp(subject, c.Op, c.Value)
}

func lookupHeader(headers map[string]string, key string) string {
	if len(headers) == 0 {
		return ""
	}
	if v, ok := headers[strings.ToLower(key)]; ok {
		return v
	}
	for k, v := range headers {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return ""
}

func matchOp(subject, op, value string) bool {
	switch strings.ToLower(op) {
	case "equals", "eq", "==":
		return strings.EqualFold(subject, value)
	case "prefix", "startswith":
		return strings.HasPrefix(strings.ToLower(subject), strings.ToLower(value))
	case "regex", "re":
		re := compileRegex(value)
		return re != nil && re.MatchString(subject)
	case "", "contains":
		return strings.Contains(strings.ToLower(subject), strings.ToLower(value))
	}
	return false
}

func compileRegex(pattern string) *regexp.Regexp {
	if v, ok := regexCache.Load(pattern); ok {
		return v.(*regexp.Regexp)
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		regexCache.Store(pattern, (*regexp.Regexp)(nil))
		return nil
	}
	regexCache.Store(pattern, re)
	return re
}

// legacyTree 把老规则的扁平匹配项折算成 AND 树。
// 老语义是「全部匹配项都命中」，所以包一层 and；单项时直接返回叶子。
func legacyTree(matches []repo.LegacyMatch) *repo.Condition {
	if len(matches) == 0 {
		return nil
	}
	leaves := make([]*repo.Condition, 0, len(matches))
	for _, m := range matches {
		if m.Pattern == "" {
			continue
		}
		leaf := &repo.Condition{
			Type:  strings.ToLower(m.Type),
			Key:   m.Key,
			Op:    strings.ToLower(m.Operator),
			Value: m.Pattern,
		}
		// 老 operator 里的 hash 是图标哈希，当前没有图标通道
		if leaf.Op == "hash" {
			leaf.Type = "icon_hash"
		}
		leaves = append(leaves, leaf)
	}
	if len(leaves) == 0 {
		return nil
	}
	if len(leaves) == 1 {
		return leaves[0]
	}
	return &repo.Condition{And: leaves}
}

// EvalTree 用给定快照试跑一棵条件树，供导入预览使用（不落库）。
func (s *FingerprintService) EvalTree(tree *repo.Condition, snap ResponseSnapshot) bool {
	return evalCondition(tree, snap)
}

// ValidateCondition 校验条件树：结构完整、叶子字段与操作符合法、正则能编译。
func ValidateCondition(c *repo.Condition) error {
	if c == nil {
		return errors.New("条件树为空")
	}
	return validateNode(c, 0)
}

func validateNode(c *repo.Condition, depth int) error {
	if depth > 8 {
		return errors.New("条件树嵌套超过 8 层")
	}
	switch {
	case len(c.And) > 0 && len(c.Or) > 0:
		return errors.New("同一层不能同时有 and 与 or")
	case len(c.And) > 0:
		for _, sub := range c.And {
			if err := validateNode(sub, depth+1); err != nil {
				return err
			}
		}
		return nil
	case len(c.Or) > 0:
		for _, sub := range c.Or {
			if err := validateNode(sub, depth+1); err != nil {
				return err
			}
		}
		return nil
	case c.Not != nil:
		return validateNode(c.Not, depth+1)
	}
	if c.Type == "" || c.Value == "" {
		return errors.New("叶子节点需要 type 与 value")
	}
	switch c.Type {
	case "header", "body", "title", "server", "status", "icon_hash":
	default:
		return errors.New("不支持的叶子类型: " + c.Type)
	}
	if c.Type == "header" && c.Key == "" {
		return errors.New("header 叶子需要 key")
	}
	switch c.Op {
	case "", "contains", "equals", "prefix", "regex":
	case "eq", "==", "startswith", "re":
	default:
		return errors.New("不支持的操作符: " + c.Op)
	}
	if c.Op == "regex" {
		if _, err := regexp.Compile(c.Value); err != nil {
			return errors.New("正则无效: " + err.Error())
		}
	}
	return nil
}
