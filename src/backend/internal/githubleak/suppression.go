package githubleak

import (
	"context"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// suppression.go — 泄露监控静默清单（误报治理最后一公里）。
//
// 通用噪声过滤（噪声路径/fork/JWT/样板风暴）拦截的是"可归类的噪声类"；
// 静默清单解决的是运营层的具体误报源：某个课程模板仓库、某个组织的演示
// 账号、某类路径。命中即整条跳过（不入库不通知）。
//
// 四种模式：
//   - repo                精确仓库（owner/name，大小写不敏感）
//   - org                 组织/用户前缀（owner/* 全部仓库）
//   - path_glob           路径通配（** 跨段，* 单段内，? 单字符；大小写不敏感）
//   - fingerprint_prefix  指纹前缀（HMAC hex 前缀，同值密钥按内容静默）
//   - rule                规则名整条静默（R7 规则自净的落点；等效禁用且可恢复）

const (
	SuppressionRepo              = "repo"
	SuppressionOrg               = "org"
	SuppressionPathGlob          = "path_glob"
	SuppressionFingerprintPrefix = "fingerprint_prefix"
	SuppressionRule              = "rule"
)

// validSuppressionType 静默类型白名单（AddSuppression 与测试共用）。
func validSuppressionType(patternType string) bool {
	switch patternType {
	case SuppressionRepo, SuppressionOrg, SuppressionPathGlob, SuppressionFingerprintPrefix, SuppressionRule:
		return true
	}
	return false
}

type Suppression struct {
	ID          string    `json:"id"`
	PatternType string    `json:"pattern_type"`
	Pattern     string    `json:"pattern"`
	Note        string    `json:"note,omitempty"`
	CreatedBy   string    `json:"created_by,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// suppressionSource 由具体 Store 实现的可选接口（测试用 fake 无需实现）。
type suppressionSource interface {
	ListSuppressions(context.Context) ([]Suppression, error)
}

// --- Store CRUD ---

// ListSuppressions 返回全部静默规则（按创建时间倒序）。
func (s *Store) ListSuppressions(ctx context.Context) ([]Suppression, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, pattern_type, pattern, COALESCE(note,''), COALESCE(created_by,''), created_at
		FROM github_leak_suppressions ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Suppression, 0, 8)
	for rows.Next() {
		var sp Suppression
		var created string
		if err := rows.Scan(&sp.ID, &sp.PatternType, &sp.Pattern, &sp.Note, &sp.CreatedBy, &created); err != nil {
			continue
		}
		if t, err := time.Parse(time.RFC3339Nano, created); err == nil {
			sp.CreatedAt = t
		}
		out = append(out, sp)
	}
	return out, rows.Err()
}

// AddSuppression 新增静默规则（同类型同模式幂等）。返回是否真正新增。
func (s *Store) AddSuppression(ctx context.Context, patternType, pattern, note, createdBy string) (bool, error) {
	patternType = strings.TrimSpace(patternType)
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return false, errors.New("pattern 不能为空")
	}
	switch patternType {
	case SuppressionRepo, SuppressionOrg, SuppressionPathGlob, SuppressionFingerprintPrefix, SuppressionRule:
	default:
		return false, fmt.Errorf("不支持的静默类型: %s", patternType)
	}
	if patternType == SuppressionRepo {
		parts := strings.Split(pattern, "/")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return false, errors.New("repo 模式须为 owner/name")
		}
	}
	if patternType == SuppressionFingerprintPrefix && (len(pattern) < 8 || !isHexString(pattern)) {
		return false, errors.New("fingerprint_prefix 至少 8 位 hex（建议 16 位，避免过宽误吞）")
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO github_leak_suppressions (id, pattern_type, pattern, note, created_by, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (pattern_type, pattern) DO NOTHING`,
		uuid.NewString(), patternType, pattern, strings.TrimSpace(note), strings.TrimSpace(createdBy), time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// DeleteSuppression 删除静默规则。返回是否实际删除。
func (s *Store) DeleteSuppression(ctx context.Context, id string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM github_leak_suppressions WHERE id = $1`, strings.TrimSpace(id))
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// --- 匹配器 ---

type globRule struct {
	pattern string
	re      *regexp.Regexp
}

type suppressionSet struct {
	repos      map[string]bool // owner/name 小写
	orgs       map[string]bool // owner 小写
	globs      []globRule
	fpPrefixes []string          // 小写 hex 前缀
	rules      map[string]string // 规则名小写 → 静默原因（note，供日志/排障）
}

// compileSuppressions 编译静默清单；非法条目（如坏 glob）跳过并计数返回。
func compileSuppressions(list []Suppression) (*suppressionSet, int) {
	set := &suppressionSet{repos: map[string]bool{}, orgs: map[string]bool{}, rules: map[string]string{}}
	skipped := 0
	for _, sp := range list {
		switch sp.PatternType {
		case SuppressionRepo:
			set.repos[strings.ToLower(sp.Pattern)] = true
		case SuppressionOrg:
			set.orgs[strings.ToLower(strings.TrimSuffix(sp.Pattern, "/*"))] = true
		case SuppressionPathGlob:
			if re, err := globToRegexp(sp.Pattern); err == nil {
				set.globs = append(set.globs, globRule{pattern: sp.Pattern, re: re})
			} else {
				skipped++
			}
		case SuppressionFingerprintPrefix:
			set.fpPrefixes = append(set.fpPrefixes, strings.ToLower(sp.Pattern))
		case SuppressionRule:
			name := strings.ToLower(strings.TrimSpace(sp.Pattern))
			if name != "" {
				set.rules[name] = sp.Note
			} else {
				skipped++
			}
		default:
			skipped++
		}
	}
	return set, skipped
}

// globToRegexp：** 跨段，* 段内，? 单字符。匹配对象为完整（小写）路径。
func globToRegexp(glob string) (*regexp.Regexp, error) {
	glob = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(glob)), "/")
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(glob); i++ {
		switch glob[i] {
		case '*':
			if i+1 < len(glob) && glob[i+1] == '*' {
				b.WriteString(".*")
				i++
			} else {
				b.WriteString("[^/]*")
			}
		case '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(string(glob[i])))
		}
	}
	b.WriteString("$")
	return regexp.Compile(b.String())
}

// suppressItem 条目级判定（Detect 之前，省去无谓的检测开销）。
func (set *suppressionSet) suppressItem(repository, itemPath string) bool {
	if set == nil {
		return false
	}
	repoLower := strings.ToLower(strings.TrimSpace(repository))
	if repoLower != "" {
		if set.repos[repoLower] {
			return true
		}
		if owner := repoOwner(repoLower); owner != "" && set.orgs[owner] {
			return true
		}
	}
	p := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(itemPath), "/"))
	if p != "" {
		for _, g := range set.globs {
			if g.re.MatchString(p) {
				return true
			}
		}
	}
	return false
}

// suppressRule 规则维度判定（整条规则静默，R7 规则自净/运营手动停用共用）。
func (set *suppressionSet) suppressRule(ruleName string) bool {
	if set == nil || len(set.rules) == 0 {
		return false
	}
	_, ok := set.rules[strings.ToLower(strings.TrimSpace(ruleName))]
	return ok
}

// suppressCandidate 候选级判定（指纹前缀）。
func (set *suppressionSet) suppressCandidate(fingerprint string) bool {
	if set == nil || len(set.fpPrefixes) == 0 {
		return false
	}
	fp := strings.ToLower(fingerprint)
	for _, prefix := range set.fpPrefixes {
		if strings.HasPrefix(fp, prefix) {
			return true
		}
	}
	return false
}

func repoOwner(repoLower string) string {
	if i := strings.Index(repoLower, "/"); i > 0 {
		return repoLower[:i]
	}
	return ""
}

// suppressPath 供路径语义提示（保留 path 包引用的语义注释锚点）。
var _ = path.Join
