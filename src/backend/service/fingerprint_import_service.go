package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/repo"

	"gopkg.in/yaml.v3"
)

// 指纹规则导入：预览（可导入 / 冲突 / 无效）→ 一次性 token 确认导入。
//
// 来源隔离沿用同步任务的口径：dddd / seed 是同步保留来源，手工导入只能写
// custom / legacy / import 这类来源。同名规则默认只更新同来源；跨来源必须
// 显式 force，避免手工导入把同步规则整批改名。

const (
	FpImportTTL      = 15 * time.Minute
	fpImportMaxRules = 10000
	fpBulkMaxRules   = 500
)

var ErrFpImportInput = errors.New("指纹导入参数错误")

// FpImportRuleInput 是导入文件里的一条规则，兼容条件树与旧扁平 rules。
type FpImportRuleInput struct {
	Name      string             `json:"name" yaml:"name"`
	Category  string             `json:"category" yaml:"category"`
	Version   string             `json:"version" yaml:"version"`
	Enabled   *bool              `json:"enabled" yaml:"enabled"`
	Condition *repo.Condition    `json:"condition_tree" yaml:"condition_tree"`
	Rules     []repo.LegacyMatch `json:"rules" yaml:"rules"`
}

// FpImportRequest 是导入预览请求。
type FpImportRequest struct {
	Rules   []FpImportRuleInput `json:"rules"`
	Content string              `json:"content"`
	Format  string              `json:"format"`
	Source  string              `json:"source"`
	Force   bool                `json:"force"`
}

// FpImportItem 是预览里的一条结果。
type FpImportItem struct {
	Index         int    `json:"index"`
	Name          string `json:"name"`
	Category      string `json:"category"`
	Status        string `json:"status"` // importable / conflict / invalid
	WillOverwrite bool   `json:"will_overwrite"`
	Reason        string `json:"reason,omitempty"`
}

// FpImportPreview 是三类计数与逐条结果。
type FpImportPreview struct {
	Total      int            `json:"total"`
	Importable int            `json:"importable"`
	Conflicts  int            `json:"conflicts"`
	Invalid    int            `json:"invalid"`
	Source     string         `json:"source"`
	Items      []FpImportItem `json:"items"`
	Token      string         `json:"token"`
	ExpiresAt  time.Time      `json:"expires_at"`
}

// FpImportCommitResult 是确认导入的回执。
type FpImportCommitResult struct {
	Imported int    `json:"imported"`
	Source   string `json:"source"`
	Force    bool   `json:"force"`
}

type fpImportTicket struct {
	rules     []*repo.FpRule
	source    string
	force     bool
	expiresAt time.Time
}

var (
	fpImportMu     sync.Mutex
	fpImportTokens = map[string]*fpImportTicket{}
	fpImportNow    = time.Now
)

// FingerprintImportService 负责规则导入预览、确认导入与批量启停。
type FingerprintImportService struct{}

func NewFingerprintImportService() *FingerprintImportService { return &FingerprintImportService{} }

func (s *FingerprintImportService) ops() (*repo.FpImportOpsRepo, error) {
	if repo.Default() == nil {
		return nil, errors.New("数据层未初始化")
	}
	return repo.Default().FingerprintOps(), nil
}

func normalizeFpImportSource(source string) (string, error) {
	source = strings.TrimSpace(source)
	if source == "" {
		source = "custom"
	}
	switch source {
	case "dddd", "seed":
		return "", fmt.Errorf("%w: %s 是同步保留来源，手工导入请使用 custom / legacy / import", ErrFpImportInput, source)
	}
	return source, nil
}

func parseFpImportContent(content, format string) ([]FpImportRuleInput, error) {
	content = strings.TrimSpace(content)
	if content == "" {
		return nil, nil
	}
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "yaml", "yml":
		var list []FpImportRuleInput
		if err := yaml.Unmarshal([]byte(content), &list); err == nil && len(list) > 0 {
			return list, nil
		}
		var wrapper struct {
			Rules []FpImportRuleInput `json:"rules" yaml:"rules"`
		}
		if err := yaml.Unmarshal([]byte(content), &wrapper); err != nil {
			return nil, fmt.Errorf("%w: 解析 YAML 失败: %v", ErrFpImportInput, err)
		}
		return wrapper.Rules, nil
	case "json":
		var list []FpImportRuleInput
		if err := json.Unmarshal([]byte(content), &list); err == nil && len(list) > 0 {
			return list, nil
		}
		var wrapper struct {
			Rules []FpImportRuleInput `json:"rules"`
		}
		if err := json.Unmarshal([]byte(content), &wrapper); err != nil {
			return nil, fmt.Errorf("%w: 解析 JSON 失败: %v", ErrFpImportInput, err)
		}
		return wrapper.Rules, nil
	default:
		return nil, fmt.Errorf("%w: format 只支持 json / yaml", ErrFpImportInput)
	}
}

func buildFpImportRule(in FpImportRuleInput, source string) (*repo.FpRule, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return nil, errors.New("规则名不能为空")
	}
	if len(name) > 200 {
		return nil, errors.New("规则名长度不能超过 200")
	}
	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	rule := &repo.FpRule{
		Name: name, Category: strings.TrimSpace(in.Category), Version: strings.TrimSpace(in.Version),
		Enabled: enabled, Source: source,
	}
	if in.Condition != nil {
		if err := ValidateCondition(in.Condition); err != nil {
			return nil, err
		}
		rule.Condition = in.Condition
		rule.DSLVersion = 2
		return rule, nil
	}
	tree := legacyTree(in.Rules)
	if tree == nil {
		return nil, errors.New("condition_tree 与 rules 至少提供一个")
	}
	if err := ValidateCondition(tree); err != nil {
		return nil, err
	}
	rule.Legacy = in.Rules
	rule.DSLVersion = 1
	return rule, nil
}

// Preview 解析并校验导入内容，返回三类计数与一次性 token。
func (s *FingerprintImportService) Preview(ctx context.Context, req FpImportRequest) (*FpImportPreview, error) {
	source, err := normalizeFpImportSource(req.Source)
	if err != nil {
		return nil, err
	}
	inputs := append([]FpImportRuleInput{}, req.Rules...)
	parsed, err := parseFpImportContent(req.Content, req.Format)
	if err != nil {
		return nil, err
	}
	inputs = append(inputs, parsed...)
	if len(inputs) == 0 {
		return nil, fmt.Errorf("%w: rules 与 content 不能同时为空", ErrFpImportInput)
	}
	if len(inputs) > fpImportMaxRules {
		return nil, fmt.Errorf("%w: 单次最多导入 %d 条规则", ErrFpImportInput, fpImportMaxRules)
	}

	preview := &FpImportPreview{Total: len(inputs), Source: source, Items: make([]FpImportItem, 0, len(inputs))}
	validRules := make([]*repo.FpRule, 0, len(inputs))
	validNames := make([]string, 0, len(inputs))
	seen := make(map[string]int, len(inputs))

	for i, in := range inputs {
		item := FpImportItem{Index: i, Name: strings.TrimSpace(in.Name), Category: strings.TrimSpace(in.Category)}
		if first, dup := seen[item.Name]; dup {
			item.Status = "invalid"
			item.Reason = fmt.Sprintf("批内重复规则名（首次出现在第 %d 条）", first+1)
			preview.Invalid++
			preview.Items = append(preview.Items, item)
			continue
		}
		seen[item.Name] = i

		rule, err := buildFpImportRule(in, source)
		if err != nil {
			item.Status = "invalid"
			item.Reason = err.Error()
			preview.Invalid++
			preview.Items = append(preview.Items, item)
			continue
		}
		preview.Items = append(preview.Items, item) // 占位，等来源查询后回填
		validRules = append(validRules, rule)
		validNames = append(validNames, rule.Name)
	}

	ops, err := s.ops()
	if err != nil {
		return nil, err
	}
	existing, err := ops.ExistingRuleSources(ctx, validNames)
	if err != nil {
		return nil, err
	}

	allowed := make([]*repo.FpRule, 0, len(validRules))
	validIdx := 0
	for i := range preview.Items {
		if preview.Items[i].Status != "" {
			continue
		}
		rule := validRules[validIdx]
		validIdx++
		oldSource, exists := existing[rule.Name]
		switch {
		case !exists:
			preview.Items[i].Status = "importable"
			preview.Importable++
			allowed = append(allowed, rule)
		case oldSource == source || req.Force:
			preview.Items[i].Status = "conflict"
			preview.Items[i].WillOverwrite = true
			preview.Conflicts++
			allowed = append(allowed, rule)
		default:
			preview.Items[i].Status = "conflict"
			preview.Items[i].Reason = fmt.Sprintf("同名规则属于 source=%s；未开启 force，提交时跳过", oldSource)
			preview.Conflicts++
		}
	}

	now := fpImportNow()
	token := randomToken()
	fpImportMu.Lock()
	for k, v := range fpImportTokens {
		if now.After(v.expiresAt) {
			delete(fpImportTokens, k)
		}
	}
	fpImportTokens[token] = &fpImportTicket{
		rules: allowed, source: source, force: req.Force, expiresAt: now.Add(FpImportTTL),
	}
	fpImportMu.Unlock()

	preview.Token = token
	preview.ExpiresAt = now.Add(FpImportTTL)
	return preview, nil
}

// Commit 消费预览 token 并写入规则。
func (s *FingerprintImportService) Commit(ctx context.Context, token, actor, ip string) (*FpImportCommitResult, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, fmt.Errorf("%w: token 必填，请先调用导入预览", ErrFpImportInput)
	}
	now := fpImportNow()
	fpImportMu.Lock()
	ticket, ok := fpImportTokens[token]
	if ok {
		delete(fpImportTokens, token)
	}
	fpImportMu.Unlock()
	if !ok {
		return nil, fmt.Errorf("%w: token 不存在或已被使用，请重新预览", ErrFpImportInput)
	}
	if now.After(ticket.expiresAt) {
		return nil, fmt.Errorf("%w: 预览已过期（15 分钟有效），请重新预览", ErrFpImportInput)
	}

	res := &FpImportCommitResult{Source: ticket.source, Force: ticket.force}
	if len(ticket.rules) == 0 {
		return res, nil
	}
	ops, err := s.ops()
	if err != nil {
		return nil, err
	}
	imported, err := ops.ImportRules(ctx, ticket.rules, ticket.source, ticket.force)
	if err != nil {
		return nil, err
	}
	res.Imported = imported
	NewFingerprintService().Invalidate()

	if actor == "" {
		actor = "system"
	}
	if err := repo.Default().LogOperation(ctx, repo.OperationLogInput{
		Username:  actor,
		Action:    "fingerprint_import",
		Module:    "fingerprint",
		Target:    ticket.source,
		Detail:    fmt.Sprintf("导入指纹规则 %d 条（force=%v）", imported, ticket.force),
		IP:        ip,
		UserAgent: "governance/fingerprint-import",
	}); err != nil {
		log.Printf("[Fingerprint] 导入已完成，但审计日志写入失败: %v", err)
	}
	return res, nil
}

// FpBulkResult 是批量启停回执。
type FpBulkResult struct {
	Requested int   `json:"requested"`
	Updated   int64 `json:"updated"`
	Skipped   int64 `json:"skipped"`
	Enabled   bool  `json:"enabled"`
}

// BulkToggle 批量启停规则，单次最多 500 条。
func (s *FingerprintImportService) BulkToggle(ctx context.Context, names []string, enabled bool, actor, ip string) (*FpBulkResult, error) {
	seen := make(map[string]struct{}, len(names))
	clean := make([]string, 0, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		clean = append(clean, name)
	}
	if len(clean) == 0 {
		return nil, fmt.Errorf("%w: names 不能为空", ErrFpImportInput)
	}
	if len(clean) > fpBulkMaxRules {
		return nil, fmt.Errorf("%w: 单次最多操作 %d 条规则", ErrFpImportInput, fpBulkMaxRules)
	}
	ops, err := s.ops()
	if err != nil {
		return nil, err
	}
	updated, err := ops.BulkSetEnabled(ctx, clean, enabled)
	if err != nil {
		return nil, err
	}
	NewFingerprintService().Invalidate()

	res := &FpBulkResult{Requested: len(clean), Updated: updated, Enabled: enabled}
	if int(updated) < len(clean) {
		res.Skipped = int64(len(clean)) - updated
	}
	if actor == "" {
		actor = "system"
	}
	if err := repo.Default().LogOperation(ctx, repo.OperationLogInput{
		Username:  actor,
		Action:    "fingerprint_bulk_toggle",
		Module:    "fingerprint",
		Target:    fmt.Sprintf("%d 条规则", len(clean)),
		Detail:    fmt.Sprintf("批量设置 enabled=%v，实际更新 %d 条，跳过 %d 条", enabled, updated, res.Skipped),
		IP:        ip,
		UserAgent: "governance/fingerprint-bulk",
	}); err != nil {
		log.Printf("[Fingerprint] 批量启停已完成，但审计日志写入失败: %v", err)
	}
	return res, nil
}
