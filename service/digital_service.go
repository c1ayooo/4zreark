package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/repo"
)

// 数字资产名单导入：预览不写库，15 分钟有效；确认时一次性消费 token。
// 名单与站点库解耦：只写 digital_assets，不触发 DNS / 验证 / 站点创建。

const (
	DigitalPreviewTTL = 15 * time.Minute
	maxDigitalItems   = 5000
)

var ErrDigitalPreviewExpired = errors.New("名单预览已过期（15 分钟有效），请重新预览")

var digitalKinds = map[string]bool{
	"app": true, "miniapp": true, "official_account": true, "newmedia": true,
}

type DigitalPreview struct {
	Token      string                   `json:"token"`
	ExpiresAt  time.Time                `json:"expires_at"`
	ProjectID  int64                    `json:"project_id"`
	Kind       string                   `json:"kind"`
	Total      int                      `json:"total"`
	Unique     int                      `json:"unique"`
	Duplicates int                      `json:"duplicates"`
	Existing   int                      `json:"existing"`
	Invalid    int                      `json:"invalid"`
	Sample     []repo.DigitalAssetInput `json:"sample"`
}

type digitalPreviewEntry struct {
	projectID int64
	kind      string
	assets    []repo.DigitalAssetInput
	expiresAt time.Time
}

type digitalPreviewStore struct {
	mu    sync.Mutex
	items map[string]*digitalPreviewEntry
}

var digitalPreviews = &digitalPreviewStore{items: map[string]*digitalPreviewEntry{}}
var digitalPreviewNow = time.Now

// DigitalService 提供名单查询与两段式导入。
type DigitalService struct{}

func NewDigitalService() *DigitalService { return &DigitalService{} }

func (s *DigitalService) repo() (repo.DigitalRepo, error) {
	r := repo.Default()
	if r == nil {
		return nil, errors.New("数据层未初始化")
	}
	return r.Digital(), nil
}

func (s *DigitalService) List(ctx context.Context, f repo.DigitalFilter) ([]*repo.DigitalAsset, int64, error) {
	r, err := s.repo()
	if err != nil {
		return nil, 0, err
	}
	return r.List(ctx, f)
}

func (s *DigitalService) Delete(ctx context.Context, id int64) error {
	r, err := s.repo()
	if err != nil {
		return err
	}
	ok, err := r.Delete(ctx, id)
	if err != nil {
		return err
	}
	if !ok {
		return repo.ErrNotFound
	}
	return nil
}

func (s *DigitalService) Batches(ctx context.Context, projectID int64, limit int) ([]*repo.ImportBatch, error) {
	r, err := s.repo()
	if err != nil {
		return nil, err
	}
	return r.ListBatches(ctx, projectID, limit)
}

func (s *DigitalService) Undo(ctx context.Context, batchID int64) (int64, error) {
	r, err := s.repo()
	if err != nil {
		return 0, err
	}
	return r.UndoBatch(ctx, batchID)
}

// Preview 规范化名单：去空白、按大小写不敏感去重，并与库内已有名单对账。
func (s *DigitalService) Preview(ctx context.Context, projectID int64, kind string, names []string, company, platform, source string) (*DigitalPreview, error) {
	if projectID <= 0 {
		return nil, errors.New("project_id 必填")
	}
	kind = strings.TrimSpace(kind)
	if !digitalKinds[kind] {
		return nil, fmt.Errorf("kind 必须是 app / miniapp / official_account / newmedia，收到 %q", kind)
	}
	if len(names) == 0 || len(names) > maxDigitalItems {
		return nil, fmt.Errorf("名单数量需在 1..%d，收到 %d", maxDigitalItems, len(names))
	}
	if strings.TrimSpace(source) == "" {
		source = "manual"
	}

	seen := map[string]bool{}
	assets := make([]repo.DigitalAssetInput, 0, len(names))
	sample := make([]repo.DigitalAssetInput, 0, 20)
	duplicates, invalid := 0, 0
	for _, raw := range names {
		name := strings.Join(strings.Fields(raw), " ")
		if name == "" {
			invalid++
			continue
		}
		key := strings.ToLower(name)
		if seen[key] {
			duplicates++
			continue
		}
		seen[key] = true
		a := repo.DigitalAssetInput{
			Kind: kind, Name: name,
			Company: strings.TrimSpace(company), Platform: strings.TrimSpace(platform),
			Source: source,
		}
		assets = append(assets, a)
		if len(sample) < 20 {
			sample = append(sample, a)
		}
	}
	if len(assets) == 0 {
		return nil, errors.New("名单全部为空或重复")
	}

	// 与库内已有名单对账（精确匹配，唯一键也是精确匹配）。
	names2 := make([]string, 0, len(assets))
	for _, a := range assets {
		names2 = append(names2, a.Name)
	}
	r, err := s.repo()
	if err != nil {
		return nil, err
	}
	existingSet, err := r.ExistingNames(ctx, projectID, kind, names2)
	if err != nil {
		return nil, err
	}
	existing := 0
	fresh := make([]repo.DigitalAssetInput, 0, len(assets))
	for _, a := range assets {
		if existingSet[a.Name] {
			existing++
			continue
		}
		fresh = append(fresh, a)
	}
	if len(fresh) == 0 {
		return nil, errors.New("这些名单在库中已存在，没有需要导入的内容")
	}

	now := digitalPreviewNow()
	token := randomToken()
	digitalPreviews.mu.Lock()
	for k, v := range digitalPreviews.items {
		if now.After(v.expiresAt) {
			delete(digitalPreviews.items, k)
		}
	}
	digitalPreviews.items[token] = &digitalPreviewEntry{
		projectID: projectID, kind: kind, assets: fresh,
		expiresAt: now.Add(DigitalPreviewTTL),
	}
	digitalPreviews.mu.Unlock()

	return &DigitalPreview{
		Token: token, ExpiresAt: now.Add(DigitalPreviewTTL),
		ProjectID: projectID, Kind: kind,
		Total: len(names), Unique: len(assets), Duplicates: duplicates,
		Existing: existing, Invalid: invalid, Sample: sample,
	}, nil
}

// Commit 消费预览 token，写入回执与名单。
func (s *DigitalService) Commit(ctx context.Context, token, createdBy string) (*repo.ImportBatch, int64, error) {
	digitalPreviews.mu.Lock()
	entry, ok := digitalPreviews.items[token]
	if ok {
		delete(digitalPreviews.items, token)
	}
	digitalPreviews.mu.Unlock()

	if !ok {
		return nil, 0, errors.New("名单预览不存在或已被使用")
	}
	if digitalPreviewNow().After(entry.expiresAt) {
		return nil, 0, ErrDigitalPreviewExpired
	}
	r, err := s.repo()
	if err != nil {
		return nil, 0, err
	}
	summary := map[string]any{
		"preview_total": len(entry.assets),
		"kind":          entry.kind,
	}
	return r.InsertBatch(ctx, entry.projectID, "digital", entry.assets, summary, createdBy)
}

// CancelPreview 主动作废 token（关闭预览弹窗时调用）。
func CancelDigitalPreview(token string) bool {
	digitalPreviews.mu.Lock()
	defer digitalPreviews.mu.Unlock()
	if _, ok := digitalPreviews.items[token]; ok {
		delete(digitalPreviews.items, token)
		return true
	}
	return false
}

// NamesFromText 把换行/逗号分隔的文本拆成名单，供页面粘贴导入。
func NamesFromText(text string) []string {
	fields := strings.FieldsFunc(text, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ',' || r == ';'
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if s := strings.TrimSpace(f); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// ---------------------------------------------------------------- 候选池

// UpsertCandidates 采集结果入池：与既有名单对账，已在名单的直接标 imported。
// rejected 是用户终态，重复入池只刷新证据字段，不复活。
func (s *DigitalService) UpsertCandidates(ctx context.Context, projectID int64, items []repo.DigitalCandidateInput) (int64, int64, error) {
	if projectID <= 0 {
		return 0, 0, errors.New("project_id 必填")
	}
	if len(items) == 0 {
		return 0, 0, errors.New("没有可入池的候选")
	}
	if len(items) > maxDigitalItems {
		return 0, 0, fmt.Errorf("单次入池最多 %d 条，收到 %d", maxDigitalItems, len(items))
	}

	seen := map[string]bool{}
	fresh := make([]repo.DigitalCandidateInput, 0, len(items))
	for _, a := range items {
		a.Kind = strings.TrimSpace(a.Kind)
		a.Name = strings.Join(strings.Fields(a.Name), " ")
		if !digitalKinds[a.Kind] || a.Name == "" {
			continue
		}
		key := a.Kind + "\x00" + strings.ToLower(a.Name)
		if seen[key] {
			continue
		}
		seen[key] = true
		a.Company = strings.TrimSpace(a.Company)
		a.Platform = strings.TrimSpace(a.Platform)
		a.Source = strings.TrimSpace(a.Source)
		a.EntityName = strings.TrimSpace(a.EntityName)
		a.Evidence = strings.TrimSpace(a.Evidence)
		if a.Source == "" {
			a.Source = "collect"
		}
		fresh = append(fresh, a)
	}
	if len(fresh) == 0 {
		return 0, 0, errors.New("候选全部无效：kind 必须是 app / miniapp / official_account / newmedia 且名称非空")
	}

	r, err := s.repo()
	if err != nil {
		return 0, 0, err
	}
	// 与既有名单对账（按 kind 分组精确匹配，唯一键也是精确匹配）。
	existing := map[string]bool{}
	byKind := map[string][]string{}
	for _, a := range fresh {
		byKind[a.Kind] = append(byKind[a.Kind], a.Name)
	}
	for k, names := range byKind {
		set, err := r.ExistingNames(ctx, projectID, k, names)
		if err != nil {
			return 0, 0, err
		}
		for name := range set {
			existing[k+"\x00"+name] = true
		}
	}
	full := repo.Default()
	if full == nil {
		return 0, 0, errors.New("数据层未初始化")
	}
	return full.DigitalCandidates().UpsertCandidates(ctx, projectID, fresh,
		func(kind, name string) bool { return existing[kind+"\x00"+name] })
}

func (s *DigitalService) ListCandidates(ctx context.Context, f repo.DigitalCandidateFilter) ([]*repo.DigitalCandidate, int64, error) {
	full := repo.Default()
	if full == nil {
		return nil, 0, errors.New("数据层未初始化")
	}
	return full.DigitalCandidates().ListCandidates(ctx, f)
}

// ConfirmCandidates 批量确认候选：经既有两段式导入落名单（生成可撤销回执），
// 确认成功的候选置 imported 记 batch_id。
func (s *DigitalService) ConfirmCandidates(ctx context.Context, projectID int64, ids []int64, createdBy string) (*repo.ImportBatch, int64, error) {
	if projectID <= 0 {
		return nil, 0, errors.New("project_id 必填")
	}
	if len(ids) == 0 {
		return nil, 0, errors.New("ids 必填")
	}
	full := repo.Default()
	if full == nil {
		return nil, 0, errors.New("数据层未初始化")
	}
	rows, err := full.DigitalCandidates().CandidatesByIDs(ctx, projectID, ids)
	if err != nil {
		return nil, 0, err
	}
	assets := make([]repo.DigitalAssetInput, 0, len(rows))
	confirmedIDs := make([]int64, 0, len(rows))
	for _, c := range rows {
		if c.Status != "candidate" {
			continue
		}
		assets = append(assets, repo.DigitalAssetInput{
			Kind: c.Kind, Name: c.Name, Company: c.Company,
			Platform: c.Platform, Source: c.Source,
		})
		confirmedIDs = append(confirmedIDs, c.ID)
	}
	if len(assets) == 0 {
		return nil, 0, errors.New("没有可确认的候选（仅待确认状态可确认）")
	}
	batch, _, err := full.Digital().InsertBatch(ctx, projectID, "digital", assets,
		map[string]any{"preview_total": len(assets), "source": "candidates"}, createdBy)
	if err != nil {
		return nil, 0, err
	}
	confirmed, err := full.DigitalCandidates().ConfirmCandidates(ctx, projectID, confirmedIDs, batch.ID)
	if err != nil {
		return nil, 0, err
	}
	return batch, confirmed, nil
}

// RejectCandidates 批量忽略候选；仅待确认状态可忽略。
func (s *DigitalService) RejectCandidates(ctx context.Context, ids []int64) (int64, error) {
	if len(ids) == 0 {
		return 0, errors.New("ids 必填")
	}
	full := repo.Default()
	if full == nil {
		return 0, errors.New("数据层未初始化")
	}
	rejected, err := full.DigitalCandidates().RejectCandidates(ctx, ids)
	if err != nil {
		return 0, err
	}
	if rejected == 0 {
		return 0, errors.New("没有可忽略的候选（仅待确认状态可忽略）")
	}
	return rejected, nil
}
