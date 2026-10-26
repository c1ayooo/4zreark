package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/repo"

	_ "golang.org/x/image/webp"
)

var (
	ErrProjectInput     = errors.New("项目操作参数错误")
	ErrSeedRestartInput = errors.New("种子重建参数错误")
)

// ProjectOpsService 负责项目生命周期：采集态快照与永久删除。
// 删除是全量级联，所以要求 confirm_code 与项目编码一致，并落审计。
type ProjectOpsService struct{}

func NewProjectOpsService() *ProjectOpsService { return &ProjectOpsService{} }

func (s *ProjectOpsService) assets() (*repo.AssetRepo, error) {
	if repo.Default() == nil {
		return nil, errors.New("数据层未初始化")
	}
	return repo.NewAssetRepo(), nil
}

func (s *ProjectOpsService) CollectionState(ctx context.Context, id int64) (*repo.ProjectCollectionState, error) {
	a, err := s.assets()
	if err != nil {
		return nil, err
	}
	return a.GetProjectCollectionState(ctx, id)
}

func (s *ProjectOpsService) Delete(ctx context.Context, id int64, confirmCode, actor, ip string) (*repo.ProjectDeleteResult, error) {
	if id <= 0 {
		return nil, fmt.Errorf("%w: 非法项目 ID", ErrProjectInput)
	}
	confirmCode = strings.TrimSpace(confirmCode)
	if confirmCode == "" {
		return nil, fmt.Errorf("%w: confirm_code 必填，值为项目编码", ErrProjectInput)
	}
	a, err := s.assets()
	if err != nil {
		return nil, err
	}
	res, err := a.DeleteProject(ctx, id, confirmCode)
	if errors.Is(err, repo.ErrProjectConfirm) {
		return nil, fmt.Errorf("%w: confirm_code 与项目编码不一致", ErrProjectInput)
	}
	if err != nil {
		return nil, err
	}

	if actor == "" {
		actor = "system"
	}
	if err := repo.Default().LogOperation(ctx, repo.OperationLogInput{
		Username:  actor,
		Action:    "project_delete",
		Module:    "asset_governance",
		Target:    res.Code,
		Detail:    fmt.Sprintf("永久删除项目 %s（sites=%d records=%d endpoints=%d seeds=%d plans=%d runs=%d targets=%d）", res.Name, res.Sites, res.Records, res.Endpoints, res.Seeds, res.Plans, res.Runs, res.Targets),
		IP:        ip,
		UserAgent: "governance/project-delete",
	}); err != nil {
		log.Printf("[Project] 项目 %s 已删除，但审计日志写入失败: %v", res.Code, err)
	}
	return res, nil
}

// SeedRestartService 负责「重建计划」：先预览、再用一次性 token 执行。
// 预览会展示将被级联删除的计划/批次/执行单元数量，防止误触。
type SeedRestartService struct{}

func NewSeedRestartService() *SeedRestartService { return &SeedRestartService{} }

const SeedRestartTTL = 15 * time.Minute

var (
	seedRestartMu     sync.Mutex
	seedRestartTokens = map[string]*seedRestartTicket{}
	seedRestartNow    = time.Now
)

type seedRestartTicket struct {
	seedID    int64
	interval  int
	budget    map[string]any
	expiresAt time.Time
}

// SeedRestartPreview 是重建前预览。
type SeedRestartPreview struct {
	Seed          *repo.Seed     `json:"seed"`
	Plans         []*repo.Plan   `json:"plans"`
	Runs          int64          `json:"runs"`
	Targets       int64          `json:"run_targets"`
	IntervalHours int            `json:"interval_hours"`
	Budget        map[string]any `json:"budget"`
	Token         string         `json:"token"`
	ExpiresAt     time.Time      `json:"expires_at"`
}

func (s *SeedRestartService) seedOps() (*repo.SeedOpsRepo, error) {
	if repo.Default() == nil {
		return nil, errors.New("数据层未初始化")
	}
	return repo.Default().SeedOps(), nil
}

func (s *SeedRestartService) Preview(ctx context.Context, seedID int64, intervalHours int, budget map[string]any) (*SeedRestartPreview, error) {
	if seedID <= 0 {
		return nil, fmt.Errorf("%w: 非法种子 ID", ErrSeedRestartInput)
	}
	ops, err := s.seedOps()
	if err != nil {
		return nil, err
	}
	snap, err := ops.Snapshot(ctx, seedID)
	if err != nil {
		return nil, err
	}

	if intervalHours == 0 {
		intervalHours = 24
		if len(snap.Plans) > 0 {
			intervalHours = snap.Plans[0].IntervalHours
		}
	}
	if intervalHours < 1 || intervalHours > 720 {
		return nil, fmt.Errorf("%w: interval_hours 需在 1..720", ErrSeedRestartInput)
	}
	if budget == nil {
		budget = map[string]any{}
		if len(snap.Plans) > 0 {
			budget = snap.Plans[0].Budget
		}
	}

	now := seedRestartNow()
	token := randomToken()
	seedRestartMu.Lock()
	for k, v := range seedRestartTokens {
		if now.After(v.expiresAt) {
			delete(seedRestartTokens, k)
		}
	}
	seedRestartTokens[token] = &seedRestartTicket{
		seedID:    seedID,
		interval:  intervalHours,
		budget:    budget,
		expiresAt: now.Add(SeedRestartTTL),
	}
	seedRestartMu.Unlock()

	return &SeedRestartPreview{
		Seed: snap.Seed, Plans: snap.Plans, Runs: snap.Runs, Targets: snap.Targets,
		IntervalHours: intervalHours, Budget: budget,
		Token: token, ExpiresAt: now.Add(SeedRestartTTL),
	}, nil
}

func (s *SeedRestartService) Restart(ctx context.Context, seedID int64, token, actor, ip string) (*repo.Plan, *repo.SeedRestartCounts, error) {
	if seedID <= 0 {
		return nil, nil, fmt.Errorf("%w: 非法种子 ID", ErrSeedRestartInput)
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, nil, fmt.Errorf("%w: 请先调用 restart-preview 获取 token", ErrSeedRestartInput)
	}

	now := seedRestartNow()
	seedRestartMu.Lock()
	ticket, ok := seedRestartTokens[token]
	if !ok {
		seedRestartMu.Unlock()
		return nil, nil, fmt.Errorf("%w: token 不存在或已被使用，请重新预览", ErrSeedRestartInput)
	}
	if ticket.seedID != seedID {
		seedRestartMu.Unlock()
		return nil, nil, fmt.Errorf("%w: token 与种子不匹配", ErrSeedRestartInput)
	}
	if now.After(ticket.expiresAt) {
		delete(seedRestartTokens, token)
		seedRestartMu.Unlock()
		return nil, nil, fmt.Errorf("%w: 预览已过期（15 分钟有效），请重新预览", ErrSeedRestartInput)
	}
	delete(seedRestartTokens, token)
	seedRestartMu.Unlock()

	ops, err := s.seedOps()
	if err != nil {
		return nil, nil, err
	}
	plan, counts, err := ops.RestartPlan(ctx, seedID, ticket.interval, ticket.budget)
	if err != nil {
		return nil, nil, err
	}

	if actor == "" {
		actor = "system"
	}
	if err := repo.Default().LogOperation(ctx, repo.OperationLogInput{
		Username:  actor,
		Action:    "seed_restart",
		Module:    "asset_governance",
		Target:    plan.SeedValue,
		Detail:    fmt.Sprintf("重建计划：删除 plans=%d runs=%d targets=%d，新计划 interval=%dh（seed_id=%d）", counts.Plans, counts.Runs, counts.Targets, ticket.interval, seedID),
		IP:        ip,
		UserAgent: "governance/seed-restart",
	}); err != nil {
		log.Printf("[Seed] 种子 %d 计划已重建，但审计日志写入失败: %v", seedID, err)
	}
	return plan, counts, nil
}

const (
	ProjectIconMaxBytes  = 256 << 10
	ProjectIconMaxPixels = 1_000_000
)

// SetIcon 校验并保存项目图标；字节按 sha256 去重进 asset_icons，
// projects.icon_sha256 只存引用。front end 通过 /api/asset-icons/{sha} 取图。
func (s *ProjectOpsService) SetIcon(ctx context.Context, id int64, data []byte, contentType string) (*repo.Project, error) {
	if id <= 0 {
		return nil, fmt.Errorf("%w: 非法项目 ID", ErrProjectInput)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: 图标内容为空", ErrProjectInput)
	}
	if len(data) > ProjectIconMaxBytes {
		return nil, fmt.Errorf("%w: 图标不能超过 %d KiB", ErrProjectInput, ProjectIconMaxBytes>>10)
	}
	ctype := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	if ctype == "" {
		ctype = http.DetectContentType(data)
	}
	switch ctype {
	case "image/png", "image/jpeg", "image/webp":
	default:
		return nil, fmt.Errorf("%w: 仅支持 PNG / JPEG / WebP，收到 %s", ErrProjectInput, ctype)
	}
	cfg, format, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("%w: 图片解码失败: %v", ErrProjectInput, err)
	}
	if cfg.Width <= 0 || cfg.Height <= 0 || cfg.Width*cfg.Height > ProjectIconMaxPixels {
		return nil, fmt.Errorf("%w: 图标像素不能超过 %d", ErrProjectInput, ProjectIconMaxPixels)
	}
	if ctype == "" {
		switch format {
		case "png":
			ctype = "image/png"
		case "jpeg":
			ctype = "image/jpeg"
		case "webp":
			ctype = "image/webp"
		}
	}

	a, err := s.assets()
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	sha := hex.EncodeToString(sum[:])
	if err := repo.Default().Clusters().UpsertIcon(ctx, repo.IconInput{
		SHA256: sha, MMH3: int64(faviconMMH3(data)), ContentType: ctype,
		Size: len(data), Data: data,
	}); err != nil {
		return nil, err
	}
	if err := a.SetProjectIcon(ctx, id, sha); err != nil {
		return nil, err
	}
	return a.GetProject(ctx, id)
}

// ClearIcon 清空项目图标引用。
func (s *ProjectOpsService) ClearIcon(ctx context.Context, id int64) (*repo.Project, error) {
	a, err := s.assets()
	if err != nil {
		return nil, err
	}
	if err := a.ClearProjectIcon(ctx, id); err != nil {
		return nil, err
	}
	return a.GetProject(ctx, id)
}

func (s *ProjectOpsService) Options(ctx context.Context) ([]*repo.ProjectOption, error) {
	a, err := s.assets()
	if err != nil {
		return nil, err
	}
	return a.ListProjectOptions(ctx)
}

func (s *ProjectOpsService) Stats(ctx context.Context) (*repo.ProjectStats, error) {
	a, err := s.assets()
	if err != nil {
		return nil, err
	}
	return a.ProjectStats(ctx)
}

func (s *ProjectOpsService) CycleStatus(ctx context.Context) (*repo.ProjectCycleStatus, error) {
	a, err := s.assets()
	if err != nil {
		return nil, err
	}
	return a.ProjectCycleStatus(ctx)
}
