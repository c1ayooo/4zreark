package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/c1ayooo/4zreark/repo"
)

// SeedCatalogService 提供种子类型的静态能力说明与项目级覆盖统计。
// 前端用 capabilities 渲染表单，不再把 kind / capability 字段硬编码在页面里。
type SeedCatalogService struct{}

func NewSeedCatalogService() *SeedCatalogService { return &SeedCatalogService{} }

type SeedKindCapability struct {
	Kind        string         `json:"kind"`
	Label       string         `json:"label"`
	Static      bool           `json:"static"`
	Live        bool           `json:"live"`
	Supported   bool           `json:"supported"`
	Requires    []string       `json:"requires,omitempty"`
	Defaults    map[string]any `json:"defaults,omitempty"`
	DataSources []string       `json:"data_sources,omitempty"`
	Note        string         `json:"note,omitempty"`
}

type SeedCapabilities struct {
	Kinds            []SeedKindCapability `json:"kinds"`
	PortsDefault     []int                `json:"ports_default"`
	MaxExpandTargets int                  `json:"max_expand_targets"`
	PreviewSample    int                  `json:"preview_sample_size"`
}

func (s *SeedCatalogService) Capabilities() *SeedCapabilities {
	return &SeedCapabilities{
		PortsDefault:     []int{80, 443},
		MaxExpandTargets: SeedMaxTargets,
		PreviewSample:    SeedPreviewSampleSize,
		Kinds: []SeedKindCapability{
			{
				Kind: "domain", Label: "域名", Static: true, Supported: true,
				Defaults: map[string]any{"ports": []int{443}},
				Note:     "静态展开取项目内已归并站点的入口；项目内没有站点时回落根域 443",
			},
			{
				Kind: "cidr", Label: "网段", Static: true, Supported: true,
				Defaults: map[string]any{"ports": []int{80, 443}},
				Note:     "只支持 IPv4；默认最小前缀 /16，跳过网络地址与广播地址",
			},
			{
				Kind: "dict", Label: "字典", Static: true, Supported: true,
				Requires: []string{"value=基础域名", "capability.dictionary_ids"},
				Defaults: map[string]any{"ports": []int{443}},
				Note:     "只接受单标签词；基础域本身也会生成一条目标",
			},
			{
				Kind: "company", Label: "公司", Static: false, Live: true, Supported: true,
				Requires:    []string{"capability.live=true"},
				DataSources: []string{"spacemap/icpquery", "ENScan"},
				Note:        "静态预览返回空态与 warning；live 需要已配置 ICP/ENScan",
			},
			{
				Kind: "repo", Label: "代码仓库", Static: false, Live: true, Supported: true,
				Requires:    []string{"capability.live=true"},
				DataSources: []string{"GitHub"},
				Note:        "从默认分支文本文件提取域名；无 token 会提示限流",
			},
			{
				Kind: "app", Label: "APP / 新媒体", Static: false, Supported: false,
				Note: "商店数据源未接入：后端保留 kind 白名单，预览返回空态与 warning，前端已隐藏该类型",
			},
		},
	}
}

func (s *SeedCatalogService) DomainCounts(ctx context.Context, projectID int64) ([]*repo.SeedDomainCount, error) {
	if repo.Default() == nil {
		return nil, errors.New("数据层未初始化")
	}
	return repo.Default().SeedOps().DomainCounts(ctx, projectID)
}

// SeedBatchItem 是批量创建里的一条种子；interval_hours>0 时同时建计划。
type SeedBatchItem struct {
	Kind          string         `json:"kind"`
	Value         string         `json:"value"`
	Capability    map[string]any `json:"capability"`
	Enabled       *bool          `json:"enabled"`
	IntervalHours int            `json:"interval_hours"`
	Budget        map[string]any `json:"budget"`
}

type SeedBatchRequest struct {
	ProjectID int64           `json:"project_id"`
	Items     []SeedBatchItem `json:"items"`
}

type SeedBatchItemResult struct {
	Index  int    `json:"index"`
	Kind   string `json:"kind"`
	Value  string `json:"value"`
	Status string `json:"status"` // created / created_plan_failed / duplicate / invalid / failed
	SeedID int64  `json:"seed_id,omitempty"`
	PlanID int64  `json:"plan_id,omitempty"`
	Error  string `json:"error,omitempty"`
}

type SeedBatchResult struct {
	Requested int                   `json:"requested"`
	Created   int                   `json:"created"`
	Duplicate int                   `json:"duplicate"`
	Invalid   int                   `json:"invalid"`
	Failed    int                   `json:"failed"`
	Items     []SeedBatchItemResult `json:"items"`
}

const seedBatchMax = 100

// CreateBatch 批量建种子（可选同时建计划）。逐条返回状态，不因一条失败中断整批。
func (s *SeedCatalogService) CreateBatch(ctx context.Context, req SeedBatchRequest, actor, ip string) (*SeedBatchResult, error) {
	if repo.Default() == nil {
		return nil, errors.New("数据层未初始化")
	}
	if req.ProjectID <= 0 {
		return nil, invalidSeed("project_id 必填")
	}
	if len(req.Items) == 0 || len(req.Items) > seedBatchMax {
		return nil, invalidSeed("items 数量需在 1..%d", seedBatchMax)
	}
	seeds := repo.Default().Seeds()
	res := &SeedBatchResult{Requested: len(req.Items), Items: make([]SeedBatchItemResult, 0, len(req.Items))}

	for i, item := range req.Items {
		out := SeedBatchItemResult{Index: i, Kind: item.Kind, Value: item.Value}
		kind := strings.ToLower(strings.TrimSpace(item.Kind))
		value := strings.TrimSpace(item.Value)
		if !validSeedKinds[kind] || value == "" {
			out.Status = "invalid"
			out.Error = "kind 不在白名单或 value 为空"
			res.Invalid++
			res.Items = append(res.Items, out)
			continue
		}
		if item.IntervalHours < 0 || item.IntervalHours > 720 || (item.IntervalHours > 0 && item.IntervalHours < 1) {
			out.Status = "invalid"
			out.Error = "interval_hours 需在 1..720"
			res.Invalid++
			res.Items = append(res.Items, out)
			continue
		}
		enabled := true
		if item.Enabled != nil {
			enabled = *item.Enabled
		}
		out.Kind, out.Value = kind, value
		seed := &repo.Seed{
			ProjectID: req.ProjectID, Kind: kind, Value: value,
			Capability: item.Capability, Enabled: enabled,
		}
		if err := seeds.CreateSeed(ctx, seed); err != nil {
			switch {
			case errors.Is(err, repo.ErrDuplicate):
				out.Status = "duplicate"
				out.Error = err.Error()
				res.Duplicate++
			default:
				out.Status = "failed"
				out.Error = err.Error()
				res.Failed++
			}
			res.Items = append(res.Items, out)
			continue
		}
		out.SeedID = seed.ID
		res.Created++
		out.Status = "created"
		if item.IntervalHours > 0 {
			plan := &repo.Plan{
				SeedID: seed.ID, IntervalHours: item.IntervalHours,
				Budget: item.Budget, Enabled: true,
			}
			if err := seeds.CreatePlan(ctx, plan); err != nil {
				out.Status = "created_plan_failed"
				out.Error = "种子已创建，计划创建失败: " + err.Error()
			} else {
				out.PlanID = plan.ID
			}
		}
		res.Items = append(res.Items, out)
	}

	if actor == "" {
		actor = "system"
	}
	if err := repo.Default().LogOperation(ctx, repo.OperationLogInput{
		Username: actor, Action: "seed_batch_create", Module: "asset_governance",
		Target: fmt.Sprintf("project=%d", req.ProjectID),
		Detail: fmt.Sprintf("批量建种子：requested=%d created=%d duplicate=%d invalid=%d failed=%d",
			res.Requested, res.Created, res.Duplicate, res.Invalid, res.Failed),
		IP: ip, UserAgent: "governance/seed-batch",
	}); err != nil {
		log.Printf("[SeedCatalog] 批量建种子审计写入失败: %v", err)
	}
	return res, nil
}
