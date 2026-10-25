package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/internal/enterprise"
	"github.com/c1ayooo/4zreark/repo"
)

// 数字资产采集编排：数据源定位企业 → 拉取 APP/小程序/公众号/新媒体 → 候选入池。
// 只产候选，不直写名单；会话凭据语义与企业采集一致（请求体携带，前端不落盘）。

type DigitalCollectInput struct {
	ProjectID int64  `json:"project_id"`
	Provider  string `json:"provider"`
	Keyword   string `json:"keyword"`    // 企业名
	Limit     int    `json:"limit"`      // 参与采集的企业候选数
	MaxAssets int    `json:"max_assets"` // 单企业资产上限
	Cookie    string `json:"cookie"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	ProxyURL  string `json:"proxy_url"`

	// ProviderOverride 供测试注入 fake 数据源；正式调用按 Provider 名称构造。
	ProviderOverride enterprise.Provider `json:"-"`
}

type DigitalCollectResult struct {
	Provider   string   `json:"provider"`
	Keyword    string   `json:"keyword"`
	Entities   int      `json:"entities"`
	Found      int      `json:"found"`
	Candidates int64    `json:"candidates"`
	Imported   int64    `json:"imported"`
	Warnings   []string `json:"warnings,omitempty"`
}

// CollectCandidates 手动采集入口：按企业名从数据源拉取数字资产并入候选池。
// 单个企业的拉取失败只记 warning，不中断整单。
func (s *DigitalService) CollectCandidates(ctx context.Context, in DigitalCollectInput) (*DigitalCollectResult, error) {
	if in.ProjectID <= 0 {
		return nil, errors.New("project_id 必填")
	}
	keyword := strings.TrimSpace(in.Keyword)
	if keyword == "" {
		return nil, errors.New("检索关键词（企业名）必填")
	}
	limit := in.Limit
	if limit <= 0 || limit > 5 {
		limit = 1
	}
	maxAssets := in.MaxAssets
	if maxAssets <= 0 || maxAssets > 500 {
		maxAssets = 100
	}

	provider := in.ProviderOverride
	if provider == nil {
		var err error
		provider, err = newEnterpriseProvider(in.Provider, in.Cookie, in.Username, in.Password, in.ProxyURL)
		if err != nil {
			NoteDatasourceSessionFailure(in.Provider, err)
			return nil, err
		}
	}
	dp, ok := provider.(enterprise.DigitalAssetsProvider)
	if !ok {
		return nil, fmt.Errorf("数据源 %s 暂不支持数字资产采集（当前支持：xiaolanben）", provider.Name())
	}

	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	refs, err := provider.Search(ctx, keyword, limit)
	if err != nil {
		return nil, fmt.Errorf("企业检索失败: %w", err)
	}

	out := &DigitalCollectResult{Provider: provider.Name(), Keyword: keyword}
	all := make([]repo.DigitalCandidateInput, 0, maxAssets)
	for _, ref := range refs {
		hits, _, err := dp.DigitalAssets(ctx, ref.ExtID, 1, maxAssets)
		if err != nil {
			out.Warnings = append(out.Warnings, ref.Name+"：数字资产拉取失败（"+err.Error()+"）")
			continue
		}
		out.Entities++
		for _, h := range hits {
			if h.EntityName == "" {
				h.EntityName = ref.Name
			}
			if h.Company == "" {
				h.Company = ref.Name
			}
			all = append(all, repo.DigitalCandidateInput{
				Kind: h.Kind, Name: h.Name, Company: h.Company, Platform: h.Platform,
				Source: provider.Name(), EntityName: h.EntityName, Evidence: h.Evidence,
			})
		}
	}
	out.Found = len(all)
	if len(all) == 0 {
		if len(out.Warnings) == 0 {
			out.Warnings = append(out.Warnings, "未采集到数字资产（上游企业详情页无 APP/小程序/公众号/新媒体数据）")
		}
		return out, nil
	}

	candidates, imported, err := s.UpsertCandidates(ctx, in.ProjectID, all)
	if err != nil {
		return nil, err
	}
	out.Candidates = candidates
	out.Imported = imported
	return out, nil
}
