package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/c1ayooo/4zreark/internal/enterprise"
	"github.com/c1ayooo/4zreark/repo"
)

// 项目采集概览：项目详情页「采集详情」卡片的数据面。
// 回答三件事——采集到了什么（实体/域名/种子/站点）、采集任务跑得怎么样（历史与状态）、
// 有没有问题（质量信号：中止/上限/未采到对外投资/待确认候选）。

type CollectJobRow struct {
	Provider   string `json:"provider"`
	Keyword    string `json:"keyword"`
	Status     string `json:"status"`
	Nodes      int    `json:"nodes"`
	Entities   int    `json:"entities"`
	Domains    int    `json:"domains"`
	Digital    int    `json:"digital"`
	Error      string `json:"error"`
	CreatedAt  string `json:"created_at"`
	FinishedAt string `json:"finished_at,omitempty"`
}

type CollectOverview struct {
	// 采集到了什么
	EntityTotal  int            `json:"entity_total"`
	EntityType   map[string]int `json:"entity_type"` // root/branch/invest/group
	SeedCount    int            `json:"seed_count"`
	Candidates   map[string]int `json:"candidates"` // candidate/imported/rejected
	CandidateNIP int            `json:"candidate_no_icp"` // 无备案号的待确认候选（不会自动转种子）
	SiteCount    int            `json:"site_count"`
	// 采集任务
	Jobs []CollectJobRow `json:"jobs"`
	// 质量信号
	Quality []CollectQualityNote `json:"quality"`
}

type CollectQualityNote struct {
	Level   string `json:"level"` // error / warn / info
	Message string `json:"message"`
}

// BuildCollectOverview 组装项目采集概览。
func (s *EnterpriseService) BuildCollectOverview(ctx context.Context, projectID int64) (*CollectOverview, error) {
	if projectID <= 0 {
		return nil, fmt.Errorf("project_id 必填")
	}
	r := repo.Default()
	if r == nil {
		return nil, fmt.Errorf("数据层未初始化")
	}
	out := &CollectOverview{
		EntityType: map[string]int{},
		Candidates: map[string]int{},
	}

	if counts, err := r.CollectEntityCount(ctx, projectID); err == nil {
		out.EntityType = counts
		for _, n := range counts {
			out.EntityTotal += n
		}
	}
	if candCounts, noICP, err := r.CollectCandidateCount(ctx, projectID); err == nil {
		out.Candidates = candCounts
		out.CandidateNIP = noICP
	}
	if seeds, err := r.Seeds().ListSeeds(ctx, projectID); err == nil {
		out.SeedCount = len(seeds)
	}
	if n, err := r.CollectSiteCount(ctx, projectID); err == nil {
		out.SiteCount = n
	}

	// 采集任务历史（最近 20 条）
	jobs, err := r.ListEnterpriseJobs(ctx, projectID, 20)
	if err == nil {
		for _, j := range jobs {
			row := CollectJobRow{
				Provider: j.Provider, Keyword: j.Keyword, Status: j.Status,
				Nodes: j.Nodes, Entities: j.Entities, Domains: j.Domains, Digital: j.Digital,
				Error: j.Error, CreatedAt: j.CreatedAt.Format("2006-01-02 15:04"),
			}
			if j.FinishedAt != nil {
				row.FinishedAt = j.FinishedAt.Format("2006-01-02 15:04")
			}
			out.Jobs = append(out.Jobs, row)
		}
	}

	out.Quality = buildCollectQuality(out, jobs)
	return out, nil
}

// buildCollectQuality 质量信号：让「采漏了/没采完/待确认」显式浮出来，
// 不再依赖用户对照企业身份页两个表格自己发现。
func buildCollectQuality(out *CollectOverview, jobs []enterprise.Job) []CollectQualityNote {
	notes := []CollectQualityNote{}
	add := func(level, msg string) {
		notes = append(notes, CollectQualityNote{Level: level, Message: msg})
	}

	for _, j := range jobs {
		if j.Status != "error" {
			continue
		}
		level := "error"
		if strings.Contains(j.Error, "节点上限") {
			level = "warn"
			add(level, fmt.Sprintf("%s采集在 %d 节点处中止（%s）：还有子公司没展开，调大「采集上限」后重跑即可续采",
				j.Provider, j.MaxNodes, j.Error))
			continue
		}
		add(level, fmt.Sprintf("%s采集「%s」失败：%s", j.Provider, j.Keyword, j.Error))
	}

	// 跑过采集但没采到对外投资：爱企查对该数据面有权限门槛（实测 -23），
	// 集团型项目换天眼查/小蓝本。
	investTotal := out.EntityType["invest"]
	if out.EntityTotal > 0 && investTotal == 0 && len(out.Jobs) > 0 {
		add("warn", "未采到任何对外投资子公司：爱企查对外投资接口可能拒绝当前会话（实测返回 -23），集团型项目建议换天眼查/小蓝本重跑")
	}

	if pending := out.Candidates["candidate"]; pending > 0 {
		msg := fmt.Sprintf("有 %d 条候选域名待确认转种子（确认后才会进入扫描范围）", pending)
		if out.CandidateNIP > 0 {
			msg += fmt.Sprintf("，其中 %d 条无备案号不会自动转种子", out.CandidateNIP)
		}
		add("info", msg)
	}
	if out.SeedCount > 0 && out.SiteCount == 0 {
		add("info", "已有种子但还没有站点资产：建一轮流水线任务（子域/端口/指纹）开始扫描")
	}
	return notes
}
