package service

import (
	"context"
	"errors"
	"sort"
	"strings"

	"github.com/c1ayooo/4zreark/internal/componentprofile"
	"github.com/c1ayooo/4zreark/repo"
)

// ComponentService 组件档案：把指纹识别出的产品连到它已知的 CVE 上。
type ComponentService struct{}

func NewComponentService() *ComponentService { return &ComponentService{} }

// ComponentCVE 是一条「组件 -> CVE」记录。
type ComponentCVE struct {
	Product  string `json:"product"`
	CVE      string `json:"cve"`
	Evidence string `json:"evidence"`
}

// CVEs 查询某产品的已知 CVE。命中不到返回空列表，不报错。
func (s *ComponentService) CVEs(ctx context.Context, product string, limit int) ([]ComponentCVE, error) {
	product = strings.TrimSpace(product)
	if product == "" {
		return nil, errors.New("product 不能为空")
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	r := repo.Default()
	if r == nil {
		return nil, errors.New("数据库未就绪")
	}
	rules, err := r.Fingerprints().ListRules(ctx, false)
	if err != nil {
		return nil, err
	}
	// 用规则名/分类作为产品来源：与 4zreark 现有的指纹库对齐，不另建产品表。
	profiles := make([]componentprofile.Profile, 0, len(rules))
	seen := map[string]bool{}
	for _, rule := range rules {
		name := strings.TrimSpace(rule.Name)
		if name == "" {
			continue
		}
		key := componentprofile.Normalize(name)
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		profiles = append(profiles, componentprofile.Profile{
			Product: key, DisplayName: name, Category: rule.Category,
			Tokens: componentprofile.MatchTokens(key),
		})
	}

	var templates []componentprofile.TemplateIndexEntry
	if pocs, _, perr := r.Pocs().List(ctx, repo.POCFilter{Type: "nuclei", Page: 1, PageSize: 500}); perr == nil {
		for _, p := range pocs {
			if p == nil || len(p.CVEID) == 0 {
				continue
			}
			tech := strings.TrimSpace(p.TemplateID)
			for _, tag := range p.Tags {
				tech += " " + tag
			}
			templates = append(templates, componentprofile.TemplateIndexEntry{
				ID: p.TemplateID, Tech: tech, CVEs: p.CVEID,
			})
		}
	}
	if len(templates) == 0 {
		return nil, nil
	}

	edges := componentprofile.MineCVEEdges(templates, profiles)
	want := componentprofile.Normalize(product)
	out := make([]ComponentCVE, 0, len(edges))
	for _, e := range edges {
		if e.Product != want {
			continue
		}
		out = append(out, ComponentCVE{Product: e.Product, CVE: e.Target, Evidence: e.Evidence})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CVE < out[j].CVE })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// VulnEvidenceQuality 是一条漏洞的证据质量检查结果。
type VulnEvidenceQuality struct {
	VulnID     string   `json:"vuln_id"`
	Name       string   `json:"name"`
	Score      int      `json:"score"`
	Missing    []string `json:"missing"`
	Upgradable bool     `json:"upgradable"`
}

// EvidenceQuality 列出证据不完整的漏洞（缺 PoC 报文、复现步骤或解决方案）。
func (s *ComponentService) EvidenceQuality(ctx context.Context, workspaceID string, limit int) ([]VulnEvidenceQuality, error) {
	r := repo.Default()
	if r == nil {
		return nil, errors.New("数据库未就绪")
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	vulns, _, err := r.Vulns().List(ctx, repo.VulnFilter{WorkspaceID: workspaceID, Page: 1, PageSize: limit})
	if err != nil {
		return nil, err
	}
	out := make([]VulnEvidenceQuality, 0, len(vulns))
	for _, v := range vulns {
		var missing []string
		score := 100
		if strings.TrimSpace(v.Request) == "" {
			missing = append(missing, "request")
			score -= 30
		}
		if strings.TrimSpace(v.Response) == "" {
			missing = append(missing, "response")
			score -= 30
		}
		if strings.TrimSpace(v.Evidence) == "" && strings.TrimSpace(v.Request) == "" {
			missing = append(missing, "evidence")
			score -= 20
		}
		if strings.TrimSpace(v.Solution) == "" {
			missing = append(missing, "solution")
			score -= 20
		}
		out = append(out, VulnEvidenceQuality{
			VulnID: v.ID.Hex(), Name: v.Name, Score: score,
			Missing: missing, Upgradable: len(missing) > 0,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Score < out[j].Score })
	return out, nil
}
