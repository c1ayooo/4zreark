package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/scanner/vulnscan/nuclei"
)

// NucleiService 是 nuclei 模板的唯一入口。
//
// 数据源只有一处：PG 的 pocs 表。历史上有两套模板库——POC 管理写 pocs 表、
// /api/nuclei/templates 读文件系统 config/nuclei-templates（该目录在仓库里
// 并不存在）。这里把两者合并：列表/详情/上传/删除/统计/扫描全部走 pocs 表，
// 文件系统 loader 只作为内存执行载体，不再拥有数据。
type NucleiService struct{}

func NewNucleiService() *NucleiService { return &NucleiService{} }

func (s *NucleiService) store() (repo.PocRepo, error) {
	r := repo.Default()
	if r == nil {
		return nil, errors.New("数据库未就绪")
	}
	return r.Pocs(), nil
}

// ListTemplates 分页查询模板。Type 缺省固定 nuclei——xray/custom 只是标签，
// 不是可执行的 nuclei 模板。
func (s *NucleiService) ListTemplates(f repo.POCFilter) ([]*models.POC, int64, error) {
	st, err := s.store()
	if err != nil {
		return nil, 0, err
	}
	if f.Type == "" {
		f.Type = "nuclei"
	}
	ctx, cancel := dbCtx()
	defer cancel()
	return st.List(ctx, f)
}

// GetTemplate 先按 24 位主键找，再按 nuclei 模板 ID 找。
func (s *NucleiService) GetTemplate(id string) (*models.POC, error) {
	st, err := s.store()
	if err != nil {
		return nil, err
	}
	ctx, cancel := dbCtx()
	defer cancel()

	if repo.ValidID(id) {
		if p, err := st.GetByID(ctx, id); err == nil {
			return p, nil
		}
	}
	return st.GetByTemplateID(ctx, id)
}

// UpsertTemplate 解析 YAML 并按 template_id / name 覆盖写。
func (s *NucleiService) UpsertTemplate(content []byte) (*models.POC, error) {
	poc, err := ParseNucleiTemplateYAML(content)
	if err != nil {
		return nil, err
	}
	st, err := s.store()
	if err != nil {
		return nil, err
	}
	ctx, cancel := dbCtx()
	defer cancel()
	if err := st.Upsert(ctx, poc); err != nil {
		return nil, err
	}
	return poc, nil
}

// DeleteTemplate 按 nuclei 模板 ID 或 24 位主键删除。
func (s *NucleiService) DeleteTemplate(id string) error {
	p, err := s.GetTemplate(id)
	if err != nil {
		return err
	}
	st, err := s.store()
	if err != nil {
		return err
	}
	ctx, cancel := dbCtx()
	defer cancel()
	return st.Delete(ctx, p.ID.Hex())
}

// Tags 聚合模板库里的全部标签。
func (s *NucleiService) Tags() ([]string, error) {
	st, err := s.store()
	if err != nil {
		return nil, err
	}
	ctx, cancel := dbCtx()
	defer cancel()
	items, err := s.allTemplates(ctx, st, repo.POCFilter{Type: "nuclei"})
	if err != nil {
		return nil, err
	}
	set := map[string]bool{}
	for _, p := range items {
		for _, t := range p.Tags {
			if t = strings.TrimSpace(t); t != "" {
				set[t] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	sort.Strings(out)
	return out, nil
}

// Statistics 模板统计。ByType 里能看到 nuclei / xray / custom 的分布。
func (s *NucleiService) Statistics() (*repo.POCStats, error) {
	st, err := s.store()
	if err != nil {
		return nil, err
	}
	ctx, cancel := dbCtx()
	defer cancel()
	return st.Stats(ctx)
}

// Validate 只解析不入库，供上传前校验。
func (s *NucleiService) Validate(content []byte) (*models.POC, *nuclei.NucleiTemplate, error) {
	poc, err := ParseNucleiTemplateYAML(content)
	if err != nil {
		return nil, nil, err
	}
	tpl, err := nuclei.NewTemplateLoader().Parse(content, "validation")
	if err != nil {
		return nil, nil, err
	}
	return poc, tpl, nil
}

// allTemplates 翻页取全量。repo 的分页上限是 500，直接传 5000 会被夹成 20，
// 之前漏洞扫描只加载到 20 个模板就是这个原因。
func (s *NucleiService) allTemplates(ctx context.Context, st repo.PocRepo, f repo.POCFilter) ([]*models.POC, error) {
	const pageSize = 500
	out := make([]*models.POC, 0, 1024)
	for page := 1; ; page++ {
		f.Page = page
		f.PageSize = pageSize
		items, total, err := st.List(ctx, f)
		if err != nil {
			return nil, err
		}
		out = append(out, items...)
		if len(items) < pageSize || int64(len(out)) >= total {
			break
		}
	}
	return out, nil
}

// verifiedRe 匹配 template metadata 里的 verified: true。
// 未验证模板里有大量「status 200 即命中」的宽匹配器，默认不参与扫描。
var verifiedRe = regexp.MustCompile(`(?m)^\s*verified:\s*true\s*$`)

// MaterializeTemplates 把启用的模板按严重度过滤后写到 dir，供 nuclei CLI 执行。
// 返回写入的模板条数。CLI 才能正确处理 DSL / 多请求 / payload 这些模板特性，
// 进程内执行器只适合简单匹配。
func (s *NucleiService) MaterializeTemplates(dir string, severities, ids, tags []string) (int, error) {
	st, err := s.store()
	if err != nil {
		return 0, err
	}
	ctx, cancel := dbCtx()
	defer cancel()

	enabled := true
	items, err := s.allTemplates(ctx, st, repo.POCFilter{Type: "nuclei", Enabled: &enabled})
	if err != nil {
		return 0, err
	}

	count := 0
	explicit := len(ids) > 0
	for _, p := range items {
		if strings.TrimSpace(p.Content) == "" {
			continue
		}
		if explicit {
			hit := false
			for _, id := range ids {
				if id == p.TemplateID {
					hit = true
					break
				}
			}
			if !hit {
				continue
			}
		} else if !verifiedRe.MatchString(p.Content) {
			// 默认只跑已验证模板：未验证模板里宽匹配器太多，误报率极高。
			continue
		}
		if len(tags) > 0 {
			hit := false
			for _, want := range tags {
				for _, have := range p.Tags {
					if strings.EqualFold(have, want) {
						hit = true
						break
					}
				}
				if hit {
					break
				}
			}
			if !hit {
				continue
			}
		}
		if len(severities) > 0 {
			ok := false
			for _, sev := range severities {
				if strings.EqualFold(string(p.Severity), sev) {
					ok = true
					break
				}
			}
			if !ok {
				continue
			}
		}
		name := strings.Map(func(r rune) rune {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
				(r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
				return r
			}
			return '_'
		}, p.TemplateID)
		if name == "" {
			name = fmt.Sprintf("tpl-%d", p.ID)
		}
		if err := os.WriteFile(filepath.Join(dir, name+".yaml"), []byte(p.Content), 0o600); err != nil {
			continue
		}
		count++
	}
	return count, nil
}

// BuildLoader 从库里启用中的模板构建执行器 loader。返回实际可执行的条数；
// 解析失败的模板跳过并计数，不影响其余模板。
func (s *NucleiService) BuildLoader(f repo.POCFilter) (*nuclei.TemplateLoader, int, int, error) {
	enabled := true
	f.Enabled = &enabled
	if f.Type == "" {
		f.Type = "nuclei"
	}
	st, err := s.store()
	if err != nil {
		return nil, 0, 0, err
	}
	ctx, cancel := dbCtx()
	defer cancel()
	items, err := s.allTemplates(ctx, st, f)
	if err != nil {
		return nil, 0, 0, err
	}

	loader := nuclei.NewTemplateLoader()
	loaded, skipped := 0, 0
	for _, p := range items {
		if strings.TrimSpace(p.Content) == "" {
			skipped++
			continue
		}
		tpl, err := loader.Parse([]byte(p.Content), "db:"+p.TemplateID)
		if err != nil {
			skipped++
			continue
		}
		loader.AddTemplate(tpl)
		loaded++
	}
	return loader, loaded, skipped, nil
}

// LoadTemplateByID 从库里取单条模板并解析，供按 ID 扫描使用。
func (s *NucleiService) LoadTemplateByID(id string) (*nuclei.NucleiTemplate, error) {
	p, err := s.GetTemplate(id)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(p.Content) == "" {
		return nil, errors.New("模板内容为空")
	}
	return nuclei.NewTemplateLoader().Parse([]byte(p.Content), "db:"+p.TemplateID)
}
